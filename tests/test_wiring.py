import json
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from conftest import Positions, fund, new_account

from lifeboat.core import evidence as evidence_mod
from lifeboat.core.chains import CHAINS, Chain

WRITE = {"lifeboat_execute", "lifeboat_sweep_back"}
READ = {"lifeboat_scan", "lifeboat_plan", "lifeboat_simulate", "lifeboat_status"}


class FakeCtx:
    def __init__(self, data_dir, config=None):
        self.state = SimpleNamespace(data_dir=data_dir)
        self.config = config or {}
        self.tools: dict[str, dict] = {}
        self.hooks: dict[str, list] = {}
        self.commands: dict[str, dict] = {}
        self.patterns: list[str] = []

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def register_tool(self, name, toolset, schema, handler, check_fn=None, **extra):
        self.tools[name] = {"toolset": toolset, "schema": schema, "handler": handler, "check_fn": check_fn}

    def register_hook(self, name, callback):
        self.hooks.setdefault(name, []).append(callback)

    def register_command(self, name, handler, description="", args_hint="", **extra):
        self.commands[name] = {"handler": handler, "description": description}

    def register_redaction_patterns(self, patterns):
        self.patterns.extend(patterns)
        return len(patterns)

    def call(self, tool, **args):
        return json.loads(self.tools[tool]["handler"](args, task_id="t"))

    def run(self, tool, **args):
        """A write tool the way Hermes runs it: the approval hook first, the handler if it is approved."""
        verdict = self.hook(tool, **args)
        if verdict["action"] != "approve":
            return {"ok": False, "error": verdict["message"], "blocked": True}
        return self.call(tool, **args)

    def hook(self, tool, **args):
        (callback,) = self.hooks["pre_tool_call"]
        return callback(tool_name=tool, args=args, task_id="t", session_id="s")


def key_hex(account) -> str:
    return "0x" + bytes(account.key).hex()


def operator_key_of(data_dir, victim, address: str) -> str:
    """The operator key as 0x hex. It is sealed on disk, so tests open it the way lifeboat does."""
    from lifeboat.core.keys import OperatorStore, seal_secret

    seen: list[str] = []
    seal = seal_secret(lambda name: key_hex(victim), lambda secret: None)
    OperatorStore(data_dir, seen.append, lambda: seal).load(address)
    return seen[-1]


EXPLORER = "http://explorer.invalid"


def history_item(n: int, when: int, sender: str, receiver: str, value: int, result: str = "success") -> dict:
    """One transaction the way the explorer API reports it."""
    stamp = datetime.fromtimestamp(when, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return {"hash": "0x" + f"{n:064x}", "timestamp": stamp, "from": {"hash": sender},
            "to": {"hash": receiver}, "value": str(value), "result": result}


def swept_history(victim: str, sweeps: int = 2, gap: int = 7) -> list[dict]:
    """Gas arrives and is gone `gap` seconds later, `sweeps` times. Newest first, as the API answers."""
    funder, sweeper = "0x" + "aa" * 20, "0x" + "bb" * 20
    items = []
    for n in range(sweeps):
        when = 1_760_000_000 + n * 3600
        items.append(history_item(2 * n, when, funder, victim, 10**16))
        items.append(history_item(2 * n + 1, when + gap, victim, sweeper, 9 * 10**15))
    return items[::-1]


def only_chains(monkeypatch, *chains: Chain) -> None:
    """Leave exactly these chains in the table, so nothing in a test can reach a real network."""
    for chain_id in list(CHAINS):
        monkeypatch.delitem(CHAINS, chain_id)
    for chain in chains:
        monkeypatch.setitem(CHAINS, chain.id, chain)


@pytest.fixture
def env(monkeypatch, w3, anvil_url, accounts):
    only_chains(monkeypatch, Chain(w3.eth.chain_id, "Anvil", anvil_url, "", EXPLORER))
    # The wallet under test has a sweep on record, as a wallet lifeboat is meant for does.
    monkeypatch.setattr(evidence_mod, "fetch_transactions", lambda chain, address: swept_history(address))
    monkeypatch.setattr(evidence_mod, "fetch_internal", lambda chain, address: [])
    monkeypatch.setenv("LIFEBOAT_VICTIM_KEY", key_hex(accounts.victim))
    monkeypatch.setenv("LIFEBOAT_SAFE_ADDRESS", accounts.safe.address)
    monkeypatch.setenv("LIFEBOAT_ENABLE_EXECUTE", "1")
    # Stands in for Hermes with its approval prompt on; outside Hermes the real probe fails closed.
    monkeypatch.setattr(sys.modules["lifeboat"], "_gate_bypassed", lambda: False)
    return monkeypatch


@pytest.fixture
def ctx(env, tmp_path):
    fake = FakeCtx(tmp_path)
    sys.modules["lifeboat"].register(fake)
    return fake


def rescue_actions(positions):
    return [
        {"type": "call", "target": positions.staking.address, "label": "withdraw",
         "signature": "withdraw()", "args": []},
        {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"},
        {"type": "transfer_nft", "standard": "erc721", "token": positions.nft.address,
         "token_id": str(positions.nft_id)},
    ]


def simulated_plan(ctx, w3, positions) -> dict:
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=rescue_actions(positions))
    assert plan["ok"], plan
    sim = ctx.call("lifeboat_simulate", plan_id=plan["plan_id"])
    assert sim["ok"], sim
    return plan


def test_registers_tools_hook_and_command(ctx):
    assert set(ctx.tools) == READ | WRITE
    assert all(t["toolset"] == "lifeboat" for t in ctx.tools.values())
    assert all(t["schema"]["name"] == name for name, t in ctx.tools.items())
    assert list(ctx.hooks) == ["pre_tool_call"]
    assert "lifeboat" in ctx.commands


def test_manifest_lists_exactly_the_registered_tools(ctx):
    from conftest import ROOT

    listed: dict[str, list[str]] = {}
    section = None
    for line in (ROOT / "plugin.yaml").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith(" "):
            section = line.split(":")[0]
        elif section in ("provides_tools", "provides_hooks") and line.strip().startswith("- "):
            listed.setdefault(section, []).append(line.strip()[2:])
    assert set(listed["provides_tools"]) == set(ctx.tools)
    assert listed["provides_hooks"] == list(ctx.hooks)


def test_write_tools_hidden_without_execute_flag(ctx, env):
    env.delenv("LIFEBOAT_ENABLE_EXECUTE")
    assert all(ctx.tools[name]["check_fn"]() is False for name in WRITE)
    assert all(ctx.tools[name]["check_fn"] is None for name in READ)
    env.setenv("LIFEBOAT_ENABLE_EXECUTE", "true")  # only the exact value 1 turns it on
    assert all(ctx.tools[name]["check_fn"]() is False for name in WRITE)


def test_write_tools_visible_with_flag(ctx):
    assert all(ctx.tools[name]["check_fn"]() is True for name in WRITE)


def test_write_handlers_refuse_without_flag_even_when_called(ctx, env, w3, positions):
    plan = simulated_plan(ctx, w3, positions)
    env.delenv("LIFEBOAT_ENABLE_EXECUTE")
    for tool, args in (("lifeboat_execute", {"plan_id": plan["plan_id"]}),
                       ("lifeboat_sweep_back", {"chain_id": w3.eth.chain_id})):
        for result in (ctx.call(tool, **args), ctx.run(tool, **args)):
            assert result["ok"] is False and "LIFEBOAT_ENABLE_EXECUTE" in result["error"]
    assert ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])["action"] == "block"


def test_write_handlers_refuse_a_call_the_hook_did_not_approve(ctx, w3, accounts, positions):
    """Review 2, findings 5, 6 and 8: the handler sends only what an approval prompt just described."""
    plan = simulated_plan(ctx, w3, positions)
    fund(w3, plan["operator"], 10**17)
    for tool, args in (("lifeboat_execute", {"plan_id": plan["plan_id"]}),
                       ("lifeboat_sweep_back", {"chain_id": w3.eth.chain_id})):
        result = ctx.call(tool, **args)
        assert result["ok"] is False and "not approved" in result["error"]
    assert w3.eth.get_transaction_count(plan["operator"]) == 0

    # One approval covers one send.
    assert ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])["action"] == "approve"
    assert ctx.call("lifeboat_execute", plan_id=plan["plan_id"])["ok"] is True
    nonce = w3.eth.get_transaction_count(plan["operator"])
    again = ctx.call("lifeboat_execute", plan_id=plan["plan_id"])
    assert again["ok"] is False and "not approved" in again["error"]
    assert w3.eth.get_transaction_count(plan["operator"]) == nonce


def test_hook_returns_approve_with_summary_for_every_write_tool(ctx, w3, accounts, positions):
    plan = simulated_plan(ctx, w3, positions)
    safe = accounts.safe.address

    first = ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])
    assert first["action"] == "approve"
    message = first["message"]
    assert safe in message and plan["operator"] in message and accounts.victim.address in message
    assert positions.staking.address in message and positions.token.address in message
    assert positions.nft.address in message
    assert "simulation: passed" in message and "gas:" in message and "Anvil" in message
    assert "why this wallet qualifies for a rescue: on Anvil, 2 incoming transfers" in message
    assert str(Positions.FREE + Positions.STAKED) in message
    assert "reverts as a whole" in message

    sweep = ctx.hook("lifeboat_sweep_back", chain_id=w3.eth.chain_id)
    assert sweep["action"] == "approve"
    assert safe in sweep["message"] and plan["operator"] in sweep["message"]

    second = ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])
    keys = {first["rule_key"], second["rule_key"], sweep["rule_key"]}
    assert len(keys) == 3  # an "always allow" answer can never match a later call


def test_hook_ignores_read_tools(ctx):
    for tool in (*READ, "terminal", "write_file"):
        assert ctx.hook(tool, plan_id="p-0000000000") is None


def test_hook_blocks_unknown_plan(ctx):
    result = ctx.hook("lifeboat_execute", plan_id="p-0000000000")
    assert result["action"] == "block" and result["message"].startswith("lifeboat:")
    assert ctx.hook("lifeboat_execute")["action"] == "block"
    assert ctx.hook("lifeboat_execute", plan_id="../../etc/passwd")["action"] == "block"


def test_hook_blocks_plan_without_passing_simulation(ctx, w3, positions):
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=rescue_actions(positions))
    result = ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])
    assert result["action"] == "block" and "lifeboat_simulate" in result["message"]


def _property_names(node, found):
    if isinstance(node, dict):
        for name, sub in (node.get("properties") or {}).items():
            found.append(name)
            _property_names(sub, found)
        _property_names(node.get("items"), found)
    return found


def test_no_tool_accepts_key_or_recipient_argument(ctx):
    banned_exact = {"to", "safe", "key", "from", "operator", "victim"}
    banned_part = ("key", "private", "secret", "recipient", "safe", "mnemonic", "seed")
    for name, tool in ctx.tools.items():
        for prop in _property_names(tool["schema"]["parameters"], []):
            assert prop not in banned_exact, f"{name}.{prop}"
            assert not any(part in prop.lower() for part in banned_part), f"{name}.{prop}"


def test_arguments_cannot_redirect_the_rescue(ctx, w3, accounts, positions):
    stranger = new_account().address
    result = ctx.call(
        "lifeboat_plan", chain_id=w3.eth.chain_id, safe=stranger, safe_address=stranger, to=stranger,
        operator=stranger, victim=stranger,
        actions=[{"type": "transfer_erc20", "token": positions.token.address, "amount": "all",
                  "to": stranger, "recipient": stranger}],
    )
    assert result["ok"]
    assert stranger not in json.dumps(result)
    assert accounts.safe.address in result["summary"]

    refused = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=[
        {"type": "call", "target": positions.token.address, "signature": "transfer(address,uint256)",
         "args": [stranger, "1"]},
        {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"},
    ])
    assert refused["ok"] is False and "not to the safe address" in refused["error"]


def test_plan_needs_configured_safe_and_supported_chain(ctx, env, w3, positions):
    assert ctx.call("lifeboat_plan", chain_id=424242, actions=rescue_actions(positions))["ok"] is False
    env.setenv("LIFEBOAT_SAFE_ADDRESS", "not-an-address")
    result = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=rescue_actions(positions))
    assert result["ok"] is False and "LIFEBOAT_SAFE_ADDRESS" in result["error"]


def test_changing_the_safe_address_invalidates_old_plans(ctx, env, w3, positions):
    plan = simulated_plan(ctx, w3, positions)
    env.setenv("LIFEBOAT_SAFE_ADDRESS", new_account().address)
    assert ctx.run("lifeboat_execute", plan_id=plan["plan_id"])["ok"] is False
    assert ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])["action"] == "block"


def test_plan_reuses_one_operator(ctx, w3, positions):
    first = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=rescue_actions(positions))
    second = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=rescue_actions(positions))
    assert first["operator"] == second["operator"] and first["plan_id"] != second["plan_id"]


def test_full_rescue_through_the_tools(ctx, w3, accounts, positions, sweeper):
    safe, victim = accounts.safe.address, accounts.victim.address
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=rescue_actions(positions))
    sim = ctx.call("lifeboat_simulate", plan_id=plan["plan_id"])
    assert sim["ok"] and sim["simulation"]["gas"]["enough"] is False
    assert plan["operator"] in sim["next"]

    fund(w3, plan["operator"], 10**17)
    sim = ctx.call("lifeboat_simulate", plan_id=plan["plan_id"])
    assert sim["simulation"]["gas"]["enough"] is True
    assert ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])["action"] == "approve"

    done = ctx.run("lifeboat_execute", plan_id=plan["plan_id"])
    assert done["ok"], done
    assert int(done["receipt"]["gas_paid_wei"]) <= int(sim["simulation"]["gas"]["max_cost_wei"])
    assert positions.token.contract.functions.balanceOf(safe).call() == Positions.FREE + Positions.STAKED
    assert positions.nft.contract.functions.ownerOf(positions.nft_id).call() == safe
    assert w3.eth.get_balance(victim) == 0 and sweeper.taken == 0

    status = ctx.call("lifeboat_status")
    assert status["setup"] == {"execute_enabled": True, "drained_wallet": victim, "safe_address": safe}
    assert status["receipts"][0]["ok"] is True
    assert int(status["operators"][0]["balance_wei"]["Anvil"]) > 0
    assert any("sweep_back" in hint for hint in status["hints"])

    safe_before = w3.eth.get_balance(safe)
    swept = ctx.run("lifeboat_sweep_back", chain_id=w3.eth.chain_id)
    assert swept["ok"] and swept["operators"][0]["tx_hash"]
    assert w3.eth.get_balance(safe) > safe_before
    assert w3.eth.get_balance(plan["operator"]) < 10**14


def test_failed_simulation_is_reported_and_blocks_execute(ctx, w3, positions):
    actions = [
        {"type": "call", "target": positions.vesting.address, "label": "claim",
         "signature": "claim()", "args": []},
        {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"},
    ]
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=actions)
    sim = ctx.call("lifeboat_simulate", plan_id=plan["plan_id"])
    assert sim["ok"] is False and "FAILED: locked" in sim["summary"]
    assert ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])["action"] == "block"
    assert "lifeboat_simulate" in ctx.run("lifeboat_execute", plan_id=plan["plan_id"])["error"]
    assert "failed: locked" in ctx.call("lifeboat_status")["plans"][0]["simulation"]

    restarted = FakeCtx(ctx.state.data_dir)  # a new process has no simulation in memory
    sys.modules["lifeboat"].register(restarted)
    assert restarted.call("lifeboat_status")["plans"][0]["simulation"] == "not simulated in this session"


def test_command_prints_steps_and_status(ctx, w3, accounts, positions):
    simulated_plan(ctx, w3, positions)
    text = ctx.commands["lifeboat"]["handler"]("")
    assert "1. scan" in text and "6. sweep" in text
    assert accounts.victim.address in text and accounts.safe.address in text
    assert "passed at block" in text
