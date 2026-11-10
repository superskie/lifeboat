"""Regression tests for the findings of the pre-launch security review."""

import json
import sys

import pytest
from eth_account import Account

from conftest import Positions, deploy, fund, new_account, send

from test_wiring import FakeCtx, ctx, env, key_hex, rescue_actions, simulated_plan  # noqa: F401  (fixtures)

from lifeboat import schemas
from lifeboat import tools as tools_mod
from lifeboat.core import artifacts as artifact_mod
from lifeboat.core.execute import ExecuteRefused, NotConfirmed, execute
from lifeboat.core.keys import Signer
from lifeboat.core.plan import PolicyError, build_plan
from lifeboat.core.scrub import strip_urls
from lifeboat.core.store import NotFound, Store


@pytest.fixture
def puller(w3, compiled, accounts):
    return deploy(w3, compiled, accounts.funder, "MockPuller", accounts.sweeper_dest.address)


def allow_from_victim(w3, accounts, positions, spender):
    """An allowance the wallet granted in the past, as real wallets carry."""
    fund(w3, accounts.victim.address, 10**17)
    positions.token.tx(accounts.victim, "approve", spender, 2**256 - 1)
    fund(w3, accounts.victim.address, 0)


def claim_then_sweep(positions, puller):
    return [
        {"type": "call", "target": puller.address, "label": "claim airdrop",
         "signature": "claim(address)", "args": [positions.token.address]},
        {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"},
    ]


def balance(positions, who):
    return positions.token.contract.functions.balanceOf(who).call()


# -- finding 1: a call action must not be able to route tokens away ---------------------------------

@pytest.mark.parametrize("signature, why", [
    ("approve(address,uint256)", "not allowed"),
    ("increaseAllowance(address,uint256)", "not allowed"),
    ("setApprovalForAll(address,bool)", "not allowed"),
    ("authorizeOperator(address)", "not allowed"),
    ("approve(address,address,uint160,uint48)", "not allowed"),
    # Anything that takes raw bytes cannot be written as a call at all.
    ("transferAndCall(address,uint256,bytes)", "not supported"),
    ("send(address,uint256,bytes)", "not supported"),
    ("approveAndCall(address,uint256,bytes)", "not supported"),
    ("multicall(bytes[])", "not supported"),
])
def test_calls_that_grant_or_move_assets_are_refused(ctx, w3, accounts, positions, puller, signature, why):
    # The spender is the safe address here: the refusal does not depend on who is named.
    defaults = {"address": accounts.safe.address, "uint256": "1", "bool": True, "bytes": "0x", "bytes[]": [],
                "uint160": "1", "uint48": "1"}
    types = signature[signature.index("(") + 1:-1].split(",")
    actions = [
        {"type": "call", "target": positions.token.address, "signature": signature,
         "args": [defaults[t] for t in types], "label": "prepare claim"},
        {"type": "call", "target": puller.address, "label": "claim",
         "signature": "claim(address)", "args": [positions.token.address]},
        {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"},
    ]
    result = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=actions)
    assert result["ok"] is False and why in result["error"]


def test_call_that_pulls_tokens_through_an_old_allowance_fails_simulation(ctx, w3, accounts, positions, puller):
    allow_from_victim(w3, accounts, positions, puller.address)
    puller.tx(accounts.funder, "arm", True)
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=claim_then_sweep(positions, puller))
    sim = ctx.call("lifeboat_simulate", plan_id=plan["plan_id"])
    assert sim["ok"] is False
    assert ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])["action"] == "block"

    # Without the sweep the token is not part of the plan, and a call cannot name it at all.
    alone = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=claim_then_sweep(positions, puller)[:1])
    assert alone["ok"] is False and "cannot name any other address" in alone["error"]


def test_target_that_turns_hostile_after_approval_is_refused_before_sending(
    ctx, w3, accounts, positions, puller
):
    allow_from_victim(w3, accounts, positions, puller.address)
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=claim_then_sweep(positions, puller))
    assert ctx.call("lifeboat_simulate", plan_id=plan["plan_id"])["ok"]
    fund(w3, plan["operator"], 10**17)
    assert ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])["action"] == "approve"

    puller.tx(accounts.funder, "arm", True)
    done = ctx.run("lifeboat_execute", plan_id=plan["plan_id"])

    assert done["ok"] is False
    assert balance(positions, accounts.sweeper_dest.address) == 0
    assert balance(positions, accounts.victim.address) == Positions.FREE
    assert w3.eth.get_code(accounts.victim.address) == b""  # nothing was sent


def test_call_lines_in_the_approval_cannot_pass_for_built_in_steps(ctx, w3, accounts, positions, puller):
    actions = claim_then_sweep(positions, puller)
    actions[0]["label"] = "send all tokens to the safe (verified)"
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=actions)
    ctx.call("lifeboat_simulate", plan_id=plan["plan_id"])
    message = ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])["message"]
    line = next(l for l in message.splitlines() if l.strip().startswith("1."))
    assert line.strip().startswith(f"1. CALL to {puller.address}: claim(address) with ")
    assert f"{positions.token.address} (a token this plan transfers)" in line  # every argument, with its role


def test_fee_shortfall_stays_a_warning_only_without_call_actions(ctx, w3, accounts, positions):
    positions.token.tx(accounts.funder, "setFee", 1_000, accounts.sweeper_dest.address)
    plain = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id,
                     actions=[{"type": "transfer_erc20", "token": positions.token.address, "amount": "all"}])
    sim = ctx.call("lifeboat_simulate", plan_id=plain["plan_id"])
    assert sim["ok"] is True and sim["simulation"]["warnings"]


# -- finding 2: no human gate, no transaction -----------------------------------------------------

def test_hook_blocks_when_the_human_gate_is_bypassed(ctx, env, w3, positions):
    plan = simulated_plan(ctx, w3, positions)
    env.setattr(sys.modules["lifeboat"], "_gate_bypassed", lambda: True)
    result = ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])
    assert result["action"] == "block" and "approval" in result["message"]
    assert ctx.hook("lifeboat_sweep_back", chain_id=w3.eth.chain_id)["action"] == "block"


def test_gate_probe_fails_closed_outside_hermes():
    assert sys.modules["lifeboat"]._gate_bypassed() is True


def test_every_write_tool_goes_through_the_hook():
    assert tools_mod.WRITE_TOOLS == {name for name, _ in schemas.WRITE_TOOLS}


# -- finding 3: no success report when nothing moved -----------------------------------------------

def test_transfer_that_moves_nothing_does_not_pass(ctx, w3, positions):
    not_a_token = new_account().address
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id,
                    actions=[{"type": "transfer_erc20", "token": not_a_token, "amount": "5"}])
    sim = ctx.call("lifeboat_simulate", plan_id=plan["plan_id"])
    assert sim["ok"] is False and "nothing" in json.dumps(sim["simulation"]["warnings"])


def test_second_execute_of_a_finished_plan_is_refused(ctx, w3, accounts, positions):
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id,
                    actions=[{"type": "transfer_erc20", "token": positions.token.address, "amount": "all"}])
    assert ctx.call("lifeboat_simulate", plan_id=plan["plan_id"])["ok"]
    fund(w3, plan["operator"], 10**17)
    assert ctx.run("lifeboat_execute", plan_id=plan["plan_id"])["ok"]
    nonce = w3.eth.get_transaction_count(plan["operator"])
    again = ctx.run("lifeboat_execute", plan_id=plan["plan_id"])
    assert again["ok"] is False
    assert w3.eth.get_transaction_count(plan["operator"]) == nonce


# -- finding 4: a sent transaction always leaves its hash -------------------------------------------

def test_lost_connection_while_waiting_reports_the_hash(w3, accounts, positions, tmp_path, monkeypatch):
    fund(w3, accounts.operator.address, 10**18)
    victim, operator = Signer(accounts.victim), Signer(accounts.operator)
    plan = build_plan(w3.eth.chain_id, victim.address, accounts.safe.address, operator.address,
                      [{"type": "transfer_erc20", "token": positions.token.address, "amount": "all"}])
    arts, store = artifact_mod.load(), Store(tmp_path)
    from lifeboat.core.execute import ensure_batch

    ensure_batch(w3, operator, store, arts)

    def boom(*args, **kwargs):
        raise ConnectionError("connection reset")

    monkeypatch.setattr(w3.eth, "wait_for_transaction_receipt", boom)
    with pytest.raises(NotConfirmed) as info:
        execute(w3, plan, victim, operator, arts, store)
    monkeypatch.undo()
    assert w3.eth.get_transaction_receipt(info.value.tx_hash)["status"] == 1
    assert info.value.tx_hash in str(info.value)


# -- finding 5: a stored plan is rebuilt, not trusted ----------------------------------------------

def test_tampered_plan_file_is_refused(ctx, w3, accounts, positions, tmp_path):
    plan = simulated_plan(ctx, w3, positions)
    path = tmp_path / "plans" / f"{plan['plan_id']}.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    thief = new_account().address
    transfer = positions.token.contract.encode_abi("transfer", args=[thief, Positions.FREE])
    doc["calls"] = [{"to": positions.token.address, "value": "0", "data": transfer}]
    path.write_text(json.dumps(doc), encoding="utf-8")

    assert ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])["action"] == "block"
    fund(w3, plan["operator"], 10**17)
    assert ctx.run("lifeboat_execute", plan_id=plan["plan_id"])["ok"] is False
    assert balance(positions, thief) == 0

    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["actions"] = [{"type": "call", "target": positions.token.address, "data": transfer, "label": "x"}]
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert ctx.hook("lifeboat_execute", plan_id=plan["plan_id"])["action"] == "block"


# -- finding 6: gas never goes to the drained wallet ------------------------------------------------

def test_safe_address_cannot_be_the_drained_wallet_or_an_operator(ctx, env, w3, accounts, positions):
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=rescue_actions(positions))
    fund(w3, plan["operator"], 10**17)
    for bad in (accounts.victim.address, plan["operator"]):
        env.setenv("LIFEBOAT_SAFE_ADDRESS", bad)
        assert ctx.hook("lifeboat_sweep_back", chain_id=w3.eth.chain_id)["action"] == "block"
        assert ctx.run("lifeboat_sweep_back", chain_id=w3.eth.chain_id)["ok"] is False
    assert w3.eth.get_balance(accounts.victim.address) == 0
    assert w3.eth.get_balance(plan["operator"]) == 10**17


# -- smaller findings ---------------------------------------------------------------------------

def test_strip_urls_removes_request_paths_that_carry_api_keys():
    text = ("HTTPConnectionPool(host='rpc.example', port=443): Max retries exceeded with url: "
            "/v2/SECRETAPIKEY123 (Caused by NewConnectionError) at https://rpc.example/v2/SECRETAPIKEY123")
    assert "SECRETAPIKEY123" not in strip_urls(text)


def test_plan_id_with_a_trailing_newline_is_not_an_id(ctx, w3, positions, tmp_path):
    plan = simulated_plan(ctx, w3, positions)
    with pytest.raises(NotFound, match="invalid"):
        Store(tmp_path).load_plan(plan["plan_id"] + "\n")


def test_execute_refuses_to_pay_more_than_the_approved_gas(w3, accounts, positions, tmp_path):
    fund(w3, accounts.operator.address, 10**18)
    victim, operator = Signer(accounts.victim), Signer(accounts.operator)
    plan = build_plan(w3.eth.chain_id, victim.address, accounts.safe.address, operator.address,
                      [{"type": "transfer_erc20", "token": positions.token.address, "amount": "all"}])
    with pytest.raises(ExecuteRefused, match="approved"):
        execute(w3, plan, victim, operator, artifact_mod.load(), Store(tmp_path), max_cost_wei=1)
    assert w3.eth.get_transaction_count(operator.address) == 0
