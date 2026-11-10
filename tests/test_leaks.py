import json
import logging
import re
import secrets

from conftest import fund

from test_wiring import FakeCtx, ctx, env, key_hex, operator_key_of, rescue_actions  # noqa: F401  (fixtures)

# Hermes wraps every registered pattern like this before matching.
HERMES_WRAP = r"(?<![A-Za-z0-9_-])(%s)(?![A-Za-z0-9_-])"


def redacted_by(patterns: list[str], text: str) -> bool:
    return any(re.search(HERMES_WRAP % p, text) for p in patterns)

import sys


def forms(secret_hex: str) -> list[str]:
    raw = secret_hex[2:] if secret_hex.startswith("0x") else secret_hex
    return [raw.lower()]


def test_no_key_anywhere(ctx, env, w3, accounts, positions, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    outputs: list[str] = []

    def call(tool, **args):
        raw = ctx.tools[tool]["handler"](args)
        outputs.append(raw)
        return json.loads(raw)

    def hook(tool, **args):
        outputs.append(json.dumps(ctx.hook(tool, **args)))

    chain_id = w3.eth.chain_id
    victim_key = key_hex(accounts.victim)

    # Success path, end to end.
    plan = call("lifeboat_plan", chain_id=chain_id, actions=rescue_actions(positions))
    operator_key = operator_key_of(tmp_path, accounts.victim, plan["operator"])
    call("lifeboat_simulate", plan_id=plan["plan_id"])
    fund(w3, plan["operator"], 10**17)
    hook("lifeboat_execute", plan_id=plan["plan_id"])
    assert call("lifeboat_execute", plan_id=plan["plan_id"])["ok"]
    call("lifeboat_status", chain_id=chain_id)
    hook("lifeboat_sweep_back", chain_id=chain_id)
    call("lifeboat_sweep_back", chain_id=chain_id)
    outputs.append(ctx.commands["lifeboat"]["handler"](""))

    # Failure paths: unknown plan, reverted simulation, unreachable RPC, invalid key, hostile arguments.
    call("lifeboat_simulate", plan_id="p-0000000000")
    call("lifeboat_execute", plan_id="p-0000000000")
    hook("lifeboat_execute", plan_id="p-0000000000")
    locked = call("lifeboat_plan", chain_id=chain_id, actions=[
        {"type": "call", "target": positions.vesting.address, "label": "claim",
         "signature": "claim()", "args": []},
        {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"},
    ])
    call("lifeboat_simulate", plan_id=locked["plan_id"])
    call("lifeboat_execute", plan_id=locked["plan_id"])
    # A model that somehow learned a key and echoes it back must not get it repeated.
    call("lifeboat_plan", chain_id=chain_id, actions=[{"type": victim_key}])
    call("lifeboat_plan", chain_id=chain_id, actions=[{"type": "call", "target": operator_key, "signature": "x()"}])
    sweep = {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"}
    for signature, args in ((victim_key, [operator_key]), ("claim(address)", [operator_key]),
                            ("claim(bytes32)", [victim_key]), ("claim(bytes32[])", [[operator_key]])):
        echoed = call("lifeboat_plan", chain_id=chain_id, actions=[
            {"type": "call", "target": positions.vesting.address, "signature": signature, "args": args}, sweep,
        ])
        assert echoed["ok"] is False  # a key that fits a bytes32 argument is still not stored in a plan
    call("lifeboat_simulate", plan_id=operator_key)

    ctx.config["rpc"] = {str(chain_id): "http://127.0.0.1:9"}
    dead = call("lifeboat_simulate", plan_id=plan["plan_id"])
    assert dead["ok"] is False
    call("lifeboat_status", chain_id=chain_id)
    call("lifeboat_sweep_back", chain_id=chain_id)
    ctx.config.clear()

    bad_key = "0x" + "ab" * 31 + "zz"
    env.setenv("LIFEBOAT_VICTIM_KEY", bad_key)
    assert call("lifeboat_plan", chain_id=chain_id, actions=rescue_actions(positions))["ok"] is False
    call("lifeboat_execute", plan_id=plan["plan_id"])
    call("lifeboat_status")
    outputs.append(ctx.commands["lifeboat"]["handler"](""))

    files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert {p.parent.name for p in files} >= {"plans", "receipts", "operators"}
    haystack = "\n".join(outputs) + "\n" + caplog.text + "\n" + "\n".join(str(r.args) for r in caplog.records)
    haystack += "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in files)
    haystack = haystack.lower()
    assert len(caplog.records) > 0, "the control: logs were captured, so a leak in them would be seen"
    for secret in (victim_key, operator_key, bad_key):
        for form in forms(secret):
            assert form not in haystack, "a key leaked"
    assert accounts.victim.address.lower() in haystack  # the control: addresses do appear, only keys do not


def test_redaction_patterns_match_every_form_of_a_key_the_way_hermes_applies_them(
    ctx, w3, accounts, positions, tmp_path
):
    """Review 2, findings 14 and 21: the 0x form must match under the Hermes wrapper, and the literal
    start of a pattern, which Hermes prints in its redaction marker, must not be the key."""
    victim_key = key_hex(accounts.victim)[2:]
    assert redacted_by(ctx.patterns, victim_key), "the victim key is registered at load"
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=rescue_actions(positions))
    operator_key = operator_key_of(tmp_path, accounts.victim, plan["operator"])[2:]
    for key in (victim_key, operator_key):
        for form in (key, key.upper(), "0x" + key, "0x" + key.upper(), "0X" + key.upper(),
                     f'{{"key": "0x{key}"}}', f"KEY=0x{key}\n"):
            assert redacted_by(ctx.patterns, form), form[:12]
    for pattern in ctx.patterns:
        assert pattern[2] == "(" and len(pattern) > 60
    for _ in range(50):
        tx_hash = secrets.token_hex(32)
        assert not redacted_by(ctx.patterns, tx_hash) and not redacted_by(ctx.patterns, "0x" + tx_hash)
    assert len(ctx.patterns) == len(set(ctx.patterns))


def test_operator_keys_from_earlier_sessions_are_registered_at_load(ctx, env, w3, accounts, positions, tmp_path):
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=rescue_actions(positions))
    operator_key = operator_key_of(tmp_path, accounts.victim, plan["operator"])
    fresh = FakeCtx(tmp_path)
    sys.modules["lifeboat"].register(fresh)
    assert redacted_by(fresh.patterns, operator_key)
