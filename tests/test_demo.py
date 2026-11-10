"""The demo scripts, run against the local chain: the victim they set up, the sweeper they run, and
the rescue lifeboat then makes of it. The sweep history lifeboat reads is built from the real
transactions the sweeper sent, so this also checks that the demo produces the record the gate asks for."""

import sys
from datetime import datetime, timezone

from conftest import ROOT, fund

from test_wiring import EXPLORER, FakeCtx, only_chains  # noqa: F401

sys.path.insert(0, str(ROOT / "demo"))

import common  # noqa: E402
import setup_victim  # noqa: E402
import sweeper  # noqa: E402

from lifeboat.core import evidence as evidence_mod  # noqa: E402
from lifeboat.core.chains import Chain  # noqa: E402
from lifeboat.core.evidence import find_sweeps  # noqa: E402


def explorer_history(w3, address: str) -> list[dict]:
    """Every transaction to or from `address`, in the shape the explorer API reports them, newest first."""
    items = []
    for number in range(w3.eth.block_number + 1):
        block = w3.eth.get_block(number, full_transactions=True)
        stamp = datetime.fromtimestamp(block["timestamp"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        for tx in block["transactions"]:
            if address in (tx["from"], tx.get("to")):
                ok = w3.eth.get_transaction_receipt(tx["hash"])["status"] == 1
                items.append({"hash": "0x" + tx["hash"].hex(), "timestamp": stamp, "from": {"hash": tx["from"]},
                              "to": {"hash": tx["to"]} if tx.get("to") else None, "value": str(tx["value"]),
                              "result": "success" if ok else "error"})
    return items[::-1]


def test_demo_keys_are_created_once_and_kept(tmp_path):
    path = tmp_path / "demo" / ".env"
    first = common.load_env(path)
    assert set(first) == {"DEPLOYER_KEY", "VICTIM_KEY", "SAFE_KEY", "SWEEPER_KEY"}
    assert len(set(first.values())) == 4
    assert common.load_env(path) == first
    assert len({a.address for a in common.accounts(first).values()}) == 4


def test_demo_victim_is_swept_and_then_rescued(w3, compiled, anvil_url, tmp_path, monkeypatch):
    who = common.accounts(common.load_env(tmp_path / ".env"))
    victim, safe = who["victim"].address, who["safe"].address
    fund(w3, who["deployer"].address, 10**18)

    state = setup_victim.setup(w3, who, compiled, unlock_in=0)
    token = w3.eth.contract(address=state["token"], abi=[{
        "name": "balanceOf", "type": "function", "stateMutability": "view",
        "inputs": [{"name": "a", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}]}])
    assert token.functions.balanceOf(victim).call() == setup_victim.FREE
    assert token.functions.balanceOf(state["staking"]).call() == setup_victim.STAKED

    lines: list[str] = []
    taken = sweeper.run(w3, who, bait=2, seconds=0, interval=0.05, log=lines.append)
    assert taken > 2 * sweeper.BAIT // 2 and w3.eth.get_balance(who["sweeper"].address) == taken
    assert w3.eth.get_balance(victim) < sweeper.BAIT // 2  # nothing left to pay for a transfer with
    assert sum("swept" in line for line in lines) == 2

    history = explorer_history(w3, victim)
    assert len(find_sweeps(history, victim)) >= 2, "the demo leaves the record lifeboat asks for"

    # The rescue, through the tools, the way the demo README walks through it.
    only_chains(monkeypatch, Chain(w3.eth.chain_id, "Anvil", anvil_url, "", EXPLORER))
    monkeypatch.setattr(evidence_mod, "fetch_transactions", lambda chain, address: explorer_history(w3, address))
    monkeypatch.setattr(evidence_mod, "fetch_internal", lambda chain, address: [])
    monkeypatch.setenv("LIFEBOAT_VICTIM_KEY", "0x" + bytes(who["victim"].key).hex())
    monkeypatch.setenv("LIFEBOAT_SAFE_ADDRESS", safe)
    monkeypatch.setenv("LIFEBOAT_ENABLE_EXECUTE", "1")
    monkeypatch.setattr(sys.modules["lifeboat"], "_gate_bypassed", lambda: False)
    ctx = FakeCtx(tmp_path / "data")
    sys.modules["lifeboat"].register(ctx)

    actions = [
        {"type": "call", "target": state["staking"], "signature": "withdraw()", "args": [], "label": "unstake"},
        {"type": "call", "target": state["vesting"], "signature": "claim()", "args": [], "label": "claim vesting"},
        {"type": "transfer_erc20", "token": state["token"], "amount": "all"},
        {"type": "transfer_nft", "standard": "erc721", "token": state["nft"], "token_id": str(state["nft_id"])},
    ]
    plan = ctx.call("lifeboat_plan", chain_id=w3.eth.chain_id, actions=actions)
    sim = ctx.call("lifeboat_simulate", plan_id=plan["plan_id"])
    assert sim["ok"] and sim["simulation"]["evidence"], sim
    fund(w3, plan["operator"], 10**17)
    done = ctx.run("lifeboat_execute", plan_id=plan["plan_id"])
    assert done["ok"], done

    everything = setup_victim.FREE + setup_victim.STAKED + setup_victim.VESTED
    assert token.functions.balanceOf(safe).call() == everything
    assert token.functions.balanceOf(victim).call() == 0
    assert w3.eth.get_balance(who["sweeper"].address) == taken  # the sweeper got nothing more
