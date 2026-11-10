import pytest
from eth_abi import encode
from eth_utils import function_signature_to_4byte_selector as selector

from conftest import Positions

from lifeboat.core import artifacts as artifact_mod
from lifeboat.core.plan import build_plan, summarize
from lifeboat.core.simulate import SimulationUnavailable, simulate


@pytest.fixture
def arts():
    return artifact_mod.load()


def make_plan(w3, accounts, actions):
    return build_plan(
        w3.eth.chain_id, accounts.victim.address, accounts.safe.address, accounts.operator.address, actions
    )


def call_action(target, signature: str, label: str = "test"):
    return {"type": "call", "target": target, "signature": signature, "args": [], "label": label}


def withdraw_and_sweep(positions):
    return [
        call_action(positions.staking.address, "withdraw()"),
        {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"},
        {"type": "transfer_nft", "standard": "erc721", "token": positions.nft.address, "token_id": positions.nft_id},
    ]


def pass_time(w3, seconds):
    w3.provider.make_request("evm_increaseTime", [seconds])
    w3.provider.make_request("evm_mine", [])


def test_staked_withdraw_then_sweep_simulates_ok(w3, accounts, positions, arts):
    plan = make_plan(w3, accounts, withdraw_and_sweep(positions))
    result = simulate(w3, plan, arts)
    assert result.ok and result.deltas_ok and result.revert_reason is None
    assert [c.ok for c in result.calls] == [True, True, True]
    token = next(b for b in result.balances if b.kind == "erc20")
    assert (token.victim_before, token.victim_after) == (Positions.FREE, 0)
    assert (token.safe_before, token.safe_after) == (0, Positions.FREE + Positions.STAKED)
    nft = next(b for b in result.balances if b.kind == "erc721")
    assert (nft.victim_before, nft.victim_after, nft.safe_after) == (1, 0, 1)
    assert result.native_after == 0
    # The pool reports the stake through balanceOf, so its drop is shown to the person approving.
    (warning,) = result.warnings
    assert positions.staking.address in warning and str(Positions.STAKED) in warning
    plan.simulation = result.to_dict()
    assert "simulation: passed" in summarize(plan)


def test_vesting_before_unlock_reports_revert_reason(w3, accounts, positions, arts):
    actions = [
        call_action(positions.vesting.address, "claim()"),
        {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"},
    ]
    plan = make_plan(w3, accounts, actions)
    result = simulate(w3, plan, arts)
    assert not result.ok
    assert result.revert_reason == "locked"
    assert [(c.ok, c.reason) for c in result.calls][0] == (False, "locked")
    assert "FAILED: locked" in summarize(plan.__class__.from_dict({**plan.to_dict(), "simulation": result.to_dict()}))

    pass_time(w3, 3700)
    after = simulate(w3, plan, arts)
    assert after.ok and after.revert_reason is None
    token = after.balances[0]
    assert token.safe_after - token.safe_before == Positions.FREE + Positions.VESTED


def test_safe_mint_to_victim_needs_receiver_hook(w3, accounts, positions, arts):
    claim = call_action(positions.staking.address, "claimReward()")
    plan = make_plan(
        w3,
        accounts,
        [claim, {"type": "transfer_nft", "standard": "erc721", "token": positions.nft.address, "token_id": 2}],
    )
    result = simulate(w3, plan, arts)
    assert result.ok, result.revert_reason
    assert result.balances[0].safe_after == 1

    # Control: the same claim reverts when the victim's code has no receiver hook, so the pass
    # above really comes from RescueCore and not from the victim being a plain account.
    tx = {"from": accounts.victim.address, "to": positions.staking.address, "data": positions.staking.contract.encode_abi("claimReward", args=[])}
    w3.eth.call(tx, "latest", {accounts.victim.address: {"code": b""}})
    with pytest.raises(Exception):
        w3.eth.call(tx, "latest", {accounts.victim.address: {"code": bytes([0x00])}})


@pytest.mark.parametrize("fee_bps, ok, warned", [(10_000, False, True), (1_000, True, True), (0, True, False)])
def test_delta_check_flags_tokens_leaving_to_stranger(w3, accounts, positions, arts, fee_bps, ok, warned):
    positions.token.tx(accounts.funder, "setFee", fee_bps, accounts.sweeper_dest.address)
    plan = make_plan(w3, accounts, [{"type": "transfer_erc20", "token": positions.token.address, "amount": "all"}])
    result = simulate(w3, plan, arts)
    assert result.deltas_ok is ok
    assert result.ok is ok
    assert bool(result.warnings) is warned
    if fee_bps == 10_000:
        assert result.revert_reason is None  # the batch itself succeeds, the delta check is what stops it
        assert "gains nothing" in result.warnings[0]
    if fee_bps == 1_000:
        assert result.balances[0].safe_after == Positions.FREE * 9 // 10


def test_nft_that_is_not_owned_is_not_ok(w3, accounts, positions, arts):
    plan = make_plan(
        w3,
        accounts,
        [{"type": "transfer_nft", "standard": "erc721", "token": positions.nft.address, "token_id": 99}],
    )
    result = simulate(w3, plan, arts)
    assert not result.ok


def test_erc1155_moves_to_safe(w3, accounts, positions, arts):
    plan = make_plan(
        w3,
        accounts,
        [{"type": "transfer_nft", "standard": "erc1155", "token": positions.multi.address,
          "token_id": Positions.MULTI_ID, "amount": Positions.MULTI_AMOUNT}],
    )
    result = simulate(w3, plan, arts)
    assert result.ok
    b = result.balances[0]
    assert (b.victim_before, b.victim_after, b.safe_after) == (Positions.MULTI_AMOUNT, 0, Positions.MULTI_AMOUNT)


def test_sim_does_not_change_chain_state(w3, accounts, positions, arts):
    plan = make_plan(w3, accounts, withdraw_and_sweep(positions))
    victim, safe = accounts.victim.address, accounts.safe.address
    token = positions.token.contract.functions

    def snapshot():
        return (
            w3.eth.block_number,
            bytes(w3.eth.get_code(victim)),
            w3.eth.get_balance(victim),
            w3.eth.get_transaction_count(victim),
            token.balanceOf(victim).call(),
            token.balanceOf(safe).call(),
            positions.nft.contract.functions.ownerOf(positions.nft_id).call(),
            positions.staking.contract.functions.staked(victim).call(),
        )

    before = snapshot()
    assert simulate(w3, plan, arts).ok
    assert snapshot() == before


def test_rpc_without_state_overrides_raises_unavailable(w3, accounts, positions, arts, monkeypatch):
    plan = make_plan(w3, accounts, withdraw_and_sweep(positions))

    def refuse(*args, **kwargs):
        raise ValueError({"code": -32602, "message": "state override not supported"})

    monkeypatch.setattr("lifeboat.core.simulate._call", refuse)
    with pytest.raises(SimulationUnavailable, match="state override not supported"):
        simulate(w3, plan, arts)
