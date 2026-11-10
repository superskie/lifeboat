from types import SimpleNamespace

import pytest

from conftest import Positions, deploy, fund, send

from lifeboat.core import artifacts as artifact_mod
from lifeboat.core.execute import (
    DELEGATION_PREFIX,
    ExecuteRefused,
    InsufficientOperatorFunds,
    SimulationFailed,
    ensure_batch,
    execute,
    sweep_back,
)
from lifeboat.core.keys import Signer
from lifeboat.core.plan import ZERO, PolicyError, build_plan
from lifeboat.core.store import Store

ORACLE = "0x420000000000000000000000000000000000000F"
# Runtime code that answers every call with the 32-byte value FAKE_L1_FEE, like an OP Stack GasPriceOracle.
FAKE_L1_FEE = 10**16
FAKE_ORACLE_CODE = "0x66" + FAKE_L1_FEE.to_bytes(7, "big").hex() + "6000526020" + "6000f3"


@pytest.fixture
def arts():
    return artifact_mod.load()


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path)


@pytest.fixture
def parties(w3, accounts):
    """The operator is funded; the victim has no ETH, as in a drained wallet."""
    fund(w3, accounts.operator.address, 10**18)
    return SimpleNamespace(
        victim=Signer(accounts.victim),
        operator=Signer(accounts.operator),
        safe=accounts.safe.address,
    )


def delegation(address: str) -> bytes:
    return DELEGATION_PREFIX + bytes.fromhex(address[2:])


def rescue_actions(positions):
    return [
        {"type": "call", "target": positions.staking.address, "label": "withdraw",
         "signature": "withdraw()", "args": []},
        {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"},
        {"type": "transfer_nft", "standard": "erc721", "token": positions.nft.address, "token_id": positions.nft_id},
    ]


def make_plan(w3, accounts, parties, actions):
    return build_plan(w3.eth.chain_id, parties.victim.address, parties.safe, parties.operator.address, actions)


def test_rescue_staked_position_and_tokens_sweeper_gets_nothing(w3, accounts, positions, sweeper, parties, arts, store):
    victim, safe = parties.victim.address, parties.safe
    taken_before = sweeper.taken
    plan = make_plan(w3, accounts, parties, rescue_actions(positions))

    receipt = execute(w3, plan, parties.victim, parties.operator, arts, store)

    assert receipt.ok, receipt.problems
    assert receipt.delegated and receipt.status == 1
    assert positions.token.contract.functions.balanceOf(safe).call() == Positions.FREE + Positions.STAKED
    assert positions.token.contract.functions.balanceOf(victim).call() == 0
    assert positions.nft.contract.functions.ownerOf(positions.nft_id).call() == safe
    assert positions.staking.contract.functions.staked(victim).call() == 0
    assert bytes(w3.eth.get_code(victim)) == delegation(receipt.batch)
    assert w3.eth.get_balance(victim) == 0
    assert sweeper.taken == taken_before
    assert w3.eth.get_balance(parties.operator.address) < 10**18
    token = next(b for b in receipt.balances if b.kind == "erc20")
    assert (token.safe_before, token.safe_after) == (0, Positions.FREE + Positions.STAKED)
    assert store.load_plan(plan.id).simulation["ok"] is True
    assert [r["tx_hash"] for r in store.receipts()] == [receipt.tx_hash]


def test_rescue_overrides_existing_sweeper_delegation(w3, compiled, accounts, positions, parties, arts, store):
    victim = parties.victim.address
    forwarder = deploy(w3, compiled, accounts.funder, "SweeperForwarder", accounts.sweeper_dest.address)
    auth = parties.victim.sign_authorization(w3.eth.chain_id, forwarder.address, w3.eth.get_transaction_count(victim))
    send(w3, accounts.funder, {"type": 4, "to": victim, "data": b"", "gas": 200_000, "authorizationList": [auth]})
    assert bytes(w3.eth.get_code(victim)) == delegation(forwarder.address)

    plan = make_plan(w3, accounts, parties, rescue_actions(positions))
    receipt = execute(w3, plan, parties.victim, parties.operator, arts, store)

    assert receipt.ok, receipt.problems
    assert bytes(w3.eth.get_code(victim)) == delegation(receipt.batch)
    assert receipt.batch != forwarder.address
    assert positions.token.contract.functions.balanceOf(parties.safe).call() == Positions.FREE + Positions.STAKED


def test_execute_refuses_without_passing_simulation(w3, accounts, positions, parties, arts, store):
    actions = [
        {"type": "call", "target": positions.vesting.address, "label": "claim",
         "signature": "claim()", "args": []},
        {"type": "transfer_erc20", "token": positions.token.address, "amount": "all"},
    ]
    plan = make_plan(w3, accounts, parties, actions)
    operator_nonce = w3.eth.get_transaction_count(parties.operator.address)

    with pytest.raises(SimulationFailed, match="locked") as info:
        execute(w3, plan, parties.victim, parties.operator, arts, store)

    assert info.value.result.ok is False
    assert w3.eth.get_transaction_count(parties.operator.address) == operator_nonce  # not even the deployment
    assert bytes(w3.eth.get_code(parties.victim.address)) == b""
    assert positions.token.contract.functions.balanceOf(parties.victim.address).call() == Positions.FREE
    assert store.load_plan(plan.id).simulation["ok"] is False
    assert store.receipts() == []


def test_auth_with_stale_nonce_lands_no_assets_and_reports_failure(
    w3, accounts, positions, parties, arts, store, monkeypatch
):
    victim = parties.victim.address
    original = Signer.sign_authorization

    def sign_then_move_the_nonce(self, chain_id, contract, nonce):
        auth = original(self, chain_id, contract, nonce)
        fund(w3, victim, 10**17)
        send(w3, accounts.victim, {"to": accounts.funder.address, "value": 1, "gas": 21_000})
        fund(w3, victim, 0)
        return auth

    monkeypatch.setattr(Signer, "sign_authorization", sign_then_move_the_nonce)
    plan = make_plan(w3, accounts, parties, rescue_actions(positions)[1:])

    receipt = execute(w3, plan, parties.victim, parties.operator, arts, store)

    assert receipt.status == 1  # the transaction itself is valid and lands, doing nothing
    assert not receipt.ok and not receipt.delegated
    assert any("not delegated" in p for p in receipt.problems)
    assert sum("nothing arrives at the safe address" in p for p in receipt.problems) == 2  # token and NFT
    assert bytes(w3.eth.get_code(victim)) == b""
    assert positions.token.contract.functions.balanceOf(victim).call() == Positions.FREE
    assert positions.nft.contract.functions.ownerOf(positions.nft_id).call() == victim
    assert receipt.gas_paid_wei > 0
    assert store.receipts()[0]["ok"] is False


def test_receipt_gas_paid_is_the_operators_balance_change(w3, accounts, positions, parties, arts, store):
    ensure_batch(w3, parties.operator, store, arts)
    before = w3.eth.get_balance(parties.operator.address)
    plan = make_plan(w3, accounts, parties, rescue_actions(positions))
    receipt = execute(w3, plan, parties.victim, parties.operator, arts, store)
    assert receipt.ok, receipt.problems
    assert before - w3.eth.get_balance(parties.operator.address) == receipt.gas_paid_wei > 0
    assert receipt.gas_used > 0


def test_native_all_is_swept_and_checked(w3, accounts, positions, parties, arts, store):
    fund(w3, parties.victim.address, 3 * 10**15)
    actions = rescue_actions(positions) + [{"type": "transfer_native", "amount": "all"}]
    plan = make_plan(w3, accounts, parties, actions)
    safe_before = w3.eth.get_balance(parties.safe)
    receipt = execute(w3, plan, parties.victim, parties.operator, arts, store)
    assert receipt.ok, receipt.problems
    assert w3.eth.get_balance(parties.victim.address) == 0
    assert w3.eth.get_balance(parties.safe) - safe_before == 3 * 10**15
    assert receipt.native["victim_after"] == 0


def test_ensure_batch_deploys_once_and_again_when_the_code_is_gone(w3, parties, arts, store):
    operator = parties.operator
    first = ensure_batch(w3, operator, store, arts)
    assert bytes(w3.eth.get_code(first)) == arts.batch_runtime(operator.address)
    nonce = w3.eth.get_transaction_count(operator.address)
    assert ensure_batch(w3, operator, store, arts) == first
    assert w3.eth.get_transaction_count(operator.address) == nonce

    w3.provider.make_request("anvil_setCode", [first, "0x"])
    second = ensure_batch(w3, operator, store, arts)
    assert second != first
    assert bytes(w3.eth.get_code(second)) == arts.batch_runtime(operator.address)


def test_execute_refuses_when_the_operator_cannot_pay(w3, accounts, positions, parties, arts, store):
    fund(w3, parties.operator.address, 1)
    plan = make_plan(w3, accounts, parties, rescue_actions(positions))
    nonce = w3.eth.get_transaction_count(parties.operator.address)
    with pytest.raises(InsufficientOperatorFunds):
        execute(w3, plan, parties.victim, parties.operator, arts, store)
    assert w3.eth.get_transaction_count(parties.operator.address) == nonce


def test_op_stack_data_fee_counts_toward_the_operators_balance(w3, accounts, positions, parties, arts, store):
    # Enough for gas alone, not for gas plus the data fee the oracle quotes.
    budget = FAKE_L1_FEE
    fund(w3, parties.operator.address, budget)
    ensure_batch(w3, parties.operator, store, arts)  # the control: without the oracle this balance pays
    w3.provider.make_request("anvil_setCode", [ORACLE, FAKE_ORACLE_CODE])
    fund(w3, parties.operator.address, budget)
    plan = make_plan(w3, accounts, parties, rescue_actions(positions))
    with pytest.raises(InsufficientOperatorFunds) as info:
        execute(w3, plan, parties.victim, parties.operator, arts, store)
    assert info.value.need > FAKE_L1_FEE * 3 // 2 > budget


@pytest.mark.parametrize("which", ["wrong_victim", "wrong_operator", "wrong_chain"])
def test_execute_refuses_mismatched_parties(w3, accounts, positions, parties, arts, store, which):
    plan = make_plan(w3, accounts, parties, rescue_actions(positions))
    victim, operator = parties.victim, parties.operator
    if which == "wrong_victim":
        victim = Signer(accounts.funder)
    elif which == "wrong_operator":
        operator = Signer(accounts.funder)
    else:
        plan.chain_id += 1
    with pytest.raises(ExecuteRefused):
        execute(w3, plan, victim, operator, arts, store)
    assert w3.eth.get_transaction_count(parties.operator.address) == 0


def test_sweep_back_only_to_safe(w3, accounts, parties):
    operator, safe, victim = parties.operator, parties.safe, parties.victim.address
    for bad in (ZERO, operator.address, "not an address", "", None):
        with pytest.raises(PolicyError):
            sweep_back(w3, operator, bad)
    assert w3.eth.get_balance(operator.address) == 10**18  # every refusal happened before any send

    safe_before = w3.eth.get_balance(safe)
    tx_hash = sweep_back(w3, operator, safe)

    receipt = w3.eth.get_transaction_receipt(tx_hash)
    fee = receipt["gasUsed"] * receipt["effectiveGasPrice"]
    left = w3.eth.get_balance(operator.address)
    gained = w3.eth.get_balance(safe) - safe_before
    assert receipt["to"] == safe
    assert gained + fee + left == 10**18
    assert left < 10**14
    assert w3.eth.get_balance(victim) == 0
    assert sweep_back(w3, operator, safe) is None  # the leftover is worth less than another transfer costs


def test_sweep_back_keeps_enough_for_an_op_stack_data_fee(w3, parties):
    w3.provider.make_request("anvil_setCode", [ORACLE, FAKE_ORACLE_CODE])
    assert sweep_back(w3, parties.operator, parties.safe)
    left = w3.eth.get_balance(parties.operator.address)
    assert 2 * FAKE_L1_FEE <= left < 2 * FAKE_L1_FEE + 10**14
