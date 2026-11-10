import time

from conftest import Positions, send


def test_positions_leave_victim_drained_with_assets_locked(w3, accounts, positions):
    victim = accounts.victim.address
    assert w3.eth.get_balance(victim) == 0
    assert positions.token.contract.functions.balanceOf(victim).call() == Positions.FREE
    assert positions.staking.contract.functions.staked(victim).call() == Positions.STAKED
    assert positions.nft.contract.functions.ownerOf(positions.nft_id).call() == victim


def test_sweeper_takes_incoming_gas(w3, accounts, sweeper):
    victim = accounts.victim.address
    send(w3, accounts.funder, {"to": victim, "value": 10**16, "gas": 21_000})
    deadline = time.time() + 3
    while sweeper.taken == 0 and time.time() < deadline:
        time.sleep(0.05)
    assert sweeper.taken > 0
    assert w3.eth.get_balance(victim) < 21_000 * 10 * 10**9
