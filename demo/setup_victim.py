"""Give the demo victim something worth rescuing: free tokens, a stake, a vesting grant and an NFT.

Usage: python demo/setup_victim.py [--rpc URL] [--unlock-in SECONDS]

Run it once, before the sweeper starts. It deploys test contracts from the deployer wallet, so that
wallet needs a little testnet ETH first; the script prints its address and stops when it has none.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from web3 import Web3

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import DEFAULT_RPC, accounts, compile_contracts, deploy, load_env, save_state, send  # noqa: E402

FREE = 400 * 10**18
STAKED = 600 * 10**18
VESTED = 500 * 10**18
VICTIM_GAS = 5 * 10**14  # what the wallet held before the leak: enough to approve and stake
MIN_DEPLOYER = 5 * 10**15


def setup(w3: Web3, who: dict, out: Path, unlock_in: int = 120) -> dict:
    deployer, victim = who["deployer"], who["victim"]
    token = deploy(w3, out, deployer, "MockToken", "Locked", "LCK")
    nft = deploy(w3, out, deployer, "MockNFT")
    staking = deploy(w3, out, deployer, "MockStaking", token.address, nft.address)
    unlock = w3.eth.get_block("latest")["timestamp"] + unlock_in
    vesting = deploy(w3, out, deployer, "MockVesting", token.address, victim.address, unlock)

    token.tx(deployer, "mint", victim.address, FREE + STAKED)
    token.tx(deployer, "mint", vesting.address, VESTED)
    nft.tx(deployer, "safeMint", victim.address)
    send(w3, deployer, {"to": victim.address, "value": VICTIM_GAS, "gas": 21_000})
    token.tx(victim, "approve", staking.address, STAKED)
    staking.tx(victim, "stake", STAKED)

    return {
        "chain_id": w3.eth.chain_id,
        "victim": victim.address,
        "safe": who["safe"].address,
        "sweeper": who["sweeper"].address,
        "token": token.address,
        "nft": nft.address,
        "nft_id": 1,
        "staking": staking.address,
        "vesting": vesting.address,
        "unlock_time": unlock,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rpc", default=DEFAULT_RPC)
    parser.add_argument("--unlock-in", type=int, default=120, help="seconds until the vesting grant unlocks")
    args = parser.parse_args()

    w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": 30}))
    who = accounts(load_env())
    deployer = who["deployer"].address
    balance = w3.eth.get_balance(deployer)
    if balance < MIN_DEPLOYER:
        print(f"The deployer {deployer} holds {balance} wei on chain {w3.eth.chain_id}.")
        print(f"Send it at least {MIN_DEPLOYER} wei of testnet ETH from a faucet, then run this again.")
        return 1

    state = setup(w3, who, compile_contracts(), args.unlock_in)
    save_state(state)
    print(f"Victim {state['victim']} now holds, on chain {state['chain_id']}:")
    print(f"  {FREE} of token {state['token']}, free")
    print(f"  {STAKED} of it staked in {state['staking']}  (withdraw())")
    print(f"  {VESTED} of it vesting in {state['vesting']}, unlocking at {state['unlock_time']}  (claim())")
    print(f"  NFT {state['nft']} #1")
    print("For Hermes: LIFEBOAT_SAFE_ADDRESS is", state["safe"])
    print("            LIFEBOAT_VICTIM_KEY is the VICTIM_KEY line in demo/.env (copy it there, not into chat)")
    print("Next: python demo/sweeper.py --bait 2, then follow demo/README.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
