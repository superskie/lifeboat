"""Shared pieces of the demo: throwaway keys, contract deployment, plain transactions.

The demo runs on a testnet with keys generated on first use and kept in demo/.env, which git
ignores. None of them is ever worth anything; the "victim" key is leaked on purpose.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from eth_account import Account
from web3 import Web3

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / "demo" / ".env"
STATE_PATH = ROOT / "demo" / ".state" / "addresses.json"
CONTRACTS = ROOT / "contracts"
DEFAULT_RPC = "https://sepolia.base.org"  # Base Sepolia
ROLES = ("DEPLOYER", "VICTIM", "SAFE", "SWEEPER")


def load_env(path: Path = ENV_PATH) -> dict[str, str]:
    """The demo keys, created on first use. One `NAME_KEY=0x...` line per role."""
    values: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                name, value = line.split("=", 1)
                values[name.strip()] = value.strip()
    missing = [role for role in ROLES if f"{role}_KEY" not in values]
    if missing:
        for role in missing:
            values[f"{role}_KEY"] = "0x" + bytes(Account.create().key).hex()
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# Throwaway testnet keys for the lifeboat demo. Never fund them on a mainnet."]
        lines += [f"{name}={value}" for name, value in sorted(values.items())]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return values


def accounts(env: dict[str, str]) -> dict[str, object]:
    return {role.lower(): Account.from_key(env[f"{role}_KEY"]) for role in ROLES}


def send(w3: Web3, account, tx: dict) -> dict:
    """Fill, sign and send one transaction; return the receipt. Raises when it reverts."""
    tx = dict(tx)
    tx.setdefault("chainId", w3.eth.chain_id)
    tx.setdefault("nonce", w3.eth.get_transaction_count(account.address, "pending"))
    tx.setdefault("value", 0)
    tip = 10**6
    tx.setdefault("maxPriorityFeePerGas", tip)
    tx.setdefault("maxFeePerGas", int(w3.eth.get_block("latest")["baseFeePerGas"]) * 2 + tip)
    if "gas" not in tx:
        tx["gas"] = w3.eth.estimate_gas({**tx, "from": account.address}) * 13 // 10 + 10_000
    signed = account.sign_transaction(tx)
    receipt = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed.raw_transaction), timeout=120)
    if receipt["status"] != 1:
        raise RuntimeError(f"transaction {receipt['transactionHash'].hex()} reverted")
    return receipt


def compile_contracts() -> Path:
    subprocess.run(["forge", "build"], cwd=CONTRACTS, check=True, capture_output=True)
    return CONTRACTS / "out"


class Deployed:
    def __init__(self, w3: Web3, address: str, abi: list):
        self.w3, self.address = w3, address
        self.contract = w3.eth.contract(address=address, abi=abi)

    def tx(self, account, fn: str, *args) -> dict:
        return send(self.w3, account, {"to": self.address, "data": self.contract.encode_abi(fn, args=list(args))})


def deploy(w3: Web3, out: Path, account, name: str, *args) -> Deployed:
    raw = json.loads((out / f"{name}.sol" / f"{name}.json").read_text(encoding="utf-8"))
    factory = w3.eth.contract(abi=raw["abi"], bytecode=raw["bytecode"]["object"])
    receipt = send(w3, account, {"data": factory.constructor(*args).data_in_transaction})
    return Deployed(w3, receipt["contractAddress"], raw["abi"])


def save_state(doc: dict, path: Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def load_state(path: Path = STATE_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
