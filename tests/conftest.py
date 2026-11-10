"""Shared fixtures: the repo loaded as package `lifeboat`, and a Prague anvil per session."""

from __future__ import annotations

import importlib.util
import json
import socket
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest
from eth_account import Account
from web3 import Web3

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "contracts"


def _load_package() -> None:
    """Import the repo root as `lifeboat` so the relative imports Hermes uses also work here."""
    if "lifeboat" in sys.modules:
        return
    init = ROOT / "__init__.py"
    if init.exists():
        spec = importlib.util.spec_from_file_location("lifeboat", init, submodule_search_locations=[str(ROOT)])
        module = importlib.util.module_from_spec(spec)
        sys.modules["lifeboat"] = module
        spec.loader.exec_module(module)
    else:
        module = types.ModuleType("lifeboat")
        module.__path__ = [str(ROOT)]
        sys.modules["lifeboat"] = module


_load_package()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_anvil(*extra: str) -> tuple[subprocess.Popen, str]:
    port = _free_port()
    proc = subprocess.Popen(
        ["anvil", "--hardfork", "prague", "--port", str(port), "--silent", *extra],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    probe = Web3(Web3.HTTPProvider(url))
    deadline = time.time() + 20
    while True:
        try:
            probe.eth.chain_id
            return proc, url
        except Exception:
            if time.time() > deadline:
                proc.kill()
                raise RuntimeError("anvil did not start")
            time.sleep(0.1)


@pytest.fixture(scope="session")
def compiled() -> Path:
    subprocess.run(["forge", "build"], cwd=CONTRACTS, check=True, capture_output=True)
    return CONTRACTS / "out"


@pytest.fixture(scope="session")
def anvil_url():
    proc, url = start_anvil()
    yield url
    proc.terminate()
    proc.wait(10)


@pytest.fixture
def w3(anvil_url):
    """A Web3 on the session anvil; chain state is reverted after each test."""
    web3 = Web3(Web3.HTTPProvider(anvil_url))
    snapshot = web3.provider.make_request("evm_snapshot", [])["result"]
    yield web3
    web3.provider.make_request("evm_revert", [snapshot])


def fund(w3: Web3, address: str, wei: int) -> None:
    w3.provider.make_request("anvil_setBalance", [address, hex(wei)])


def new_account(w3: Web3 | None = None, wei: int = 0):
    account = Account.create()
    if w3 is not None and wei:
        fund(w3, account.address, wei)
    return account


def send(w3: Web3, account, tx: dict) -> dict:
    """Fill, sign and send a transaction from a local account; return the receipt."""
    tx = dict(tx)
    tx.setdefault("chainId", w3.eth.chain_id)
    tx.setdefault("nonce", w3.eth.get_transaction_count(account.address))
    tx.setdefault("value", 0)
    if "gas" not in tx:
        tx["gas"] = int(w3.eth.estimate_gas({**tx, "from": account.address}) * 1.3) + 10_000
    base = w3.eth.get_block("latest")["baseFeePerGas"]
    tx.setdefault("maxPriorityFeePerGas", 10**9)
    tx.setdefault("maxFeePerGas", base * 2 + tx["maxPriorityFeePerGas"])
    signed = account.sign_transaction(tx)
    receipt = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed.raw_transaction), timeout=30)
    return receipt


def deploy_code(w3: Web3, account, initcode: bytes) -> str:
    receipt = send(w3, account, {"data": initcode})
    assert receipt["status"] == 1, "deployment reverted"
    return receipt["contractAddress"]


class Fixture:
    """A deployed test contract: `.address`, `.contract` (web3 contract), `.call(account, fn, *args)`."""

    def __init__(self, w3: Web3, address: str, abi: list):
        self.w3 = w3
        self.address = address
        self.contract = w3.eth.contract(address=address, abi=abi)

    def tx(self, account, fn: str, *args, value: int = 0) -> dict:
        data = self.contract.encode_abi(fn, args=list(args))
        receipt = send(self.w3, account, {"to": self.address, "data": data, "value": value})
        assert receipt["status"] == 1, f"{fn} reverted"
        return receipt


def deploy(w3: Web3, out: Path, account, name: str, *args) -> Fixture:
    raw = json.loads((out / f"{name}.sol" / f"{name}.json").read_text(encoding="utf-8"))
    factory = w3.eth.contract(abi=raw["abi"], bytecode=raw["bytecode"]["object"])
    initcode = factory.constructor(*args).data_in_transaction
    address = deploy_code(w3, account, bytes.fromhex(initcode[2:]))
    return Fixture(w3, address, raw["abi"])


class Accounts:
    def __init__(self, w3: Web3):
        self.funder = new_account(w3, 1000 * 10**18)
        self.victim = new_account()
        self.operator = new_account()
        self.safe = new_account()
        self.sweeper_dest = new_account()


@pytest.fixture
def accounts(w3):
    return Accounts(w3)


class Positions:
    """Mocks deployed with the victim holding free tokens, a stake, an NFT, an ERC-1155 balance
    and a vesting grant. The victim ends with zero ETH, as a drained wallet does."""

    FREE = 400 * 10**18
    STAKED = 600 * 10**18
    VESTED = 500 * 10**18
    MULTI_ID = 7
    MULTI_AMOUNT = 5

    def __init__(self, w3: Web3, out: Path, acc: Accounts, unlock_delay: int = 3600):
        f = acc.funder
        self.token = deploy(w3, out, f, "MockToken", "Locked", "LCK")
        self.nft = deploy(w3, out, f, "MockNFT")
        self.multi = deploy(w3, out, f, "MockMulti")
        self.staking = deploy(w3, out, f, "MockStaking", self.token.address, self.nft.address)
        self.unlock_time = w3.eth.get_block("latest")["timestamp"] + unlock_delay
        self.vesting = deploy(w3, out, f, "MockVesting", self.token.address, acc.victim.address, self.unlock_time)
        victim = acc.victim.address
        self.token.tx(f, "mint", victim, self.FREE + self.STAKED)
        self.token.tx(f, "mint", self.vesting.address, self.VESTED)
        self.nft.tx(f, "safeMint", victim)
        self.nft_id = 1
        self.multi.tx(f, "mint", victim, self.MULTI_ID, self.MULTI_AMOUNT)
        fund(w3, victim, 10**17)
        self.token.tx(acc.victim, "approve", self.staking.address, self.STAKED)
        self.staking.tx(acc.victim, "stake", self.STAKED)
        fund(w3, victim, 0)


@pytest.fixture
def positions(w3, compiled, accounts):
    return Positions(w3, compiled, accounts)


class Sweeper:
    """Sends every wei that reaches the victim to sweeper_dest, as a sweeper bot does."""

    def __init__(self, url: str, victim, dest: str, interval: float = 0.05):
        import threading

        self.w3 = Web3(Web3.HTTPProvider(url))
        self.victim = victim
        self.dest = dest
        self.interval = interval
        self.taken = 0
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "Sweeper":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(5)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._sweep_once()
            except Exception as exc:  # keep sweeping; tests read errors if they care
                self.errors.append(type(exc).__name__)
            self._stop.wait(self.interval)

    def _sweep_once(self) -> None:
        balance = self.w3.eth.get_balance(self.victim.address)
        base = self.w3.eth.get_block("latest")["baseFeePerGas"]
        priority = 10**9
        max_fee = base * 2 + priority
        cost = 21_000 * max_fee
        if balance <= cost:
            return
        receipt = send(
            self.w3,
            self.victim,
            {"to": self.dest, "value": balance - cost, "gas": 21_000,
             "maxFeePerGas": max_fee, "maxPriorityFeePerGas": priority},
        )
        if receipt["status"] == 1:
            self.taken += balance - cost


@pytest.fixture
def sweeper(w3, anvil_url, accounts):
    bot = Sweeper(anvil_url, accounts.victim, accounts.sweeper_dest.address).start()
    yield bot
    bot.stop()
