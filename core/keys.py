"""Signing keys. A Signer never shows its key: not in repr, str, errors or pickles.

The victim key comes from the Hermes secret scope. Operator keys are generated here and
written to the plugin data directory before their address is ever shown, so funds sent to an
operator can always be recovered.

The data directory is writable, and readable, by anything else the agent runs. An operator file
therefore holds its key sealed, and carries a MAC, both under a secret derived from the victim key,
which only the secret scope has. A file somebody else wrote does not verify and is ignored, and
reading a real one gives no key. Recovering an operator by hand needs the victim key as well.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Callable

from eth_account import Account
from eth_utils import keccak, to_checksum_address

VICTIM_KEY_ENV = "LIFEBOAT_VICTIM_KEY"

SecretSink = Callable[[str], None]
SealSource = Callable[[], bytes]


class KeyConfigError(Exception):
    pass


class Signer:
    __slots__ = ("address", "_account")

    def __init__(self, account) -> None:
        self.address: str = account.address
        self._account = account

    def __repr__(self) -> str:
        return f"Signer({self.address})"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("Signer cannot be pickled")

    def sign_transaction(self, tx: dict) -> bytes:
        return bytes(self._account.sign_transaction(tx).raw_transaction)

    def sign_authorization(self, chain_id: int, contract: str, nonce: int):
        """EIP-7702 authorization pointing this account at `contract`."""
        return Account.sign_authorization(
            {"chainId": int(chain_id), "address": to_checksum_address(contract), "nonce": int(nonce)},
            self._account.key,
        )


def _parse_key(value: str | None, on_secret: SecretSink):
    """Return an account or None. Kept separate so no failing frame holds the key."""
    if not value or not value.strip():
        return None
    value = value.strip()
    on_secret(value)
    try:
        return Account.from_key(value)
    except Exception:
        return None


def victim_signer(get_secret: Callable[[str], str | None], on_secret: SecretSink) -> Signer:
    account = _parse_key(get_secret(VICTIM_KEY_ENV), on_secret)
    if account is None:
        raise KeyConfigError(f"{VICTIM_KEY_ENV} is missing or is not a valid private key")
    return Signer(account)


def seal_secret(get_secret: Callable[[str], str | None], on_secret: SecretSink) -> bytes:
    """The secret operator files are sealed and authenticated with. It never leaves this module's callers."""
    account = _parse_key(get_secret(VICTIM_KEY_ENV), on_secret)
    if account is None:
        raise KeyConfigError(f"{VICTIM_KEY_ENV} is missing or is not a valid private key")
    return keccak(bytes(account.key) + b"lifeboat-operator-seal")


def seal_tag(seal: bytes, *parts: str) -> str:
    """A tag over a record lifeboat stores in the open and wants to recognise as its own later."""
    return hmac.new(seal, ("tag:" + "\n".join(parts)).encode(), hashlib.sha256).hexdigest()


def _pad(seal: bytes, address: str) -> bytes:
    return hmac.new(seal, b"pad:" + address.encode(), hashlib.sha256).digest()


def _mac(seal: bytes, address: str, sealed: str, created_at: int) -> str:
    message = f"mac:{address}:{sealed}:{created_at}".encode()
    return hmac.new(seal, message, hashlib.sha256).hexdigest()


class OperatorStore:
    """Fresh operator wallets, one JSON file each under <data_dir>/operators/. Only files this store
    wrote under the current victim key count; anything else in the folder is ignored."""

    def __init__(self, data_dir: Path, on_secret: SecretSink, seal: SealSource) -> None:
        self.dir = Path(data_dir) / "operators"
        self._on_secret = on_secret
        self._seal = seal

    def create(self) -> Signer:
        seal = self._seal()
        account = Account.create()
        self._on_secret("0x" + bytes(account.key).hex())
        address = account.address
        sealed = bytes(a ^ b for a, b in zip(bytes(account.key), _pad(seal, address))).hex()
        created_at = int(time.time())
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self.dir / f"{address}.json"
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"address": address, "sealed": sealed, "created_at": created_at,
                       "mac": _mac(seal, address, sealed, created_at)}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        if self.load(address).address != address:
            raise KeyConfigError("operator key file did not read back")
        return Signer(account)

    def _verified(self, path: Path, seal: bytes) -> dict | None:
        """The record in `path` when this store wrote it under the current victim key, else nothing."""
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
            address, sealed, created_at = saved["address"], saved["sealed"], saved["created_at"]
            if not isinstance(created_at, int) or path.stem != address:
                return None
            if not hmac.compare_digest(str(saved["mac"]), _mac(seal, address, sealed, created_at)):
                return None
            return {"address": address, "sealed": sealed, "created_at": created_at}
        except Exception:
            return None

    def load(self, address: str) -> Signer:
        address = to_checksum_address(address)
        record = self._verified(self.dir / f"{address}.json", self._seal())
        if record is None:
            raise KeyConfigError(f"no operator key stored for {address}")
        key = bytes(a ^ b for a, b in zip(bytes.fromhex(record["sealed"]), _pad(self._seal(), address)))
        account = _parse_key("0x" + key.hex(), self._on_secret)
        if account is None or account.address != address:
            raise KeyConfigError(f"operator key file for {address} is damaged")
        return Signer(account)

    def _records(self) -> list[dict]:
        if not self.dir.exists():
            return []
        try:
            seal = self._seal()
        except KeyConfigError:
            return []  # without the victim key no operator file can be told from a planted one
        records = [r for r in (self._verified(path, seal) for path in self.dir.glob("*.json")) if r]
        return sorted(records, key=lambda r: (r["created_at"], r["address"]))

    def addresses(self) -> list[str]:
        return [r["address"] for r in self._records()]

    def latest(self) -> Signer | None:
        records = self._records()
        return self.load(records[-1]["address"]) if records else None
