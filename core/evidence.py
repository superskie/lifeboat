"""Signs that a wallet is being swept, read from public chain history.

lifeboat exists for one situation: gas sent to the wallet is taken before it can be used. A wallet
nobody sweeps can be funded and emptied the ordinary way, so a rescue is only offered when a sweep
is on record. A leaked key is leaked on every chain, so a sweep seen on one chain counts for all.

This shows that a sweep happened. It does not show who owns the wallet: the owner and the thief hold
the same key, and nothing on chain tells them apart.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from datetime import datetime
import requests
from eth_utils import to_checksum_address

from .chains import Chain
from .scrub import strip_urls

WINDOW = 300  # seconds between a transfer arriving and leaving again
MIN_SWEEPS = 2
PAGES = 2
DELEGATION_PREFIX = bytes.fromhex("ef0100")
_HASH = re.compile(r"^0x[0-9a-fA-F]{64}(#\d{1,6})?$")  # a transaction, or an internal call by its index in one

_session = requests.Session()
_session.headers["User-Agent"] = "lifeboat-plugin"
_session_lock = threading.Lock()


@dataclass(frozen=True)
class Sweep:
    incoming: str
    outgoing: str
    seconds: int
    to: str


@dataclass(frozen=True)
class Evidence:
    chain: str
    sweeps: tuple[Sweep, ...]

    def line(self) -> str:
        last = self.sweeps[0]
        return (
            f"on {self.chain}, {len(self.sweeps)} incoming transfers left the wallet again within "
            f"{WINDOW} seconds (latest: {last.incoming} in, {last.outgoing} out to {last.to} "
            f"{last.seconds} s later)"
        )


def fetch_transactions(chain: Chain, address: str, pages: int = PAGES) -> list[dict]:
    """The wallet's latest transactions from the chain's Blockscout, newest first."""
    items: list[dict] = []
    params: dict | None = None
    for _ in range(pages):
        with _session_lock:
            reply = _session.get(f"{chain.blockscout}/api/v2/addresses/{address}/transactions",
                                 params=params, timeout=10)
        reply.raise_for_status()
        doc = reply.json()
        items.extend(doc.get("items") or [])
        params = doc.get("next_page_params")
        if not params:
            break
    return items


def fetch_internal(chain: Chain, address: str) -> list[dict]:
    """The wallet's latest internal calls, in the shape of `fetch_transactions`. A wallet delegated to a
    sweeper contract forwards what arrives from inside the incoming transaction, so that movement only
    shows here. An internal call is named by its transaction hash and its index in it."""
    with _session_lock:
        reply = _session.get(f"{chain.blockscout}/api/v2/addresses/{address}/internal-transactions", timeout=10)
    reply.raise_for_status()
    return [
        {"hash": f"{item.get('transaction_hash')}#{item.get('index')}", "timestamp": item.get("timestamp"),
         "from": item.get("from"), "to": item.get("to"), "value": item.get("value"),
         "result": "success" if item.get("success") and item.get("type") == "call" else "failed"}
        for item in reply.json().get("items") or [] if isinstance(item, dict)
    ]


def _party(item: dict, side: str) -> str | None:
    value = (item.get(side) or {}).get("hash")
    try:
        return to_checksum_address(value) if value else None
    except Exception:
        return None


def _moment(item: dict) -> float | None:
    try:
        return datetime.fromisoformat(str(item["timestamp"]).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def find_sweeps(items: list[dict], victim: str) -> list[Sweep]:
    """Native transfers into the wallet that left again, to another address, within WINDOW seconds and
    for at least half the amount. Newest first. Each outgoing transfer answers one incoming transfer."""
    victim = to_checksum_address(victim)
    arrived, left = [], []
    for item in items:
        when = _moment(item)
        try:
            value = int(item.get("value") or 0)
        except (TypeError, ValueError):
            continue
        # The hashes end up in the approval text, so only something shaped like one is accepted.
        if when is None or value <= 0 or item.get("result") != "success" or not _HASH.match(str(item.get("hash"))):
            continue
        sender, receiver = _party(item, "from"), _party(item, "to")
        if receiver == victim and sender != victim:
            arrived.append((when, value, item))
        elif sender == victim and receiver not in (None, victim):
            left.append((when, value, item, receiver))
    arrived.sort(key=lambda entry: entry[0])
    left.sort(key=lambda entry: entry[0])
    used: set[str] = set()
    sweeps: list[Sweep] = []
    for when, value, item in arrived:
        for out_when, out_value, out_item, receiver in left:
            if out_item["hash"] in used or not when <= out_when <= when + WINDOW or out_value * 2 < value:
                continue
            used.add(out_item["hash"])
            sweeps.append(Sweep(str(item["hash"]), str(out_item["hash"]), int(out_when - when), receiver))
            break
    return sweeps[::-1]


def foreign_delegation(code: bytes, own: set[str]) -> str | None:
    """The contract an EIP-7702 wallet is delegated to, unless it is one of lifeboat's own batches."""
    code = bytes(code)
    if len(code) != 23 or code[:3] != DELEGATION_PREFIX:
        return None
    target = to_checksum_address(code[3:])
    return None if target in own else target


def gather(victim: str, chains: list[Chain]) -> tuple[Evidence | None, dict[str, str]]:
    """The first evidence found, looking at `chains` in order, and why any chain could not be read.
    A chain that fails never hides what another chain shows.

    A delegation by itself is not evidence: wallet apps delegate accounts to their own contracts, so a
    delegated wallet is not thereby a swept one. What a sweeper contract does with incoming gas is."""
    errors: dict[str, str] = {}
    for chain in chains:
        if not chain.blockscout:
            errors[chain.name] = "no readable history"
            continue
        try:
            items = list(fetch_transactions(chain, victim))
        except Exception as exc:
            errors[chain.name] = f"history unreadable: {strip_urls(exc)[:120]}"
            continue
        try:
            items += fetch_internal(chain, victim)
        except Exception as exc:
            errors[chain.name] = f"internal calls unreadable: {strip_urls(exc)[:120]}"
        sweeps = find_sweeps(items, victim)
        if len(sweeps) >= MIN_SWEEPS:
            return Evidence(chain.name, tuple(sweeps)), errors
    return None, errors
