"""What a drained wallet still holds, chain by chain, read from the RPC and the chain's explorer.

Everything here is read-only and nothing touches the wallet on chain. Token names and symbols are
written by whoever deployed the token, and a drained wallet is full of spam, so no free text from
a token reaches the model: a symbol is cut down to a few plain characters and the name is dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from eth_utils import to_checksum_address

from .chains import Chain
from . import evidence
from .evidence import _session, _session_lock, find_sweeps, foreign_delegation
from .scrub import strip_urls

MAX_TOKENS = 40
MAX_NFTS = 40
_SYMBOL_UNSAFE = re.compile(r"[^A-Za-z0-9.$_-]")


@dataclass(frozen=True)
class TokenHolding:
    token: str
    symbol: str
    decimals: int | None
    amount: int
    usd: float | None  # the explorer's estimate; a guide for ordering, never a price to act on


@dataclass(frozen=True)
class NftHolding:
    token: str
    standard: str  # erc721 or erc1155
    token_id: int
    amount: int
    symbol: str


@dataclass
class ChainReport:
    chain_id: int
    chain: str
    native: int | None = None
    erc20: list[TokenHolding] = field(default_factory=list)
    nfts: list[NftHolding] = field(default_factory=list)
    delegated_to: str | None = None
    sweeps: int | None = None  # incoming gas that left again within minutes; None when unreadable
    notes: list[str] = field(default_factory=list)

    def actions(self) -> list[dict]:
        """Transfer steps for everything found, ready to hand to a plan."""
        steps: list[dict] = [{"type": "transfer_erc20", "token": t.token, "amount": "all"} for t in self.erc20]
        for nft in self.nfts:
            step = {"type": "transfer_nft", "standard": nft.standard, "token": nft.token, "token_id": str(nft.token_id)}
            if nft.standard == "erc1155":
                step["amount"] = str(nft.amount)
            steps.append(step)
        if self.native:
            steps.append({"type": "transfer_native", "amount": "all"})
        return steps

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "chain": self.chain,
            "native_wei": None if self.native is None else str(self.native),
            "erc20": [
                {"token": t.token, "symbol": t.symbol, "decimals": t.decimals, "amount": str(t.amount),
                 "usd_estimate": t.usd}
                for t in self.erc20
            ],
            "nfts": [
                {"token": n.token, "standard": n.standard, "token_id": str(n.token_id), "amount": str(n.amount),
                 "symbol": n.symbol}
                for n in self.nfts
            ],
            "delegated_to": self.delegated_to,
            "sweeps_on_record": self.sweeps,
            "notes": list(self.notes),
            "actions": self.actions(),
        }


def clean_symbol(value) -> str:
    return _SYMBOL_UNSAFE.sub("", str(value or ""))[:12] or "?"


def fetch_holdings(chain: Chain, address: str, path: str) -> list[dict]:
    """One page of `tokens?...` or `nft?...` for the address. The first page is ordered by value."""
    with _session_lock:
        reply = _session.get(f"{chain.blockscout}/api/v2/addresses/{address}/{path}", timeout=10)
    reply.raise_for_status()
    return reply.json().get("items") or []


def _token_address(token: dict) -> str:
    return to_checksum_address(token.get("address_hash") or token.get("address"))


def _number(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_erc20(items: list[dict]) -> list[TokenHolding]:
    found: list[TokenHolding] = []
    for item in items:
        try:
            token = item["token"]
            amount = int(item["value"])
            if amount <= 0 or token.get("type") != "ERC-20":
                continue
            decimals = _number(token.get("decimals"))
            usd = None
            if token.get("exchange_rate") is not None and decimals is not None and 0 <= decimals <= 36:
                usd = round(amount / 10**decimals * float(token["exchange_rate"]), 2)
            found.append(TokenHolding(_token_address(token), clean_symbol(token.get("symbol")), decimals, amount, usd))
        except Exception:
            continue  # one malformed entry never hides the rest
    return found


def parse_nfts(items: list[dict]) -> list[NftHolding]:
    found: list[NftHolding] = []
    for item in items:
        try:
            token = item["token"]
            standard = {"ERC-721": "erc721", "ERC-1155": "erc1155"}.get(item.get("token_type") or token.get("type"))
            token_id = int(item["id"])
            amount = 1 if standard == "erc721" else int(item.get("value") or 0)
            if standard is None or token_id < 0 or amount <= 0:
                continue
            found.append(NftHolding(_token_address(token), standard, token_id, amount, clean_symbol(token.get("symbol"))))
        except Exception:
            continue
    return found


def scan_chain(chain: Chain, victim: str, native_of: Callable[[Chain], int], code_of: Callable[[Chain], bytes],
               own: set[str]) -> ChainReport:
    report = ChainReport(chain.id, chain.name)
    try:
        report.native = int(native_of(chain))
        report.delegated_to = foreign_delegation(code_of(chain), own)
    except Exception as exc:
        report.notes.append(f"RPC unreadable: {strip_urls(exc)[:120]}")
    if not chain.blockscout:
        report.notes.append("no readable explorer for this chain: tokens and NFTs are not listed, name them yourself")
        return report
    for what, read in (
        ("tokens", lambda: setattr(report, "erc20", parse_erc20(fetch_holdings(chain, victim, "tokens?type=ERC-20")))),
        ("NFTs", lambda: setattr(report, "nfts", parse_nfts(
            fetch_holdings(chain, victim, "nft?type=ERC-721%2CERC-1155")))),
        ("history", lambda: setattr(report, "sweeps", len(find_sweeps(evidence.fetch_transactions(chain, victim), victim)))),
    ):
        try:
            read()
        except Exception as exc:
            report.notes.append(f"{what} unreadable: {strip_urls(exc)[:120]}")
    if len(report.erc20) > MAX_TOKENS or len(report.nfts) > MAX_NFTS:
        report.notes.append(f"more than {MAX_TOKENS} tokens or NFTs held; only the first ones are listed")
        report.erc20, report.nfts = report.erc20[:MAX_TOKENS], report.nfts[:MAX_NFTS]
    return report


def scan(victim: str, chains: list[Chain], native_of: Callable[[Chain], int], code_of: Callable[[Chain], bytes],
         own: set[str]) -> list[ChainReport]:
    """One report per chain. A chain that fails is reported with its error and never stops the others."""
    reports: list[ChainReport] = []
    for chain in chains:
        try:
            reports.append(scan_chain(chain, victim, native_of, code_of, own))
        except Exception as exc:
            reports.append(ChainReport(chain.id, chain.name, notes=[f"scan failed: {strip_urls(exc)[:120]}"]))
    return reports
