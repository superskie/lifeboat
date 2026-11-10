"""Dry-runs a plan with eth_call state overrides: the victim's address runs lifeboat code, no delegation."""

from __future__ import annotations

from dataclasses import dataclass, field

from eth_abi import decode, encode
from eth_utils import function_signature_to_4byte_selector as _sel
from eth_utils import to_checksum_address
from web3 import Web3
from web3.exceptions import ContractLogicError

from .artifacts import Artifacts, Call, Check, Probe, SimOutput
from .plan import ZERO, Plan
from .scrub import strip_urls

_ERROR = _sel("Error(string)")
_PANIC = _sel("Panic(uint256)")
_BALANCE_OF = _sel("balanceOf(address)")
_OWNER_OF = _sel("ownerOf(uint256)")
_BALANCE_OF_ID = _sel("balanceOf(address,uint256)")


class SimulationUnavailable(RuntimeError):
    """The RPC could not run the simulation (no state override support, or the node failed)."""


@dataclass(frozen=True)
class CallResult:
    ok: bool
    reason: str | None


@dataclass(frozen=True)
class BalanceDelta:
    asset: str
    kind: str  # erc20, erc721, erc1155 or native
    token: str
    token_id: int | None
    victim_before: int
    victim_after: int
    safe_before: int
    safe_after: int

    def to_dict(self) -> dict:
        return {
            "asset": self.asset,
            "victim_before": str(self.victim_before),
            "victim_after": str(self.victim_after),
            "safe_before": str(self.safe_before),
            "safe_after": str(self.safe_after),
        }


@dataclass
class SimResult:
    ok: bool
    revert_reason: str | None
    calls: list[CallResult]
    balances: list[BalanceDelta]
    native_after: int
    deltas_ok: bool
    block: int
    warnings: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)  # what the batch enforces on chain for this result

    def gains(self) -> dict[str, int]:
        """What each planned asset adds to the safe address: the amounts a person is asked to approve."""
        return {b.asset: b.safe_after - b.safe_before for b in self.balances if b.safe_after > b.safe_before}

    def to_dict(self) -> dict:
        """The shape stored on the plan and read by `summarize`; integers stay strings for JSON safety."""
        return {
            "ok": self.ok,
            "revert_reason": self.revert_reason,
            "block": self.block,
            "deltas_ok": self.deltas_ok,
            "native_after": str(self.native_after),
            "warnings": list(self.warnings),
            "calls": [{"ok": c.ok, "reason": c.reason} for c in self.calls],
            "balances": [b.to_dict() for b in self.balances],
        }


def decode_revert(data: bytes | None) -> str | None:
    """Readable text for revert data: Error(string), Panic(uint256), or none for an empty revert."""
    if not data:
        return None
    data = bytes(data)
    try:
        if data[:4] == _ERROR:
            return decode(["string"], data[4:])[0]
        if data[:4] == _PANIC:
            return f"panic code {decode(['uint256'], data[4:])[0]:#x}"
    except Exception:
        pass
    return "reverted with data 0x" + data[:36].hex()


def _revert_text(exc: ContractLogicError) -> str:
    raw = getattr(exc, "data", None)
    if isinstance(raw, str) and raw.startswith("0x"):
        try:
            text = decode_revert(bytes.fromhex(raw[2:]))
        except ValueError:
            text = None
        if text:
            return text
    message = str(getattr(exc, "message", None) or exc)
    message = message.removeprefix("execution reverted:").removeprefix("execution reverted").strip()
    return message or "reverted without a reason"


@dataclass(frozen=True)
class Asset:
    kind: str
    token: str
    token_id: int | None
    watch: bool = False  # not planned for transfer: only checked for leaving without reaching the safe

    @property
    def label(self) -> str:
        if self.kind == "native":
            return "native currency"
        suffix = "" if self.token_id is None else f" #{self.token_id}"
        return f"{self.kind} {self.token}{suffix}"

    def probe(self, holder: str) -> Probe:
        if self.kind == "native":
            return Probe(holder, b"")  # RescueSim answers a probe without calldata with the balance
        if self.kind == "erc20":
            return Probe(self.token, _BALANCE_OF + encode(["address"], [holder]))
        if self.kind == "erc721":
            return Probe(self.token, _OWNER_OF + encode(["uint256"], [self.token_id]))
        return Probe(self.token, _BALANCE_OF_ID + encode(["address", "uint256"], [holder, self.token_id]))

    def amount(self, raw: bytes, holder: str) -> int:
        """Units `holder` owns according to a probe result. An unreadable probe counts as zero."""
        if len(raw) < 32:
            return 0
        if self.kind == "erc721":
            owner = to_checksum_address(decode(["address"], raw[:32])[0])
            return 1 if owner == holder else 0
        return decode(["uint256"], raw[:32])[0]


def plan_assets(plan: Plan) -> list[Asset]:
    """What the plan transfers, then the target of every free-form call, watched as an ERC-20: many
    pools report a position through balanceOf, and a drop there has to be matched by an arrival. A
    call names no address beyond the wallet, the safe and the planned tokens, so nothing else to watch."""
    found: list[Asset] = []
    for action in plan.actions:
        if action["type"] == "transfer_erc20":
            asset = Asset("erc20", action["token"], None)
        elif action["type"] == "transfer_nft":
            asset = Asset(action["standard"], action["token"], action["token_id"])
        elif action["type"] == "transfer_native":
            asset = Asset("native", ZERO, None)
        else:
            continue
        if asset not in found:
            found.append(asset)
    seen = {a.token for a in found if a.kind == "erc20"}
    for action in plan.actions:
        if action["type"] == "call" and action["target"] not in seen:
            seen.add(action["target"])
            found.append(Asset("erc20", action["target"], None, watch=True))
    return found


def checks_for(assets: list[Asset], gains: dict[str, int], safe: str) -> list[Check]:
    """The conditions RescueBatch enforces after the calls: each planned asset reaches the safe address
    in at least the amount in `gains`. An asset with no expected gain gets no check."""
    checks: list[Check] = []
    for asset in assets:
        gain = gains.get(asset.label, 0)
        if asset.watch or gain <= 0:
            continue
        probe = asset.probe(safe)
        if asset.kind == "erc721":
            checks.append(Check(probe.target, probe.data, int(safe, 16), 1))
        elif asset.kind == "native":
            checks.append(Check(safe, b"", gain, 2))
        else:
            checks.append(Check(probe.target, probe.data, gain, 0))
    return checks


def is_strict(plan: Plan) -> bool:
    """With a free-form call in the plan, a shortfall can be theft, not just a transfer fee."""
    return any(action["type"] == "call" for action in plan.actions)


Holdings = list[tuple[int, int]]  # per asset: (victim amount, safe amount)


def holding_probes(assets: list[Asset], victim: str, safe: str) -> list[Probe]:
    probes: list[Probe] = []
    for asset in assets:
        probes.append(asset.probe(victim))
        probes.append(asset.probe(safe))
    return probes


def holdings_from(out: SimOutput, assets: list[Asset], victim: str, safe: str) -> Holdings:
    return [
        (asset.amount(out.probe_ret[2 * i], victim), asset.amount(out.probe_ret[2 * i + 1], safe))
        for i, asset in enumerate(assets)
    ]


def evaluate(assets: list[Asset], before: Holdings, after: Holdings, *,
             strict: bool = False) -> tuple[list[BalanceDelta], list[str], bool]:
    """Judge how holdings changed. Shared by the simulation and by the check after a real transaction.

    Every asset planned for transfer must arrive at the safe address. Arriving short of what left the
    wallet is a warning in a transfer-only plan, where only the token itself can take a fee, and a
    failure when `strict`.

    A call target is watched as a token. When the wallet's balance on it drops, that is either an
    unstake, a redeem or an unwrap, whose value shows up as a planned asset reaching the safe address
    in a larger amount than the wallet held, or it is a loss. The first is reported as a warning for
    the person approving, the second fails.
    """
    balances: list[BalanceDelta] = []
    warnings: list[str] = []
    deltas_ok = True
    released = any(
        not asset.watch and s_a - s_b > v_b
        for asset, (v_b, s_b), (_, s_a) in zip(assets, before, after)
    )
    if all(asset.watch for asset in assets):
        deltas_ok = False
        warnings.append("the plan has no transfer step, so nothing can be shown to reach the safe address")
    for asset, (v_b, s_b), (v_a, s_a) in zip(assets, before, after):
        lost, gained = v_b - v_a, s_a - s_b
        if asset.watch:
            if lost > 0 and gained < lost:
                if released:
                    warnings.append(
                        f"the wallet's position on {asset.token} drops by {lost}; check that the amounts "
                        "reaching the safe address account for it"
                    )
                else:
                    deltas_ok = False
                    balances.append(
                        BalanceDelta(asset.label, asset.kind, asset.token, asset.token_id, v_b, v_a, s_b, s_a)
                    )
                    warnings.append(
                        f"{asset.label}: {lost} leaves the wallet through a call and only {max(gained, 0)} "
                        "reaches the safe address"
                    )
            continue
        balances.append(BalanceDelta(asset.label, asset.kind, asset.token, asset.token_id, v_b, v_a, s_b, s_a))
        if gained <= 0:
            deltas_ok = False
            if lost > 0:
                warnings.append(f"{asset.label}: the wallet loses {lost} and the safe address gains nothing")
            else:
                warnings.append(f"{asset.label}: nothing arrives at the safe address")
        elif gained < lost:
            deltas_ok = deltas_ok and not strict
            warnings.append(
                f"{asset.label}: the wallet loses {lost} but the safe address gains {gained} "
                "(a transfer fee or a share going elsewhere)"
            )
    return balances, warnings, deltas_ok


def _call(w3: Web3, tx: dict, block: int, overrides: dict):
    return w3.eth.call(tx, block, overrides)


def _run_sim(w3: Web3, plan: Plan, artifacts: Artifacts, calls: list[Call], probes: list[Probe],
             block: int) -> SimOutput:
    """RescueSim code at the victim's address: run `calls`, then read `probes`, in one eth_call."""
    data = artifacts.encode_simulate(calls, probes)
    try:
        raw = _call(
            w3,
            {"from": plan.operator, "to": plan.victim, "data": data},
            block,
            {plan.victim: {"code": artifacts.sim_runtime()}},
        )
    except ContractLogicError as exc:
        raise SimulationUnavailable(f"the simulation contract reverted: {_revert_text(exc)}") from None
    except Exception as exc:
        raise SimulationUnavailable(f"the RPC could not run the simulation: {strip_urls(exc)}") from None
    return artifacts.decode_simulate(raw)


def read_holdings(w3: Web3, plan: Plan, artifacts: Artifacts, assets: list[Asset], block: int) -> Holdings:
    """Victim and safe amounts of every planned asset at `block`, from a single eth_call."""
    probes = holding_probes(assets, plan.victim, plan.safe)
    return holdings_from(_run_sim(w3, plan, artifacts, [], probes, block), assets, plan.victim, plan.safe)


def simulate(w3: Web3, plan: Plan, artifacts: Artifacts, approved: dict[str, int] | None = None) -> SimResult:
    """Dry-run the plan. `approved` holds the amounts a person already agreed to, per asset label: the
    batch is then run with those as its on-chain minimums, so the result says whether the chain can
    still deliver them. Without it the minimums are the amounts this run measures."""
    victim, safe = plan.victim, plan.safe
    assets = plan_assets(plan)
    probes = holding_probes(assets, victim, safe)
    calls = list(plan.calls)

    try:
        block = w3.eth.block_number
    except Exception as exc:
        raise SimulationUnavailable(f"cannot read the chain head: {strip_urls(exc)}") from None

    before = _run_sim(w3, plan, artifacts, [], probes, block)
    detail = _run_sim(w3, plan, artifacts, calls, probes, block)

    results = [
        CallResult(ok, None if ok else (decode_revert(ret) or "reverted without a reason"))
        for ok, ret in zip(detail.ok, detail.ret)
    ]
    balances, warnings, deltas_ok = evaluate(
        assets, holdings_from(before, assets, victim, safe), holdings_from(detail, assets, victim, safe),
        strict=is_strict(plan),
    )
    measured = {b.asset: b.safe_after - b.safe_before for b in balances}
    checks = checks_for(assets, measured if approved is None else approved, safe)

    revert_reason = None
    try:
        _call(
            w3,
            {"from": plan.operator, "to": victim, "data": artifacts.encode_execute(calls, checks)},
            block,
            {victim: {"code": artifacts.batch_runtime(plan.operator)}},
        )
        real_ok = True
    except ContractLogicError as exc:
        real_ok = False
        revert_reason = _revert_text(exc)
    except Exception as exc:
        raise SimulationUnavailable(f"the RPC could not run the simulation: {strip_urls(exc)}") from None

    return SimResult(
        ok=real_ok and deltas_ok,
        revert_reason=revert_reason,
        calls=results,
        balances=balances,
        native_after=detail.native_after,
        deltas_ok=deltas_ok,
        block=block,
        warnings=warnings,
        checks=checks,
    )
