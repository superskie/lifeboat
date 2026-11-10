"""Sends the rescue: deploys the batch if needed, signs the EIP-7702 authorization, checks what landed.

The operator pays for everything. The victim key signs one authorization and nothing else, and the
victim address never holds or receives gas. Verification reads the chain after the receipt, because a
type 4 transaction whose authorization went stale still succeeds on chain while doing nothing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from eth_abi import decode, encode
from eth_utils import function_signature_to_4byte_selector as _sel
from eth_utils import is_address, keccak, to_checksum_address
from web3 import Web3
from web3.exceptions import Web3RPCError

from .artifacts import Artifacts
from .artifacts import load as load_artifacts
from .chains import CHAINS
from .keys import Signer
from .plan import ZERO, Plan, PolicyError
from .scrub import strip_urls
from .simulate import BalanceDelta, SimResult, evaluate, is_strict, plan_assets, read_holdings, simulate
from .store import Store

DELEGATION_PREFIX = bytes.fromhex("ef0100")
OP_GAS_PRICE_ORACLE = "0x420000000000000000000000000000000000000F"
_GET_L1_FEE = _sel("getL1Fee(bytes)")
TRANSFER_GAS = 21_000
MAX_AUTHORIZATIONS = 4


class ExecuteRefused(RuntimeError):
    """A check failed before anything was sent."""


class SimulationFailed(ExecuteRefused):
    def __init__(self, result: SimResult) -> None:
        reason = result.revert_reason or "; ".join(result.warnings) or "see the simulation details"
        super().__init__(f"the simulation did not pass: {reason}")
        self.result = result


class InsufficientOperatorFunds(ExecuteRefused):
    def __init__(self, operator: str, have: int, need: int) -> None:
        super().__init__(
            f"the operator wallet {operator} holds {have} wei and needs about {need} wei for this transaction"
        )
        self.have = have
        self.need = need


class NotConfirmed(RuntimeError):
    """The transaction was handed to the node and its outcome is unknown. `tx_hash` says which one to
    look up before anything is tried again."""

    def __init__(self, tx_hash: str, why: str) -> None:
        super().__init__(
            f"transaction {tx_hash} was sent but its result is unknown ({why}); "
            "look it up on the explorer before trying again"
        )
        self.tx_hash = tx_hash


@dataclass
class Receipt:
    ok: bool
    plan_id: str
    chain_id: int
    tx_hash: str
    block: int
    status: int
    batch: str
    delegated: bool
    gas_used: int
    gas_paid_wei: int
    balances: list[BalanceDelta]
    native: dict
    problems: list[str]
    warnings: list[str]
    link: str
    created_at: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "plan_id": self.plan_id,
            "chain_id": self.chain_id,
            "tx_hash": self.tx_hash,
            "block": self.block,
            "status": self.status,
            "batch": self.batch,
            "delegated": self.delegated,
            "gas_used": str(self.gas_used),
            "gas_paid_wei": str(self.gas_paid_wei),
            "balances": [b.to_dict() for b in self.balances],
            "native": {k: str(v) for k, v in self.native.items()},
            "problems": list(self.problems),
            "warnings": list(self.warnings),
            "link": self.link,
            "created_at": self.created_at,
        }


def _hex_hash(value) -> str:
    return "0x" + bytes(value).hex()


def _fee_parts(w3: Web3, priority_gwei: float | None) -> tuple[int, int]:
    """(base fee, priority fee) in wei. Without an explicit tip, the node's own suggestion is used."""
    base = int(w3.eth.get_block("latest")["baseFeePerGas"])
    if priority_gwei is None:
        try:
            tip = int(w3.eth.max_priority_fee)
        except Exception:
            tip = 10**9
    else:
        tip = int(priority_gwei * 10**9)
    return base, max(tip, 1)


def l1_data_fee(w3: Web3, raw_tx: bytes) -> int:
    """OP Stack chains charge a data fee for posting the transaction to Ethereum and take it from the
    sender's balance on top of gas. Chains without that oracle answer with nothing, which reads as 0."""
    try:
        data = _GET_L1_FEE + encode(["bytes"], [bytes(raw_tx)])
        out = w3.eth.call({"to": OP_GAS_PRICE_ORACLE, "data": "0x" + data.hex()})
        return decode(["uint256"], bytes(out))[0]
    except Exception:
        return 0


def _require_funds(w3: Web3, operator: Signer, gas: int, max_fee: int, raw_tx: bytes,
                   max_cost_wei: int | None = None) -> None:
    need = gas * max_fee + l1_data_fee(w3, raw_tx) * 3 // 2
    if max_cost_wei is not None and need > max_cost_wei:
        raise ExecuteRefused(
            f"this transaction could cost {need} wei, more than the {max_cost_wei} wei that was approved; "
            "simulate again to get a current figure"
        )
    have = w3.eth.get_balance(operator.address)
    if have < need:
        raise InsufficientOperatorFunds(operator.address, have, need)


_MAYBE_SENT = ("already known", "nonce too low", "already imported", "replacement")


def _known_to_node(w3: Web3, tx_hash: str) -> bool:
    try:
        return w3.eth.get_transaction(tx_hash) is not None
    except Exception:
        return False


def _send_and_wait(w3: Web3, raw: bytes, timeout: float) -> tuple[str, dict]:
    """Only an explicit answer from the node counts as "not sent". Anything else that goes wrong after
    the bytes left (a dropped connection, a timeout) leaves the outcome unknown, and the hash, computed
    here and not taken from the reply, is what the caller needs to find out."""
    tx_hash = "0x" + keccak(bytes(raw)).hex()
    try:
        w3.eth.send_raw_transaction(raw)
    except Web3RPCError as exc:
        # A gateway can accept the bytes on one backend and still answer with an error, so the error
        # alone does not prove that nothing was sent. The node is asked whether it knows the hash.
        reason = strip_urls(exc)
        if not _known_to_node(w3, tx_hash):
            if any(hint in reason.lower() for hint in _MAYBE_SENT):
                raise NotConfirmed(tx_hash, f"the node answered: {reason[:120]}") from None
            raise ExecuteRefused(f"the node rejected the transaction {tx_hash}: {reason}") from None
    except Exception as exc:
        raise NotConfirmed(tx_hash, f"the connection failed while sending: {type(exc).__name__}") from None
    try:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout, poll_latency=0.5)
    except Exception as exc:
        raise NotConfirmed(tx_hash, f"no receipt: {type(exc).__name__}") from None
    return tx_hash, receipt


def _batch_key(chain_id: int, operator: str) -> str:
    return f"batch-{chain_id}-{operator[2:].lower()}"


def ensure_batch(w3: Web3, operator: Signer, store: Store, artifacts: Artifacts | None = None, *,
                 priority_gwei: float | None = None, timeout: float = 180.0,
                 max_cost_wei: int | None = None) -> str:
    """The RescueBatch address for this operator on this chain, deployed first if it is not there.

    A stored address counts only if the code at it is exactly the shipped runtime for this operator.
    """
    artifacts = artifacts or load_artifacts()
    chain_id = w3.eth.chain_id
    key = _batch_key(chain_id, operator.address)
    runtime = artifacts.batch_runtime(operator.address)
    saved = store.load_meta(key).get("address")
    if saved and bytes(w3.eth.get_code(saved)) == runtime:
        return saved

    initcode = artifacts.batch_initcode(operator.address)
    try:
        estimate = w3.eth.estimate_gas({"from": operator.address, "data": "0x" + initcode.hex()})
    except Exception as exc:
        raise ExecuteRefused(f"cannot estimate the batch deployment: {strip_urls(exc)}") from None
    gas = estimate * 13 // 10
    base, tip = _fee_parts(w3, priority_gwei)
    max_fee = base * 2 + tip
    tx = {
        "type": 2, "chainId": chain_id, "nonce": w3.eth.get_transaction_count(operator.address, "pending"),
        "value": 0, "data": initcode, "gas": gas, "maxFeePerGas": max_fee, "maxPriorityFeePerGas": tip,
    }
    raw = operator.sign_transaction(tx)
    _require_funds(w3, operator, gas, max_fee, raw, max_cost_wei)
    tx_hash, receipt = _send_and_wait(w3, raw, timeout)
    if receipt["status"] != 1 or not receipt.get("contractAddress"):
        raise ExecuteRefused(f"the batch deployment failed (transaction {tx_hash})")
    address = to_checksum_address(receipt["contractAddress"])
    if bytes(w3.eth.get_code(address, int(receipt["blockNumber"]))) != runtime:
        raise ExecuteRefused("the deployed batch code does not match the shipped artifact")
    store.save_meta(key, {
        "address": address, "operator": operator.address, "chain_id": chain_id,
        "deploy_tx": tx_hash, "created_at": int(time.time()),
    })
    return address


def _auth_json(auth) -> dict:
    return {
        "chainId": hex(auth.chain_id), "address": to_checksum_address(auth.address), "nonce": hex(auth.nonce),
        "yParity": hex(auth.y_parity), "r": hex(auth.r), "s": hex(auth.s),
    }


def _estimate_type4_gas(w3: Web3, sender: str, to: str, calldata: bytes, auths: list) -> int:
    params = {
        "from": sender, "to": to, "data": "0x" + calldata.hex(), "value": "0x0",
        "authorizationList": [_auth_json(auth) for auth in auths],
    }
    reply = w3.provider.make_request("eth_estimateGas", [params])
    if "error" in reply:
        message = reply["error"].get("message") if isinstance(reply["error"], dict) else reply["error"]
        raise ExecuteRefused(f"gas estimation failed: {strip_urls(message)}")
    return int(reply["result"], 16) * 13 // 10


def _explorer_link(chain_id: int, tx_hash: str) -> str:
    chain = CHAINS.get(chain_id)
    return chain.tx_link(tx_hash) if chain else tx_hash


def _fee_from_receipt(receipt: dict) -> int:
    """Fallback when balances cannot be compared: execution fee plus the OP Stack data fee if reported."""
    extra = receipt.get("l1Fee") or 0
    extra = int(extra, 16) if isinstance(extra, str) else int(extra)
    return int(receipt["gasUsed"]) * int(receipt.get("effectiveGasPrice") or 0) + extra


def execute(w3: Web3, plan: Plan, victim: Signer, operator: Signer, artifacts: Artifacts, store: Store, *,
            priority_gwei: float | None = None, timeout: float = 180.0,
            max_cost_wei: int | None = None, approved: dict[str, int] | None = None) -> Receipt:
    """Run the plan in one type 4 transaction paid by the operator, then report what actually landed.

    `approved` holds what a person agreed to: the amount each asset adds to the safe address. The
    batch carries those amounts as on-chain minimums and reverts as a whole when the safe address
    would get less, so a call target that behaves in a dry run and steals in the real transaction
    gains nothing. Without `approved` the minimums come from the simulation made here. No transaction
    may cost more than `max_cost_wei`.

    Raises ExecuteRefused (nothing was sent) or NotConfirmed (sent, outcome unknown). Once a receipt
    exists the result is always a Receipt: `ok` is False and `problems` says why when the chain does
    not show the rescue, even though the operator has paid for the transaction.
    """
    chain_id = w3.eth.chain_id
    if chain_id != plan.chain_id:
        raise ExecuteRefused(f"the plan is for chain {plan.chain_id} but the RPC answers as chain {chain_id}")
    if victim.address != plan.victim:
        raise ExecuteRefused("the configured victim key does not belong to the wallet in this plan")
    if operator.address != plan.operator:
        raise ExecuteRefused("this plan was made for a different operator wallet")

    sim = simulate(w3, plan, artifacts, approved)
    plan.simulation = sim.to_dict()
    store.save_plan(plan)
    fresh = sim.gains()
    for asset, amount in (approved or {}).items():
        if fresh.get(asset, 0) < amount:
            raise ExecuteRefused(
                f"{asset}: the safe address would now receive {fresh.get(asset, 0)}, less than the "
                f"{amount} that was approved; simulate again and review the plan"
            )
    if not sim.ok:
        raise SimulationFailed(sim)

    batch = ensure_batch(w3, operator, store, artifacts, priority_gwei=priority_gwei, timeout=timeout,
                         max_cost_wei=max_cost_wei)
    assets = plan_assets(plan)
    head = w3.eth.block_number
    holdings_before = read_holdings(w3, plan, artifacts, assets, head)
    native_before = (w3.eth.get_balance(plan.victim, head), w3.eth.get_balance(plan.safe, head))

    # The sender is the operator, so the authorization carries the victim's current nonce, not nonce + 1.
    # A victim transaction waiting in the pool may land before or after the rescue, and whoever holds
    # the leaked key decides which. One authorization per possible nonce covers both: the chain applies
    # the one that matches and skips the rest.
    mined = w3.eth.get_transaction_count(victim.address, "latest")
    pending = w3.eth.get_transaction_count(victim.address, "pending")
    nonces = range(mined, min(max(pending, mined), mined + MAX_AUTHORIZATIONS - 1) + 1)
    auths = [victim.sign_authorization(chain_id, batch, nonce) for nonce in nonces]
    calldata = artifacts.encode_execute(plan.calls, sim.checks)
    gas = _estimate_type4_gas(w3, operator.address, plan.victim, calldata, auths)
    base, tip = _fee_parts(w3, priority_gwei)
    max_fee = base * 2 + tip
    tx = {
        "type": 4, "chainId": chain_id, "nonce": w3.eth.get_transaction_count(operator.address, "pending"),
        "to": plan.victim, "value": 0, "data": calldata, "gas": gas,
        "maxFeePerGas": max_fee, "maxPriorityFeePerGas": tip, "authorizationList": auths,
    }
    raw = operator.sign_transaction(tx)
    _require_funds(w3, operator, gas, max_fee, raw, max_cost_wei)
    operator_before = w3.eth.get_balance(operator.address)
    tx_hash, receipt = _send_and_wait(w3, raw, timeout)

    block = int(receipt["blockNumber"])
    status = int(receipt["status"])
    problems: list[str] = []
    warnings: list[str] = []
    balances: list[BalanceDelta] = []
    native: dict = {"victim_before": native_before[0], "safe_before": native_before[1]}
    delegated = False
    paid = 0
    if status != 1:
        problems.append(
            "the transaction reverted on chain, so no asset moved; the authorization may still have been "
            "applied, which leaves the wallet delegated to the rescue contract"
        )
    try:
        delegated = bytes(w3.eth.get_code(plan.victim, block)) == DELEGATION_PREFIX + bytes.fromhex(batch[2:])
        balances, warnings, deltas_ok = evaluate(
            assets, holdings_before, read_holdings(w3, plan, artifacts, assets, block), strict=is_strict(plan)
        )
        native["victim_after"] = w3.eth.get_balance(plan.victim, block)
        native["safe_after"] = w3.eth.get_balance(plan.safe, block)
        paid = operator_before - w3.eth.get_balance(operator.address, block)
        if not deltas_ok:
            problems.extend(warnings)
            warnings = []
        else:
            landed = {b.asset: b.safe_after - b.safe_before for b in balances}
            for expected in sim.balances:
                want = expected.safe_after - expected.safe_before
                if landed.get(expected.asset, 0) < want:
                    problems.append(
                        f"{expected.asset}: the simulation expected {want} at the safe address, "
                        f"{landed.get(expected.asset, 0)} arrived"
                    )
        if status == 1 and not delegated:
            # Every plan has a transfer step and `evaluate` fails any that did not reach the safe
            # address, so an empty `problems` means the batch ran.
            if problems:
                problems.insert(0, (
                    "the wallet is not delegated to the rescue contract afterwards, so the authorization "
                    "was not applied (its nonce most likely moved after it was signed)"
                ))
            else:
                # Every planned asset arrived, so the batch did run: the delegation was changed later.
                warnings.append("the delegation of the wallet was changed again right after the rescue")
        wants_all_native = any(a["type"] == "transfer_native" and a["amount"] == "all" for a in plan.actions)
        if status == 1 and not problems and wants_all_native and native["victim_after"] != 0:
            warnings.append(f"the wallet holds {native['victim_after']} wei that arrived after the rescue ran")
    except Exception as exc:
        problems.append(f"the chain could not be read to verify the result: {strip_urls(exc)}")
    if paid <= 0:
        paid = _fee_from_receipt(receipt)

    result = Receipt(
        ok=not problems, plan_id=plan.id, chain_id=chain_id, tx_hash=tx_hash, block=block, status=status,
        batch=batch, delegated=delegated, gas_used=int(receipt["gasUsed"]), gas_paid_wei=paid,
        balances=balances, native=native, problems=problems, warnings=warnings,
        link=_explorer_link(chain_id, tx_hash),
    )
    store.save_receipt(f"{plan.id}-{tx_hash[2:10]}", result.to_dict())
    return result


def sweep_back(w3: Web3, operator: Signer, safe: str, *, priority_gwei: float | None = None,
               timeout: float = 180.0) -> str | None:
    """Send what is left on the operator to the safe address. Returns the transaction hash, or None when
    the leftover is worth less than the transfer costs. The only recipient this ever accepts is `safe`,
    which callers take from configuration, and it cannot be the zero address or the operator itself."""
    if not isinstance(safe, str) or not is_address(safe):
        raise PolicyError("the sweep-back target is not a valid address")
    safe = to_checksum_address(safe)
    if safe == ZERO or safe == operator.address:
        raise PolicyError("the sweep-back target must be the configured safe address")

    chain_id = w3.eth.chain_id
    balance = w3.eth.get_balance(operator.address)
    base, tip = _fee_parts(w3, priority_gwei)
    max_fee = base * 5 // 4 + tip  # little headroom, so little is left unspent behind the transfer
    nonce = w3.eth.get_transaction_count(operator.address, "pending")

    # A plain transfer leaves a contract wallet no gas to run its receive code, so that case is measured.
    gas = TRANSFER_GAS
    if bytes(w3.eth.get_code(safe)):
        try:
            gas = w3.eth.estimate_gas({"from": operator.address, "to": safe, "value": 1}) * 6 // 5
        except Exception as exc:
            raise ExecuteRefused(f"the safe address would not accept a transfer: {strip_urls(exc)}") from None

    def transfer(value: int) -> dict:
        return {
            "type": 2, "chainId": chain_id, "nonce": nonce, "to": safe, "value": value, "gas": gas,
            "maxFeePerGas": max_fee, "maxPriorityFeePerGas": tip,
        }

    l1_fee = l1_data_fee(w3, operator.sign_transaction(transfer(balance)))
    cost = gas * max_fee + l1_fee
    value = balance - (cost + l1_fee)  # the data fee is quoted once and can move, so keep a second one back
    if value <= cost:
        return None  # sending would cost more than it recovers
    tx_hash, receipt = _send_and_wait(w3, operator.sign_transaction(transfer(value)), timeout)
    if int(receipt["status"]) != 1:
        raise ExecuteRefused(f"the sweep-back transaction failed (transaction {tx_hash})")
    return tx_hash
