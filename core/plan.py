"""Turns rescue actions into batch calls and enforces the policy: everything goes to the safe."""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field

from eth_abi import encode
from eth_utils import function_signature_to_4byte_selector as _sel
from eth_utils import is_address, to_checksum_address

from .artifacts import Artifacts, Call
from .chains import chain_name

MAX_ACTIONS = 32
MAX_CALL_VALUES = 64
ZERO = "0x0000000000000000000000000000000000000000"

WALLET_ROLE = "the drained wallet"
SAFE_ROLE = "the safe address"
TOKEN_ROLE = "a token this plan transfers"


class PolicyError(ValueError):
    pass


# Calls that move assets: selector -> index of the recipient argument.
_MOVES = {
    _sel("transfer(address,uint256)"): 0,
    _sel("transferFrom(address,address,uint256)"): 1,
    _sel("safeTransferFrom(address,address,uint256)"): 1,
    _sel("safeTransferFrom(address,address,uint256,uint256)"): 1,
    _sel("transfer(address,uint256,uint256)"): 0,
    _sel("transferFrom(address,address,uint256,uint256)"): 1,
}

# Calls that hand another address power over the wallet's assets. None of them is needed to claim,
# withdraw or unstake, so none is allowed, whoever the argument names.
_REJECTED = {
    _sel(signature): what
    for signature, what in (
        ("approve(address,uint256)", "a token approval"),
        ("increaseAllowance(address,uint256)", "a token approval"),
        ("increaseApproval(address,uint256)", "a token approval"),
        ("approve(address,uint256,uint256)", "a token approval"),
        ("setApprovalForAll(address,bool)", "an approval for all tokens"),
        ("setOperator(address,bool)", "an operator authorization"),
        ("approve(address,address,uint160,uint48)", "a Permit2 approval"),
        ("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", "permit"),
        ("permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)", "permit"),
        ("authorizeOperator(address)", "an operator authorization"),
        ("transferAndCall(address,uint256)", "a transfer with a callback"),
    )
}

_ERC20_TRANSFER = _sel("transfer(address,uint256)")
_ERC721_SAFE = _sel("safeTransferFrom(address,address,uint256)")
_ERC1155_SAFE = _sel("safeTransferFrom(address,address,uint256,uint256,bytes)")

_LABEL_UNSAFE = re.compile(r"[^A-Za-z0-9 .,:;()#/_+-]")

# A free-form call is written as a function signature and its arguments, never as raw calldata. The
# selector comes from the signature, so the declared types are the ones the target decodes, and every
# address the call names is known. Only static types and flat arrays of them are accepted: `bytes`,
# `string` and tuples could carry an address, or a whole nested call, where no check would see it.
_SIGNATURE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]{0,63})\(([A-Za-z0-9\[\],]*)\)$")
_ARRAY = re.compile(r"^(.+?)\[(\d{0,2})\]$")
_INT = re.compile(r"^u?int(\d{1,3})$")
_FIXED_BYTES = re.compile(r"^bytes(\d{1,2})$")
_DECIMAL = re.compile(r"^-?\d{1,78}$")
_HEX = re.compile(r"^0x[0-9a-fA-F]*$")


@dataclass
class Plan:
    id: str
    chain_id: int
    victim: str
    safe: str
    operator: str
    actions: list[dict]
    calls: list[Call]
    labels: list[str]
    created_at: int
    simulation: dict | None = field(default=None)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "chain_id": self.chain_id,
            "victim": self.victim,
            "safe": self.safe,
            "operator": self.operator,
            "actions": self.actions,
            "calls": [{"to": c.to, "value": str(c.value), "data": "0x" + c.data.hex()} for c in self.calls],
            "labels": self.labels,
            "created_at": self.created_at,
            "simulation": self.simulation,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "Plan":
        return cls(
            id=doc["id"],
            chain_id=int(doc["chain_id"]),
            victim=doc["victim"],
            safe=doc["safe"],
            operator=doc["operator"],
            actions=doc["actions"],
            calls=[Call(c["to"], int(c["value"]), bytes.fromhex(c["data"][2:])) for c in doc["calls"]],
            labels=doc["labels"],
            created_at=int(doc["created_at"]),
            simulation=doc.get("simulation"),
        )


def _addr(value, what: str) -> str:
    if not isinstance(value, str) or not is_address(value):
        raise PolicyError(f"{what} is not a valid address: {value!r}")
    return to_checksum_address(value)


def _amount(value, where: str) -> int | str:
    if value == "all":
        return "all"
    try:
        amount = int(value)
    except (TypeError, ValueError):
        raise PolicyError(f"{where}: amount must be 'all' or a whole number in base units") from None
    if amount <= 0:
        raise PolicyError(f"{where}: amount must be positive")
    return amount


def _whole(value, where: str, name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise PolicyError(f"{where}: {name} must be a whole number") from None
    if number < 0:
        raise PolicyError(f"{where}: {name} must not be negative")
    return number


def _clean_label(value) -> str:
    """Labels end up in the approval message, so they cannot carry newlines or look like fields."""
    text = _LABEL_UNSAFE.sub(" ", str(value or ""))
    return " ".join(text.split())[:60]


def _elementary(kind: str, where: str) -> None:
    match = _INT.match(kind)
    if match and int(match[1]) % 8 == 0 and 8 <= int(match[1]) <= 256:
        return
    match = _FIXED_BYTES.match(kind)
    if match and 1 <= int(match[1]) <= 32:
        return
    if kind in ("address", "bool"):
        return
    raise PolicyError(
        f"{where}: argument type {kind!r} is not supported; a call takes address, bool, uintN, intN, "
        "bytesN and flat arrays of them"
    )


def _parse_signature(value, where: str) -> list[str]:
    match = _SIGNATURE.match(value) if isinstance(value, str) else None
    if not match:
        raise PolicyError(f"{where}: signature must look like withdraw(uint256,address), with full type names")
    types = match[2].split(",") if match[2] else []
    for kind in types:
        array = _ARRAY.match(kind)
        _elementary(array[1] if array else kind, where)
    return types


def _coerce(kind: str, value, where: str):
    """One argument value in the form eth_abi takes. Addresses come back checksummed."""
    if kind == "address":
        return _addr(value, f"{where}: address argument")
    if kind == "bool":
        if isinstance(value, bool):
            return value
        raise PolicyError(f"{where}: a bool argument must be true or false")
    if kind.startswith("bytes"):
        size = int(kind[5:])
        if isinstance(value, str) and _HEX.match(value) and len(value) == 2 + 2 * size:
            return bytes.fromhex(value[2:])
        raise PolicyError(f"{where}: a {kind} argument must be 0x-prefixed hex of {size} bytes")
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not _DECIMAL.match(str(value)):
        raise PolicyError(f"{where}: a {kind} argument must be a whole number in base units")
    return int(value)


def _plain(value):
    """The JSON form kept on the plan: numbers as strings, bytes as hex."""
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, (bool, str)):
        return value
    return str(value)


def _encode_call(signature, args, where: str) -> tuple[bytes, list[str], list, list]:
    """(calldata, types, values, JSON form of the values) for a call action."""
    types = _parse_signature(signature, where)
    if not isinstance(args, list) or len(args) != len(types):
        raise PolicyError(f"{where}: {signature} takes {len(types)} arguments, given as a list in args")
    values: list = []
    count = 0
    for kind, value in zip(types, args):
        array = _ARRAY.match(kind)
        if array:
            if not isinstance(value, list) or (array[2] and len(value) != int(array[2])):
                raise PolicyError(f"{where}: a {kind} argument must be a list of the right length")
            values.append([_coerce(array[1], item, where) for item in value])
            count += len(value)
        else:
            values.append(_coerce(kind, value, where))
            count += 1
    if count > MAX_CALL_VALUES:
        raise PolicyError(f"{where}: a call carries at most {MAX_CALL_VALUES} values")
    try:
        data = _sel(signature) + encode(types, values)
    except Exception:
        raise PolicyError(f"{where}: an argument does not fit its type in {signature}") from None
    plain = [[_plain(item) for item in v] if isinstance(v, list) else _plain(v) for v in values]
    return data, types, values, plain


def _named_addresses(types: list[str], values: list) -> list[str]:
    found: list[str] = []
    for kind, value in zip(types, values):
        if kind == "address":
            found.append(value)
        elif kind.startswith("address["):
            found.extend(value)
    return found


def _check_call(data: bytes, types: list[str], values: list, where: str, roles: dict[str, str]) -> None:
    """`roles` maps every address a call may name to what it is: the wallet, the safe, a planned token."""
    selector = data[:4]
    if selector in _REJECTED:
        raise PolicyError(f"{where}: {_REJECTED[selector]} is not allowed in a rescue batch")
    if selector in _MOVES:
        recipient = values[_MOVES[selector]]
        if roles.get(recipient) != SAFE_ROLE:
            raise PolicyError(f"{where}: sends assets to {recipient}, not to the safe address")
    for address in _named_addresses(types, values):
        if address not in roles:
            raise PolicyError(
                f"{where}: names {address}, which is not the drained wallet, the safe address or a token "
                "this plan transfers; a call cannot name any other address"
            )


def _show(value, roles: dict[str, str]) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(_show(item, roles) for item in value) + "]"
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return f"{value} ({roles[value]})"
    return str(value)


def _call_label(target: str, signature: str, values: list, label: str, roles: dict[str, str]) -> str:
    """The approval line for a free-form call. It starts with a fixed word and shows the function and
    every argument in full, so the description the agent wrote cannot pass for one of the built-in steps."""
    shown = ", ".join(_show(value, roles) for value in values) or "no arguments"
    return f'CALL to {target}: {signature} with {shown}; the agent describes it as "{label}"'


def _roles(victim: str, safe: str, actions: list) -> dict[str, str]:
    """Every address a call in this plan may name. The safe and the wallet win over a token entry."""
    roles: dict[str, str] = {}
    for action in actions:
        if isinstance(action, dict) and action.get("type") in ("transfer_erc20", "transfer_nft"):
            token = action.get("token")
            if isinstance(token, str) and is_address(token):
                roles[to_checksum_address(token)] = TOKEN_ROLE
    roles[victim] = WALLET_ROLE
    roles[safe] = SAFE_ROLE
    return roles


def build_plan(chain_id: int, victim: str, safe: str, operator: str, actions: list[dict],
               *, now: int | None = None) -> Plan:
    victim = _addr(victim, "victim")
    safe = _addr(safe, "safe address")
    operator = _addr(operator, "operator")
    if safe == ZERO:
        raise PolicyError("the safe address is the zero address")
    if safe == victim:
        raise PolicyError("the safe address is the drained wallet itself; set a wallet the leaked key does not control")
    if safe == operator:
        raise PolicyError("the safe address must not be the operator")
    if operator == victim:
        raise PolicyError("the operator must not be the drained wallet")
    if not isinstance(actions, list) or not actions:
        raise PolicyError("a plan needs at least one action")
    if len(actions) > MAX_ACTIONS:
        raise PolicyError(f"a plan holds at most {MAX_ACTIONS} actions")

    roles = _roles(victim, safe, actions)
    normalized: list[dict] = []
    calls: list[Call] = []
    labels: list[str] = []
    for i, action in enumerate(actions):
        where = f"action {i + 1}"
        if not isinstance(action, dict):
            raise PolicyError(f"{where}: must be an object")
        kind = action.get("type")
        if kind == "transfer_erc20":
            token = _addr(action.get("token"), f"{where}: token")
            amount = _amount(action.get("amount"), where)
            if amount == "all":
                calls.append(Call(victim, 0, Artifacts.sweep_erc20_data(token, safe)))
                labels.append(f"send all of token {token} to the safe")
            else:
                calls.append(Call(token, 0, _ERC20_TRANSFER + encode(["address", "uint256"], [safe, amount])))
                labels.append(f"send {amount} base units of token {token} to the safe")
            normalized.append({"type": kind, "token": token, "amount": amount})
        elif kind == "transfer_nft":
            token = _addr(action.get("token"), f"{where}: token")
            token_id = _whole(action.get("token_id"), where, "token_id")
            standard = action.get("standard")
            if standard == "erc721":
                data = _ERC721_SAFE + encode(["address", "address", "uint256"], [victim, safe, token_id])
                labels.append(f"send ERC-721 {token} #{token_id} to the safe")
                normalized.append({"type": kind, "standard": standard, "token": token, "token_id": token_id})
            elif standard == "erc1155":
                amount = _amount(action.get("amount", 1), where)
                if amount == "all":
                    raise PolicyError(f"{where}: ERC-1155 needs an exact amount")
                data = _ERC1155_SAFE + encode(
                    ["address", "address", "uint256", "uint256", "bytes"], [victim, safe, token_id, amount, b""]
                )
                labels.append(f"send {amount} of ERC-1155 {token} #{token_id} to the safe")
                normalized.append({"type": kind, "standard": standard, "token": token, "token_id": token_id,
                                   "amount": amount})
            else:
                raise PolicyError(f"{where}: standard must be erc721 or erc1155")
            calls.append(Call(token, 0, data))
        elif kind == "transfer_native":
            amount = _amount(action.get("amount"), where)
            if amount == "all":
                calls.append(Call(victim, 0, Artifacts.sweep_native_data(safe)))
                labels.append("send the whole native balance to the safe")
            else:
                calls.append(Call(safe, amount, b""))
                labels.append(f"send {amount} wei to the safe")
            normalized.append({"type": kind, "amount": amount})
        elif kind == "call":
            target = _addr(action.get("target"), f"{where}: target")
            if target in (victim, safe, operator):
                raise PolicyError(f"{where}: a call cannot target the drained wallet, the safe address or the operator")
            if "data" in action:
                raise PolicyError(f"{where}: raw calldata is not accepted; give signature and args")
            if int(action.get("value") or 0) != 0:
                raise PolicyError(f"{where}: a call cannot carry value; use transfer_native")
            signature = action.get("signature")
            data, types, values, plain = _encode_call(signature, action.get("args", []), where)
            _check_call(data, types, values, where, roles)
            label = _clean_label(action.get("label")) or "call"
            calls.append(Call(target, 0, data))
            labels.append(_call_label(target, signature, values, label, roles))
            normalized.append({"type": kind, "target": target, "signature": signature, "args": plain,
                               "label": label})
        else:
            raise PolicyError(
                f"{where}: unknown type {kind!r}; use transfer_erc20, transfer_nft, transfer_native or call"
            )

    # Without a transfer step nothing shows that a claim or a withdrawal reached the safe address.
    if not any(action["type"] != "call" for action in normalized):
        raise PolicyError(
            "a plan needs at least one transfer step: a call alone leaves no asset whose arrival at the "
            "safe address can be checked"
        )

    return Plan(
        id="p-" + secrets.token_hex(5),
        chain_id=int(chain_id),
        victim=victim,
        safe=safe,
        operator=operator,
        actions=normalized,
        calls=calls,
        labels=labels,
        created_at=int(now if now is not None else time.time()),
    )


def summarize(plan: Plan) -> str:
    lines = [
        f"lifeboat plan {plan.id} on {chain_name(plan.chain_id)} (chain {plan.chain_id})",
        f"  victim    {plan.victim}  (drained wallet, never receives gas)",
        f"  operator  {plan.operator}  (fresh wallet, pays the gas)",
        f"  safe      {plan.safe}  (receives everything)",
        "calls, in one transaction, all or nothing:",
    ]
    lines += [f"  {n}. {label}" for n, label in enumerate(plan.labels, 1)]
    sim = plan.simulation
    if not sim:
        lines.append("simulation: not run yet")
    elif sim.get("ok"):
        lines.append(f"simulation: passed at block {sim.get('block')}")
    else:
        lines.append(f"simulation: FAILED: {sim.get('revert_reason') or 'see details'}")
    for warning in (sim or {}).get("warnings", []):
        lines.append(f"  warning: {warning}")
    return "\n".join(lines)
