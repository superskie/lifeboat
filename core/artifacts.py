"""The shipped contract artifact: bytecode for RescueBatch and RescueSim, and their encoders."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from eth_abi import decode, encode
from eth_utils import function_signature_to_4byte_selector, to_checksum_address

ARTIFACT_PATH = Path(__file__).resolve().parent.parent / "contracts" / "artifacts.json"

_CALL = "(address,uint256,bytes)"
_PROBE = "(address,bytes)"
_CHECK = "(address,bytes,uint256,uint8)"
EXECUTE_SELECTOR = function_signature_to_4byte_selector(f"execute({_CALL}[],{_CHECK}[])")
SIMULATE_SELECTOR = function_signature_to_4byte_selector(f"simulate({_CALL}[],{_PROBE}[])")
SWEEP_ERC20_SELECTOR = function_signature_to_4byte_selector("sweepERC20(address,address)")
SWEEP_NATIVE_SELECTOR = function_signature_to_4byte_selector("sweepNative(address)")


@dataclass(frozen=True)
class Call:
    to: str
    value: int
    data: bytes


@dataclass(frozen=True)
class Probe:
    target: str
    data: bytes


@dataclass(frozen=True)
class Check:
    """A condition RescueBatch enforces after the calls. Kinds: 0 the number read from `target` grows
    by at least `min`, 1 the word read equals `min`, 2 the native balance of `target` grows by `min`."""

    target: str
    data: bytes
    min: int
    kind: int


@dataclass(frozen=True)
class SimOutput:
    ok: tuple[bool, ...]
    ret: tuple[bytes, ...]
    probe_ret: tuple[bytes, ...]
    native_after: int


def _hex_bytes(value: str) -> bytes:
    return bytes.fromhex(value[2:] if value.startswith("0x") else value)


def _calls_arg(calls: list[Call]) -> list[tuple]:
    return [(to_checksum_address(c.to), int(c.value), bytes(c.data)) for c in calls]


class Artifacts:
    def __init__(self, doc: dict):
        self.compiler = doc["compiler"]
        batch = doc["contracts"]["RescueBatch"]
        sim = doc["contracts"]["RescueSim"]
        self.batch_abi = batch["abi"]
        self._batch_init = _hex_bytes(batch["bytecode"])
        self._batch_runtime = _hex_bytes(batch["deployedBytecode"])
        self._batch_immutables = [
            (ref["start"], ref["length"]) for refs in batch["immutableReferences"].values() for ref in refs
        ]
        self._sim_runtime = _hex_bytes(sim["deployedBytecode"])
        if sim["immutableReferences"]:
            raise ValueError("RescueSim must not have immutables")
        if len(self._batch_immutables) == 0:
            raise ValueError("RescueBatch artifact is missing the operator immutable")

    def batch_initcode(self, operator: str) -> bytes:
        return self._batch_init + encode(["address"], [to_checksum_address(operator)])

    def batch_runtime(self, operator: str) -> bytes:
        """Runtime code exactly as a deployment by `operator` would leave it on chain."""
        code = bytearray(self._batch_runtime)
        word = encode(["address"], [to_checksum_address(operator)])
        for start, length in self._batch_immutables:
            if length != 32:
                raise ValueError("unexpected immutable size")
            code[start : start + 32] = word
        return bytes(code)

    def sim_runtime(self) -> bytes:
        return self._sim_runtime

    @staticmethod
    def encode_execute(calls: list[Call], checks: list[Check]) -> bytes:
        check_arg = [(to_checksum_address(c.target), bytes(c.data), int(c.min), int(c.kind)) for c in checks]
        return EXECUTE_SELECTOR + encode([f"{_CALL}[]", f"{_CHECK}[]"], [_calls_arg(calls), check_arg])

    @staticmethod
    def encode_simulate(calls: list[Call], probes: list[Probe]) -> bytes:
        probe_arg = [(to_checksum_address(p.target), bytes(p.data)) for p in probes]
        return SIMULATE_SELECTOR + encode([f"{_CALL}[]", f"{_PROBE}[]"], [_calls_arg(calls), probe_arg])

    @staticmethod
    def decode_simulate(data: bytes) -> SimOutput:
        ok, ret, probe_ret, native_after = decode(["bool[]", "bytes[]", "bytes[]", "uint256"], bytes(data))
        return SimOutput(tuple(ok), tuple(ret), tuple(probe_ret), native_after)

    @staticmethod
    def sweep_erc20_data(token: str, to: str) -> bytes:
        return SWEEP_ERC20_SELECTOR + encode(["address", "address"], [to_checksum_address(token), to_checksum_address(to)])

    @staticmethod
    def sweep_native_data(to: str) -> bytes:
        return SWEEP_NATIVE_SELECTOR + encode(["address"], [to_checksum_address(to)])


@lru_cache(maxsize=1)
def load() -> Artifacts:
    return Artifacts(json.loads(ARTIFACT_PATH.read_text(encoding="utf-8")))
