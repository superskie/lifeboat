"""Compile the rescue contracts and write the artifact the plugin ships.

Usage: python scripts/build_artifacts.py

The artifact is plain JSON text so reviewers and the install scanner can read it, and
tests/test_artifacts.py rebuilds it from source to prove it matches.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "contracts"
SHIPPED_PATH = CONTRACTS / "artifacts.json"
SHIPPED = ("RescueBatch", "RescueSim")


def build(out_dir: Path) -> str:
    """Compile into out_dir and return the artifact text."""
    subprocess.run(
        ["forge", "build", "--force", "--out", str(out_dir)],
        cwd=CONTRACTS,
        check=True,
        capture_output=True,
    )
    profile = tomllib.loads((CONTRACTS / "foundry.toml").read_text(encoding="utf-8"))["profile"]["default"]
    contracts = {}
    for name in SHIPPED:
        raw = json.loads((out_dir / f"{name}.sol" / f"{name}.json").read_text(encoding="utf-8"))
        contracts[name] = {
            "abi": raw["abi"],
            "bytecode": raw["bytecode"]["object"],
            "deployedBytecode": raw["deployedBytecode"]["object"],
            "immutableReferences": raw["deployedBytecode"].get("immutableReferences", {}),
        }
    doc = {
        "compiler": {
            "solc": profile["solc_version"],
            "evm_version": profile["evm_version"],
            "optimizer_runs": profile["optimizer_runs"],
            "bytecode_hash": profile["bytecode_hash"],
            "cbor_metadata": profile["cbor_metadata"],
        },
        "contracts": contracts,
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        text = build(Path(tmp))
    SHIPPED_PATH.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {SHIPPED_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
