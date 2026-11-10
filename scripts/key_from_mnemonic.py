"""Turn a recovery phrase into the LIFEBOAT_VICTIM_KEY line of an env file, without showing either.

Usage: python scripts/key_from_mnemonic.py <path to the Hermes .env> [--index N]

Run it yourself, in your own terminal. The phrase is typed at a hidden prompt, the key is written
straight into the env file, and the only thing printed is the address, so you can check that it is
the drained wallet. Nothing is sent anywhere. `--index` picks another account of the same phrase
(0 is the first one a wallet app shows).
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from eth_account import Account

NAME = "LIFEBOAT_VICTIM_KEY"


def derive(phrase: str, index: int = 0):
    """The account a wallet app shows at position `index` for this phrase (path m/44'/60'/0'/0/index)."""
    Account.enable_unaudited_hdwallet_features()
    return Account.from_mnemonic(" ".join(phrase.split()), account_path=f"m/44'/60'/0'/0/{index}")


def write_key(path: Path, key: str) -> None:
    """Set the one line for NAME, replacing an earlier one and leaving every other line alone."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    lines = [line for line in lines if not line.startswith(f"{NAME}=")]
    lines.append(f"{NAME}={key}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("env_file", type=Path)
    parser.add_argument("--index", type=int, default=0)
    args = parser.parse_args()
    if not args.env_file.parent.is_dir():
        print(f"{args.env_file.parent} does not exist")
        return 1
    phrase = getpass.getpass("Recovery phrase (hidden): ")
    try:
        account = derive(phrase, args.index)
    except Exception:
        print("That is not a valid recovery phrase. Nothing was written.")
        return 1
    print(f"Account {args.index} of this phrase is {account.address}")
    if input("Is that the drained wallet? Type yes to write its key: ").strip().lower() != "yes":
        print("Nothing was written. Try another --index if the address is not the one you expected.")
        return 1
    write_key(args.env_file, "0x" + bytes(account.key).hex())
    print(f"{NAME} is set in {args.env_file}. The key was not shown.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
