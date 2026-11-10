"""The helper that writes the victim key from a recovery phrase."""

import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))

import key_from_mnemonic as helper  # noqa: E402

# The published development phrase every local chain uses; its accounts are public knowledge.
PHRASE = "test test test test test test test test test test test junk"


def test_derives_the_accounts_a_wallet_app_shows():
    assert helper.derive(PHRASE).address == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    assert helper.derive("  Test test test test test test test test test test test junk \n".lower(), 1).address \
        == "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


def test_writes_one_key_line_and_keeps_the_rest(tmp_path):
    path = tmp_path / ".env"
    path.write_text("OTHER=1\nLIFEBOAT_VICTIM_KEY=0xold\nLAST=2", encoding="utf-8")
    helper.write_key(path, "0xnew")
    assert path.read_text(encoding="utf-8") == "OTHER=1\nLAST=2\nLIFEBOAT_VICTIM_KEY=0xnew\n"
    fresh = tmp_path / "new.env"
    helper.write_key(fresh, "0xnew")
    assert fresh.read_text(encoding="utf-8") == "LIFEBOAT_VICTIM_KEY=0xnew\n"


def test_main_shows_the_address_and_never_the_key(tmp_path, monkeypatch, capsys):
    path = tmp_path / ".env"
    key = bytes(helper.derive(PHRASE).key).hex()
    monkeypatch.setattr(sys, "argv", ["key_from_mnemonic.py", str(path)])
    monkeypatch.setattr(helper.getpass, "getpass", lambda prompt: PHRASE)

    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    assert helper.main() == 1 and not path.exists()

    monkeypatch.setattr("builtins.input", lambda prompt: "yes")
    assert helper.main() == 0
    shown = capsys.readouterr().out
    assert "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" in shown
    assert key not in shown and "junk" not in shown
    assert path.read_text(encoding="utf-8") == f"LIFEBOAT_VICTIM_KEY=0x{key}\n"

    monkeypatch.setattr(helper.getpass, "getpass", lambda prompt: "not a phrase at all")
    assert helper.main() == 1
