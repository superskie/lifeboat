import json
import time
import traceback

import pytest
from eth_account import Account

from lifeboat.core.keys import VICTIM_KEY_ENV, KeyConfigError, OperatorStore, victim_signer
from lifeboat.core.scrub import Scrubber


def key_hex(account) -> str:
    return "0x" + bytes(account.key).hex()


def test_signer_repr_has_no_key():
    account = Account.create()
    signer = victim_signer(lambda name: key_hex(account), lambda secret: None)
    text = repr(signer) + str(signer) + f"{signer}"
    assert account.address in text
    assert bytes(account.key).hex() not in text.lower()


def test_victim_secret_is_reported_before_parsing():
    seen = []
    account = Account.create()
    victim_signer(lambda name: key_hex(account), seen.append)
    assert seen == [key_hex(account)]


def test_bad_victim_key_error_has_no_key():
    bad = "0x" + "ab" * 31 + "zz"
    with pytest.raises(KeyConfigError) as info:
        victim_signer(lambda name: bad, lambda secret: None)
    err = info.value
    rendered = str(err) + repr(err) + "".join(traceback.format_exception(err))
    assert bad[2:] not in rendered.lower()
    assert err.__context__ is None
    assert VICTIM_KEY_ENV in str(err)


def test_missing_victim_key():
    with pytest.raises(KeyConfigError):
        victim_signer(lambda name: None, lambda secret: None)


SEAL = b"\x07" * 32


def test_operator_key_on_disk_before_create_returns(tmp_path):
    seen = []
    store = OperatorStore(tmp_path, seen.append, lambda: SEAL)
    signer = store.create()
    path = tmp_path / "operators" / f"{signer.address}.json"
    text = path.read_text(encoding="utf-8")
    assert seen[0][2:] not in text.lower(), "the key is sealed on disk, not written in the clear"
    assert store.load(signer.address).address == signer.address
    assert store.addresses() == [signer.address]
    assert store.latest().address == signer.address
    # The same file under another victim key is nobody's operator.
    other = OperatorStore(tmp_path, lambda secret: None, lambda: b"\x08" * 32)
    assert other.addresses() == [] and other.latest() is None
    with pytest.raises(KeyConfigError):
        other.load(signer.address)


def test_planted_operator_file_is_not_adopted(tmp_path):
    """Review 2, findings 4 and 9: a file somebody else wrote must never become the signer."""
    store = OperatorStore(tmp_path, lambda secret: None, lambda: SEAL)
    real = store.create()
    folder = tmp_path / "operators"
    genuine = json.loads((folder / f"{real.address}.json").read_text(encoding="utf-8"))
    future = int(time.time()) + 10**6

    planted = Account.create()
    key = "0x" + bytes(planted.key).hex()
    forgeries = [
        {"address": planted.address, "key": key, "created_at": future},
        {"address": planted.address, "sealed": key[2:], "created_at": future, "mac": "00" * 32},
        {"address": planted.address, "sealed": key[2:], "created_at": future, "mac": genuine["mac"]},
        {**genuine, "address": planted.address},
    ]
    for forged in forgeries:
        (folder / f"{planted.address}.json").write_text(json.dumps(forged), encoding="utf-8")
        assert store.addresses() == [real.address]
        assert store.latest().address == real.address
        with pytest.raises(KeyConfigError):
            store.load(planted.address)

    # A genuine record cannot be re-dated or moved to another file name either.
    (folder / f"{planted.address}.json").write_text(json.dumps(genuine), encoding="utf-8")
    assert store.addresses() == [real.address]
    (folder / f"{real.address}.json").write_text(json.dumps({**genuine, "created_at": future}), encoding="utf-8")
    assert store.addresses() == []
    (folder / "broken.json").write_text("{not json", encoding="utf-8")
    assert store.addresses() == []


def test_operator_store_without_a_victim_key_sees_no_operators(tmp_path):
    OperatorStore(tmp_path, lambda secret: None, lambda: SEAL).create()

    def missing() -> bytes:
        raise KeyConfigError("no victim key")

    store = OperatorStore(tmp_path, lambda secret: None, missing)
    assert store.addresses() == [] and store.latest() is None
    with pytest.raises(KeyConfigError):
        store.create()


def test_operator_secret_reported_on_create_and_load(tmp_path):
    seen = []
    store = OperatorStore(tmp_path, seen.append, lambda: SEAL)
    signer = store.create()
    assert seen, "secret must be reported before create returns"
    store.load(signer.address)
    assert set(seen) == {seen[0]}
    assert Account.from_key(seen[0]).address == signer.address


def test_scrubber_removes_key_in_any_case_and_prefix():
    account = Account.create()
    raw = bytes(account.key).hex()
    scrub = Scrubber()
    scrub.add("0x" + raw)
    text = f"a 0x{raw} b {raw.upper()} c {raw}"
    cleaned = scrub.clean(text)
    assert raw not in cleaned.lower()
    assert cleaned.count("[redacted]") == 3


def test_scrubber_patterns_start_with_two_literal_characters_and_no_more():
    account = Account.create()
    scrub = Scrubber()
    scrub.add("0x" + bytes(account.key).hex())
    assert scrub.patterns()
    for pattern in scrub.patterns():
        assert pattern[:2].isalnum() and pattern[2] == "("
        assert "|" not in pattern
