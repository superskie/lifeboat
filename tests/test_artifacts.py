import importlib.util

from conftest import ROOT, deploy_code, new_account

from lifeboat.core import artifacts


def _build_script():
    spec = importlib.util.spec_from_file_location("build_artifacts", ROOT / "scripts" / "build_artifacts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shipped_artifact_matches_fresh_compile(tmp_path):
    fresh = _build_script().build(tmp_path / "out")
    assert fresh == artifacts.ARTIFACT_PATH.read_text(encoding="utf-8")


def test_artifact_is_text():
    raw = artifacts.ARTIFACT_PATH.read_bytes()
    assert raw[:1] == b"{"
    assert b"\x00" not in raw


def test_runtime_patch_matches_deployment(w3):
    operator = new_account(w3, 10**18)
    art = artifacts.load()
    address = deploy_code(w3, operator, art.batch_initcode(operator.address))
    assert bytes(w3.eth.get_code(address)) == art.batch_runtime(operator.address)


def test_runtime_differs_per_operator():
    art = artifacts.load()
    a, b = new_account(), new_account()
    assert art.batch_runtime(a.address) != art.batch_runtime(b.address)
