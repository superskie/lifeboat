import pytest

from lifeboat.core.chains import CHAINS, UnknownChain, chain_name, get_chain


def test_gensyn_mainnet_is_registered():
    chain = get_chain(685689)
    assert chain.name == "Gensyn"
    assert not chain.testnet
    assert chain.tx_link("0xabc") == "https://gensyn-mainnet.explorer.alchemy.com/tx/0xabc"
    assert chain_name(685689) == "Gensyn"


def test_rpc_override_wins_and_unknown_chain_is_refused():
    assert get_chain(685689, {"685689": "http://localhost:1"}).rpc == "http://localhost:1"
    with pytest.raises(UnknownChain):
        get_chain(999999)


def test_every_chain_has_a_https_rpc_and_explorer():
    for chain_id, chain in CHAINS.items():
        assert chain.id == chain_id
        assert chain.rpc.startswith("https://"), chain.name
        assert chain.explorer.startswith("https://"), chain.name
        assert chain.blockscout is None or chain.blockscout.startswith("https://"), chain.name
    assert len({chain.name for chain in CHAINS.values()}) == len(CHAINS) == 19
    assert len({chain.rpc for chain in CHAINS.values()}) == len(CHAINS)


def test_chains_added_by_probe_are_registered():
    assert chain_name(42161) == "Arbitrum One" and chain_name(4663) == "Robinhood Chain"
    assert get_chain(42161).blockscout is None  # its explorer refuses scripts: no history, rescue still works
    assert get_chain(1868).blockscout == "https://soneium.blockscout.com"
