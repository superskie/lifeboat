"""Supported chains and one keep-alive Web3 client per chain."""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace

from web3 import Web3


@dataclass(frozen=True)
class Chain:
    id: int
    name: str
    rpc: str
    explorer: str
    blockscout: str | None = None  # Blockscout API host, each checked with a live request on 2026-11-10
    testnet: bool = False
    block_time: float = 2.0

    def tx_link(self, tx_hash: str) -> str:
        return f"{self.explorer}/tx/{tx_hash}" if self.explorer else tx_hash

    def address_link(self, address: str) -> str:
        return f"{self.explorer}/address/{address}" if self.explorer else address


CHAINS: dict[int, Chain] = {
    c.id: c
    for c in (
        Chain(84532, "Base Sepolia", "https://sepolia.base.org", "https://sepolia.basescan.org",
              "https://base-sepolia.blockscout.com", True, 2.0),
        Chain(11155420, "OP Sepolia", "https://sepolia.optimism.io", "https://sepolia-optimism.etherscan.io",
              "https://testnet-explorer.optimism.io", True, 2.0),
        Chain(11155111, "Sepolia", "https://ethereum-sepolia-rpc.publicnode.com", "https://sepolia.etherscan.io",
              "https://eth-sepolia.blockscout.com", True, 12.0),
        # base.blockscout.com answers scripts with a browser challenge (2026-11-10), so Base has no
        # history lifeboat can read; only the delegation is checked there.
        Chain(8453, "Base", "https://mainnet.base.org", "https://basescan.org", None, False, 2.0),
        Chain(10, "OP Mainnet", "https://mainnet.optimism.io", "https://optimistic.etherscan.io",
              "https://explorer.optimism.io", False, 2.0),
        Chain(1, "Ethereum", "https://ethereum-rpc.publicnode.com", "https://etherscan.io",
              "https://eth.blockscout.com", False, 12.0),
        # OP Stack (op-reth). Live eth_call with an authorization list honoured delegation on 2026-11-09.
        Chain(685689, "Gensyn", "https://gensyn-mainnet.g.alchemy.com/public",
              "https://gensyn-mainnet.explorer.alchemy.com", "https://gensyn-mainnet.explorer.alchemy.com",
              False, 2.0),
        # Added 2026-11-10. Each answered a live probe on its public RPC: the chain id, an eth_call and
        # an eth_estimateGas carrying an EIP-7702 authorization (delegation honoured), and an eth_call
        # with a state override. Where the last field is a host, its Blockscout API answered too; where
        # it is None the explorer refuses scripts or has no such API, so history and tokens are not read.
        Chain(42161, "Arbitrum One", "https://arb1.arbitrum.io/rpc", "https://arbiscan.io", None, False, 0.25),
        Chain(421614, "Arbitrum Sepolia", "https://sepolia-rollup.arbitrum.io/rpc", "https://sepolia.arbiscan.io",
              None, True, 0.25),
        Chain(4663, "Robinhood Chain", "https://rpc.mainnet.chain.robinhood.com",
              "https://robinhoodchain.blockscout.com", None, False, 0.25),
        Chain(130, "Unichain", "https://mainnet.unichain.org", "https://unichain.blockscout.com",
              "https://unichain.blockscout.com", False, 1.0),
        Chain(1868, "Soneium", "https://rpc.soneium.org", "https://soneium.blockscout.com",
              "https://soneium.blockscout.com", False, 2.0),
        Chain(57073, "Ink", "https://rpc-gel.inkonchain.com", "https://explorer.inkonchain.com",
              "https://explorer.inkonchain.com", False, 1.0),
        Chain(480, "World Chain", "https://worldchain-mainnet.g.alchemy.com/public",
              "https://worldchain-mainnet.explorer.alchemy.com", "https://worldchain-mainnet.explorer.alchemy.com",
              False, 2.0),
        # Scroll charges a data fee through its own oracle, which lifeboat does not read: fund the
        # operator with a margin there.
        Chain(534352, "Scroll", "https://rpc.scroll.io", "https://scroll.blockscout.com",
              "https://scroll.blockscout.com", False, 3.0),
        Chain(100, "Gnosis", "https://rpc.gnosischain.com", "https://gnosisscan.io", None, False, 5.0),
        Chain(59144, "Linea", "https://rpc.linea.build", "https://lineascan.build", None, False, 2.0),
        Chain(80094, "Berachain", "https://rpc.berachain.com", "https://berascan.com", None, False, 2.0),
        Chain(146, "Sonic", "https://rpc.soniclabs.com", "https://sonicscan.org", None, False, 0.5),
    )
}


class UnknownChain(ValueError):
    pass


def get_chain(chain_id: int, rpc_overrides: dict | None = None) -> Chain:
    chain = CHAINS.get(int(chain_id))
    if chain is None:
        raise UnknownChain(f"chain {chain_id} is not supported; supported: {sorted(CHAINS)}")
    override = (rpc_overrides or {}).get(str(chain.id)) or (rpc_overrides or {}).get(chain.id)
    return replace(chain, rpc=override) if override else chain


def chain_name(chain_id: int) -> str:
    chain = CHAINS.get(int(chain_id))
    return chain.name if chain else f"chain {chain_id}"


def _retry_reads_only():
    """web3 retries a failed request by default, eth_sendRawTransaction included. A send whose reply was
    lost would be posted twice and come back as "nonce too low" although the first one went through, so
    sends are never retried and their outcome is looked up by hash instead."""
    import requests
    from web3.providers.rpc.utils import REQUEST_RETRY_ALLOWLIST, ExceptionRetryConfiguration

    reads = [method for method in REQUEST_RETRY_ALLOWLIST if method != "eth_sendRawTransaction"]
    return ExceptionRetryConfiguration(
        errors=(ConnectionError, requests.HTTPError, requests.Timeout), method_allowlist=reads
    )


_clients: dict[tuple[int, str], Web3] = {}
_clients_lock = threading.Lock()


def web3_for(chain: Chain) -> Web3:
    key = (chain.id, chain.rpc)
    with _clients_lock:
        client = _clients.get(key)
        if client is None:
            client = Web3(Web3.HTTPProvider(chain.rpc, request_kwargs={"timeout": 20},
                                            exception_retry_configuration=_retry_reads_only()))
            _clients[key] = client
        return client
