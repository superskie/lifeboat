"""Tool schemas the model reads. No tool takes a key or a recipient: both come from configuration."""

from __future__ import annotations

_CHAIN = {
    "type": "integer",
    "description": "EVM chain id, for example 1 (Ethereum), 8453 (Base), 42161 (Arbitrum One), 84532 (Base Sepolia). "
                   "lifeboat_status lists every supported chain.",
}
_PLAN_ID = {"type": "string", "description": "Plan id returned by lifeboat_plan, for example p-1a2b3c4d5e."}

_ACTION = {
    "type": "object",
    "description": "One step of the rescue. Every asset ends at the configured safe address.",
    "properties": {
        "type": {
            "type": "string",
            "enum": ["transfer_erc20", "transfer_nft", "transfer_native", "call"],
            "description": (
                "transfer_erc20, transfer_nft and transfer_native move an asset to the safe address. "
                "call runs a claim, withdraw or unstake on another contract first, and a plan with a "
                "call also needs the transfer step for what that call releases."
            ),
        },
        "token": {"type": "string", "description": "Token contract address (transfer_erc20, transfer_nft)."},
        "amount": {
            "type": "string",
            "description": "'all' or a whole number in base units. ERC-1155 needs an exact number.",
        },
        "standard": {"type": "string", "enum": ["erc721", "erc1155"], "description": "For transfer_nft."},
        "token_id": {"type": "string", "description": "NFT token id (transfer_nft)."},
        "target": {"type": "string", "description": "Contract to call (call). Never the drained wallet."},
        "signature": {
            "type": "string",
            "description": (
                "Function to call, with full type names and no spaces, for example "
                "withdraw(uint256,address) or claim(uint256,address,uint256,bytes32[]). Only address, "
                "bool, uintN, intN, bytesN and flat arrays of them; raw calldata is not accepted."
            ),
        },
        "args": {
            "type": "array",
            "items": {},
            "description": (
                "Arguments in order. Numbers as decimal strings in base units, bytesN as 0x hex, arrays as "
                "lists. An address may only be the drained wallet, the safe address or a token this plan "
                "transfers; a recipient must be the safe address."
            ),
        },
        "label": {"type": "string", "description": "Short human label for the call, for example 'claim airdrop'."},
    },
    "required": ["type"],
}


def _schema(name: str, description: str, properties: dict, required: list[str] | None = None) -> dict:
    return {
        "name": name,
        "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required or []},
    }


PLAN = _schema(
    "lifeboat_plan",
    "Build a rescue plan for the drained wallet on one chain: an ordered batch of calls that runs in a "
    "single EIP-7702 transaction paid by a fresh operator wallet. Read-only: nothing is sent. Returns the "
    "plan id, a summary, and the operator address that needs a little gas on that chain.",
    {"chain_id": _CHAIN, "actions": {"type": "array", "items": _ACTION, "minItems": 1, "maxItems": 32}},
    ["chain_id", "actions"],
)

SCAN = _schema(
    "lifeboat_scan",
    "List what the drained wallet still holds on each supported chain: native balance, ERC-20 tokens, "
    "NFTs, whether it is delegated to a foreign contract, and how many sweeps are on record. Read-only: "
    "it sends nothing and never touches the wallet on chain. Returns ready transfer steps per chain for "
    "lifeboat_plan. Token symbols are shortened and names left out, since anyone can write them.",
    {"chain_ids": {"type": "array", "items": {"type": "integer"},
                   "description": "Optional: only these chain ids. Left out, every supported chain is scanned."}},
)

SIMULATE = _schema(
    "lifeboat_simulate",
    "Dry-run a plan against the live chain with eth_call state overrides. Read-only. Reports each call's "
    "result, the balance changes for the wallet and the safe address, and an estimated gas cost. It also "
    "looks, read-only, for a sign that the wallet is being swept on any supported chain; without one "
    "lifeboat_execute is refused, because a wallet nobody sweeps does not need lifeboat.",
    {"plan_id": _PLAN_ID},
    ["plan_id"],
)

STATUS = _schema(
    "lifeboat_status",
    "Show the lifeboat setup, operator wallets with their gas balances, plans with their last simulation "
    "verdict, and receipts of executed rescues. Read-only.",
    {"chain_id": {**_CHAIN, "description": "Optional: also read operator balances on this chain."}},
)

EXECUTE = _schema(
    "lifeboat_execute",
    "Send the rescue transaction for a plan that passed simulation. The operator pays the gas; the "
    "drained wallet never receives any. Asks the user for approval first. Returns a receipt that says "
    "what actually landed on chain.",
    {"plan_id": _PLAN_ID},
    ["plan_id"],
)

SWEEP_BACK = _schema(
    "lifeboat_sweep_back",
    "Return the gas left on the operator wallets to the configured safe address on one chain. Asks the "
    "user for approval first.",
    {"chain_id": _CHAIN},
    ["chain_id"],
)

READ_TOOLS = (("lifeboat_scan", SCAN), ("lifeboat_plan", PLAN), ("lifeboat_simulate", SIMULATE),
              ("lifeboat_status", STATUS))
WRITE_TOOLS = (("lifeboat_execute", EXECUTE), ("lifeboat_sweep_back", SWEEP_BACK))
