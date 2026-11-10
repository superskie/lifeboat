# Demo: a swept wallet on Base Sepolia, rescued

Everything here runs on a testnet with throwaway keys. The scripts create four wallets on first use
and keep their keys in `demo/.env`, which git ignores: a deployer, the victim, the safe and the
sweeper's own wallet. The victim key is "leaked" on purpose: the sweeper script uses it.

You need Foundry (`forge`) and the Python environment from the main README.

## 1. Set up the victim

```
python demo/setup_victim.py
```

The first run prints the deployer address and stops. Send it a little Base Sepolia ETH from a
faucet (0.005 is plenty) and run it again. It deploys a token, an NFT, a staking pool and a vesting
contract, and leaves the victim with:

- 400 tokens in the wallet
- 600 tokens staked (`withdraw()` on the pool returns them)
- 500 tokens vesting, unlocking two minutes later (`claim()` on the vesting contract)
- one NFT

The addresses are written to `demo/.state/addresses.json`.

## 2. Let the sweeper loose

```
python demo/sweeper.py --bait 2
```

The bot holds the victim key and sends away any ETH that reaches the wallet. With `--bait 2` the
deployer first sends the wallet gas twice, as an owner would when trying to move the tokens by
hand, and the bot takes it both times. Leave it running in its own terminal for the rest of the demo.

This is the problem. The tokens, the stake, the grant and the NFT are still there, and no
transaction from the wallet can ever be paid for.

## 3. Rescue it from Hermes

Put two values into the Hermes environment (not into the chat): `LIFEBOAT_VICTIM_KEY`, the
`VICTIM_KEY` line of `demo/.env`, and `LIFEBOAT_SAFE_ADDRESS`, printed by the setup script. Set
`LIFEBOAT_ENABLE_EXECUTE=1`. Then ask the agent, in your own words:

> My wallet got drained and a bot takes any gas I send it. Use lifeboat to see what is left on Base
> Sepolia and rescue it. There is a stake in `<staking address>` (withdraw()) and a vesting grant in
> `<vesting address>` (claim()).

What should happen:

1. `lifeboat_scan` lists the 400 tokens and the NFT, and reports the sweeps on record.
2. `lifeboat_plan` builds one batch: withdraw, claim, send all tokens, send the NFT.
3. `lifeboat_simulate` shows 1500 tokens and the NFT arriving at the safe, quotes the sweeps that
   qualify the wallet, and says how much gas the operator needs.
4. You send that gas to the operator address, from the deployer or any other wallet. Never to the
   victim, and the sweeper would take it anyway.
5. `lifeboat_execute` shows the approval text. Approve it. One transaction later the safe holds
   everything and the sweeper's terminal has printed nothing new.
6. `lifeboat_sweep_back` returns the leftover gas to the safe.

If the vesting grant is still locked when you simulate, the simulation fails with `locked` and
nothing can be sent. Wait for the unlock and simulate again.

## What the demo does not show

A testnet sweeper is a script we wrote. The contracts are mocks. The scan needs a moment after the
setup before the explorer has indexed the new tokens. On a real chain the rescue transaction is
visible in the mempool for a moment before it lands, where the chain has a public one.
