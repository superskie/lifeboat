"""Tool handlers: JSON in, JSON string out. Every error is caught and every output is scrubbed.

Keys and the safe address come from configuration, never from tool arguments, so nothing the model
writes can change who signs or who receives.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from pathlib import Path
from typing import Callable

from eth_utils import is_address, to_checksum_address

from . import schemas
from .core import artifacts as artifact_mod
from .core import evidence as evidence_mod
from .core import scan as scan_mod
from .core.chains import CHAINS, chain_name, get_chain, web3_for
from .core.execute import NotConfirmed, _batch_key, _fee_parts, execute, l1_data_fee, sweep_back
from .core.keys import KeyConfigError, OperatorStore, Signer, seal_secret, seal_tag, victim_signer
from .core.plan import ZERO, Plan, PolicyError, build_plan, summarize
from .core.scrub import Scrubber, strip_urls
from .core.simulate import simulate
from .core.store import Store

SAFE_ENV = "LIFEBOAT_SAFE_ADDRESS"
ENABLE_ENV = "LIFEBOAT_ENABLE_EXECUTE"
WRITE_TOOLS = frozenset(name for name, _ in schemas.WRITE_TOOLS)
AUTHORIZATION_GAS = 125_000  # EIP-7702 charges 25,000 per authorization, up to four are sent; plus headroom
APPROVAL_TTL = 15 * 60  # seconds an answered approval prompt stays usable by its handler

STEPS = (
    "lifeboat rescues what a sweeper left behind, in one transaction the drained wallet never pays for:\n"
    "  1. scan      see what the wallet still holds on each chain, read-only (lifeboat_scan)\n"
    "  2. plan      list the claim, withdraw and transfer steps (lifeboat_plan)\n"
    "  3. simulate  dry-run the plan against the live chain (lifeboat_simulate)\n"
    "  4. fund      send a little gas to the operator address shown in the plan, from a wallet that has\n"
    "               nothing to do with the drained one, and never to the drained wallet itself\n"
    "  5. execute   one EIP-7702 transaction, after your approval (lifeboat_execute)\n"
    "  6. sweep     return the unused gas to the safe address (lifeboat_sweep_back)"
)


NO_EVIDENCE = (
    "lifeboat found no sign that this wallet is being swept, on any chain it can read, so it will not "
    "send a rescue for it. lifeboat is for wallets where gas is taken as soon as it arrives. A wallet "
    "nobody sweeps can be sent gas and emptied the ordinary way."
)


class ConfigError(Exception):
    pass


def _eth(wei: int) -> str:
    return f"{wei / 10**18:.8f}".rstrip("0").rstrip(".") or "0"


def _digest(doc) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


def _plan_digest(plan: Plan) -> str:
    """Everything in a plan that decides what a transaction does and who it is for."""
    doc = plan.to_dict()
    return _digest({k: doc[k] for k in ("id", "chain_id", "victim", "safe", "operator", "calls", "labels")})


class Runtime:
    def __init__(self, data_dir: Callable[[], Path], get_secret: Callable, get_config: Callable,
                 on_patterns: Callable[[list[str]], object] | None = None,
                 gate_bypassed: Callable[[], bool] | None = None) -> None:
        # Without a way to ask, assume nobody would be asked: write tools then stay blocked.
        self._gate_bypassed = gate_bypassed or (lambda: True)
        self._data_dir = data_dir
        self._get_secret = get_secret
        self._get_config = get_config
        self._on_patterns = on_patterns
        self._sent_patterns: set[str] = set()
        self.scrub = Scrubber()
        # The data directory is open to every other tool the agent has, so nothing a person approves
        # is read back from it. Simulation results and answered approvals live here, in memory.
        self._sims: dict[str, tuple[str, dict]] = {}
        self._approvals: dict[str, dict] = {}
        self._evidence: dict[str, str] = {}

    # -- configuration ---------------------------------------------------------------------------

    def _secret_seen(self, secret: str) -> None:
        """Every key read from anywhere lands here first, so it is redacted before it can be used."""
        self.scrub.add(secret)
        fresh = [p for p in self.scrub.patterns() if p not in self._sent_patterns]
        if fresh and self._on_patterns is not None:
            try:
                self._on_patterns(fresh)
            except Exception:
                pass
        self._sent_patterns.update(fresh)

    @property
    def store(self) -> Store:
        return Store(self._data_dir())

    @property
    def operators(self) -> OperatorStore:
        return OperatorStore(self._data_dir(), self._secret_seen,
                             lambda: seal_secret(self._get_secret, self._secret_seen))

    def execute_enabled(self) -> bool:
        try:
            return str(self._get_secret(ENABLE_ENV) or "").strip() == "1"
        except Exception:
            return False

    def victim(self) -> Signer:
        return victim_signer(self._get_secret, self._secret_seen)

    def safe(self) -> str:
        value = str(self._get_secret(SAFE_ENV) or "").strip()
        if not is_address(value) or to_checksum_address(value) == ZERO:
            raise ConfigError(f"{SAFE_ENV} is not set to a valid address")
        safe = to_checksum_address(value)
        try:
            victim = self.victim().address
        except KeyConfigError:
            victim = None
        if safe == victim:
            raise ConfigError(f"{SAFE_ENV} is the drained wallet itself; use a wallet the leaked key does not control")
        if safe in self.operators.addresses():
            raise ConfigError(f"{SAFE_ENV} is a lifeboat operator wallet; use a wallet of your own")
        return safe

    def w3(self, chain_id: int):
        overrides = self._get_config("rpc", {}) or {}
        return web3_for(get_chain(chain_id, overrides if isinstance(overrides, dict) else {}))

    def prime(self) -> None:
        """Read every key once at load so redaction is in place before the first tool call."""
        for read in (self.victim, lambda: [self.operators.load(a) for a in self.operators.addresses()]):
            try:
                read()
            except Exception:
                pass

    # -- plumbing --------------------------------------------------------------------------------

    def _clean(self, text: str) -> str:
        return self.scrub.clean(text)

    def _error_text(self, exc: BaseException) -> str:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        known = (PolicyError, ConfigError, KeyConfigError, ValueError, RuntimeError, KeyError)
        text = str(message) if isinstance(exc, known) else f"{type(exc).__name__}: {message}"
        return self._clean(strip_urls(text))[:600]

    def handler(self, name: str) -> Callable[..., str]:
        fn = {
            "lifeboat_scan": self._scan,
            "lifeboat_plan": self._plan,
            "lifeboat_simulate": self._simulate,
            "lifeboat_status": self._status,
            "lifeboat_execute": self._execute,
            "lifeboat_sweep_back": self._sweep_back,
        }[name]

        def handle(args: dict, **_kwargs) -> str:
            try:
                result = fn(args if isinstance(args, dict) else {})
            except Exception as exc:
                result = {"ok": False, "error": self._error_text(exc)}
            return self._clean(json.dumps(result))

        handle.__name__ = f"handle_{name}"
        return handle

    @staticmethod
    def _chain_arg(args: dict) -> int:
        try:
            return int(args.get("chain_id"))
        except (TypeError, ValueError):
            raise PolicyError("chain_id must be a whole number") from None

    @staticmethod
    def _plan_arg(args: dict) -> str:
        return str(args.get("plan_id") or "")

    def _require_enabled(self) -> None:
        if not self.execute_enabled():
            raise ConfigError(f"sending transactions is off; set {ENABLE_ENV}=1 to turn it on")

    def _load_current_plan(self, plan_id: str) -> Plan:
        plan = self.store.load_plan(plan_id)
        if plan.safe != self.safe():
            raise ConfigError("the safe address changed after this plan was made; build a new plan")
        if plan.victim != self.victim().address:
            raise ConfigError("this plan was made for a different drained wallet; build a new plan")
        if plan.operator not in self.operators.addresses():
            raise ConfigError("this plan names an operator wallet lifeboat does not hold; build a new plan")
        # The file is not trusted: the calls and the approval lines must be exactly what the actions build.
        rebuilt = build_plan(plan.chain_id, plan.victim, plan.safe, plan.operator, plan.actions)
        if rebuilt.calls != plan.calls or rebuilt.labels != plan.labels or rebuilt.actions != plan.actions:
            raise ConfigError(f"the stored plan {plan.id} was changed after it was built; build a new plan")
        return plan

    # -- read tools ------------------------------------------------------------------------------

    def _plan(self, args: dict) -> dict:
        chain_id = self._chain_arg(args)
        get_chain(chain_id)
        victim = self.victim().address
        safe = self.safe()
        operator = self.operators.latest() or self.operators.create()
        plan = build_plan(chain_id, victim, safe, operator.address, args.get("actions"))
        stored = json.dumps(plan.to_dict())
        if self._clean(stored) != stored:
            raise PolicyError("an argument repeats a private key; a key never belongs in a plan")
        self.store.save_plan(plan)
        return {
            "ok": True,
            "plan_id": plan.id,
            "operator": operator.address,
            "summary": summarize(plan),
            "next": (
                f"Run lifeboat_simulate with plan_id {plan.id}. Before executing, the operator "
                f"{operator.address} needs a little native gas on {chain_name(chain_id)}. "
                "Never send gas to the drained wallet."
            ),
        }

    def _own_batches(self, chains: list) -> set[str]:
        """Addresses of the batch contracts lifeboat deployed: a delegation to one of them is its own."""
        store, operators = self.store, self.operators.addresses()
        found = {store.load_meta(_batch_key(chain.id, operator)).get("address")
                 for chain in chains for operator in operators}
        return found - {None}

    def _scan(self, args: dict) -> dict:
        victim = self.victim().address
        overrides = self._get_config("rpc", {}) or {}
        overrides = overrides if isinstance(overrides, dict) else {}
        wanted = args.get("chain_ids")
        if wanted is None:
            ids = sorted(CHAINS)
        elif isinstance(wanted, list) and wanted:
            ids = [self._chain_arg({"chain_id": chain_id}) for chain_id in wanted]
        else:
            raise PolicyError("chain_ids must be a list of chain ids, or left out to scan every chain")
        chains = [get_chain(chain_id, overrides) for chain_id in ids]
        reports = scan_mod.scan(
            victim, chains,
            lambda chain: web3_for(chain).eth.get_balance(victim),
            lambda chain: web3_for(chain).eth.get_code(victim),
            self._own_batches(chains),
        )
        return {
            "ok": True,
            "wallet": victim,
            "chains": [report.to_dict() for report in reports],
            "next": (
                "Each chain lists ready transfer steps under actions: pass the ones worth rescuing to "
                "lifeboat_plan, one plan per chain, together with any claim or unstake call. A spam token "
                "whose transfer reverts fails the whole batch; lifeboat_simulate shows which step, drop it. "
                "The scan only reads: it sends nothing and does not touch the wallet."
            ),
        }

    def _sweep_evidence(self, plan: Plan) -> tuple[str | None, dict[str, str]]:
        """A sign that the wallet in this plan is being swept, on any chain, the plan's own first.
        Found once, it is kept for the session. Returns the line for the approval text, or nothing
        and what could not be read."""
        found = self._evidence.get(plan.victim)
        if found is not None:
            return found, {}
        # Only the latest pages of a history are read and explorers go down, so evidence found once
        # is kept for later sessions, tagged so that a hand-written file is not taken for it.
        store = self.store
        seal = seal_secret(self._get_secret, self._secret_seen)
        name = f"evidence-{plan.victim[2:].lower()}"
        saved = store.load_meta(name)
        line = saved.get("line")
        if isinstance(line, str) and hmac.compare_digest(str(saved.get("tag")), seal_tag(seal, plan.victim, line)):
            self._evidence[plan.victim] = line
            return line, {}
        overrides = self._get_config("rpc", {}) or {}
        overrides = overrides if isinstance(overrides, dict) else {}
        order = sorted(CHAINS, key=lambda chain_id: chain_id != plan.chain_id)
        chains = [get_chain(chain_id, overrides) for chain_id in order]
        found, errors = evidence_mod.gather(plan.victim, chains)
        if found is None:
            return None, errors
        line = found.line()
        store.save_meta(name, {"line": line, "tag": seal_tag(seal, plan.victim, line),
                               "created_at": int(time.time())})
        self._evidence[plan.victim] = line
        return line, {}

    def _sim_for(self, plan: Plan) -> dict | None:
        """The simulation this process ran for exactly this plan, if any."""
        digest, doc = self._sims.get(plan.id, ("", None))
        return doc if doc is not None and digest == _plan_digest(plan) else None

    def _take_approval(self, key: str, digest: str) -> dict:
        """The record the approval hook left for this call. One approval covers one send."""
        record = self._approvals.pop(key, None)
        if record is None or time.time() - record["at"] > APPROVAL_TTL:
            raise ConfigError("this call was not approved; lifeboat only sends after the approval prompt")
        if record["digest"] != digest:
            raise ConfigError("what would be sent is not what was approved; start again from lifeboat_simulate")
        return record

    def _gas_estimate(self, w3, plan: Plan, arts, checks: list) -> dict | None:
        """Upper bound for what the operator pays, deployment included when the batch is not there yet."""
        try:
            calldata = arts.encode_execute(plan.calls, checks)
            units = w3.eth.estimate_gas(
                {"from": plan.operator, "to": plan.victim, "data": "0x" + calldata.hex()},
                "latest",
                {plan.victim: {"code": arts.batch_runtime(plan.operator)}},
            ) * 13 // 10 + AUTHORIZATION_GAS
            transactions = 1
            saved = self.store.load_meta(_batch_key(plan.chain_id, plan.operator)).get("address")
            if not saved or bytes(w3.eth.get_code(saved)) != arts.batch_runtime(plan.operator):
                initcode = arts.batch_initcode(plan.operator)
                units += w3.eth.estimate_gas({"from": plan.operator, "data": "0x" + initcode.hex()}) * 13 // 10
                transactions = 2
            base, tip = _fee_parts(w3, None)
            cost = units * (base * 2 + tip) + l1_data_fee(w3, calldata) * 2 * transactions
            cost = cost * 5 // 4  # the base fee can rise between the dry run and the send
            balance = w3.eth.get_balance(plan.operator)
            return {"max_cost_wei": str(cost), "operator_balance_wei": str(balance), "enough": balance >= cost}
        except Exception:
            return None

    def _simulate(self, args: dict) -> dict:
        plan = self._load_current_plan(self._plan_arg(args))
        w3 = self.w3(plan.chain_id)
        arts = artifact_mod.load()
        result = simulate(w3, plan, arts)
        doc = result.to_dict()
        doc["gas"] = self._gas_estimate(w3, plan, arts, result.checks) if result.ok else None
        doc["gains"] = {asset: str(amount) for asset, amount in result.gains().items()}
        doc["evidence"], unread = self._sweep_evidence(plan) if result.ok else (None, {})
        plan.simulation = doc
        self._sims[plan.id] = (_plan_digest(plan), doc)
        self.store.save_plan(plan)  # the stored copy is for reference only and is never read back
        out = {"ok": result.ok, "plan_id": plan.id, "summary": summarize(plan), "simulation": doc}
        gas = doc["gas"]
        if result.ok and not doc["evidence"]:
            out["next"] = NO_EVIDENCE + (
                " Could not be read: " + "; ".join(f"{name} ({why})" for name, why in unread.items()) + "."
                if unread else ""
            )
        elif gas and not gas["enough"]:
            out["next"] = (
                f"Send at least {_eth(int(gas['max_cost_wei']))} native currency on "
                f"{chain_name(plan.chain_id)} to the operator {plan.operator}, then execute."
            )
        return out

    def _verdict(self, plan: Plan) -> str:
        sim = self._sim_for(plan)
        if not sim:
            return "not simulated in this session"
        if sim.get("ok"):
            return f"passed at block {sim.get('block')}"
        return f"failed: {sim.get('revert_reason') or '; '.join(sim.get('warnings') or []) or 'see details'}"

    def _status(self, args: dict) -> dict:
        store = self.store
        plans = store.plans()
        receipts = store.receipts()
        setup: dict = {"execute_enabled": self.execute_enabled()}
        for name, read in (("drained_wallet", lambda: self.victim().address), ("safe_address", self.safe)):
            try:
                setup[name] = read()
            except Exception as exc:
                setup[name] = f"not configured: {self._error_text(exc)}"

        chains = {p.chain_id for p in plans}
        if args.get("chain_id") is not None:
            chains.add(self._chain_arg(args))
        operators = []
        funded = False
        for address in self.operators.addresses():
            balances = {}
            for chain_id in sorted(chains):
                try:
                    wei = self.w3(chain_id).eth.get_balance(address)
                    balances[chain_name(chain_id)] = str(wei)
                    funded = funded or wei > 0
                except Exception as exc:
                    balances[chain_name(chain_id)] = f"unreadable: {self._error_text(exc)}"
            operators.append({"address": address, "balance_wei": balances})

        hints = []
        if not setup["execute_enabled"]:
            hints.append(f"Read-only mode. Set {ENABLE_ENV}=1 to allow lifeboat_execute and lifeboat_sweep_back.")
        if funded and receipts:
            hints.append("An operator still holds gas. lifeboat_sweep_back returns it to the safe address.")
        return {
            "ok": True,
            "setup": setup,
            "operators": operators,
            "plans": [
                {"plan_id": p.id, "chain": chain_name(p.chain_id), "chain_id": p.chain_id,
                 "calls": len(p.calls), "simulation": self._verdict(p)}
                for p in plans[-10:]
            ],
            "receipts": [
                {k: r.get(k) for k in ("ok", "plan_id", "chain_id", "tx_hash", "link", "problems", "warnings",
                                       "balances", "gas_paid_wei")}
                for r in receipts[-10:]
            ],
            "hints": hints,
            "supported_chains": [
                {"chain_id": c.id, "name": c.name, "testnet": c.testnet, "history_readable": bool(c.blockscout)}
                for c in sorted(CHAINS.values(), key=lambda c: (c.testnet, c.name))
            ],
        }

    # -- write tools -----------------------------------------------------------------------------

    def _execute(self, args: dict) -> dict:
        self._require_enabled()
        plan = self._load_current_plan(self._plan_arg(args))
        approval = self._take_approval(plan.id, _plan_digest(plan))
        victim = self.victim()
        operator = self.operators.load(plan.operator)
        try:
            receipt = execute(self.w3(plan.chain_id), plan, victim, operator, artifact_mod.load(), self.store,
                              max_cost_wei=approval["ceiling"], approved=approval["gains"])
        except NotConfirmed as exc:
            return {
                "ok": False,
                "error": str(exc),
                "tx_hash": exc.tx_hash,
                "link": get_chain(plan.chain_id).tx_link(exc.tx_hash),
                "next": "Do not execute again until the explorer shows what happened to this transaction.",
            }
        out = {"ok": receipt.ok, "receipt": receipt.to_dict()}
        if receipt.ok:
            out["next"] = (
                "Rescue confirmed. lifeboat_sweep_back returns the unused operator gas to the safe address. "
                "The drained wallet stays delegated to the rescue contract and the leaked key still controls "
                "it, so never use that wallet again."
            )
        else:
            out["error"] = "The transaction was mined but the rescue is not confirmed: " + "; ".join(receipt.problems)
        return out

    def _sweep_back(self, args: dict) -> dict:
        self._require_enabled()
        chain_id = self._chain_arg(args)
        chain = get_chain(chain_id)
        w3 = self.w3(chain_id)
        safe = self.safe()
        operators = self.operators.addresses()
        self._take_approval(f"sweep-{chain_id}", _digest([chain_id, safe, operators]))
        swept = []
        for address in operators:
            entry: dict = {"operator": address}
            try:
                tx_hash = sweep_back(w3, self.operators.load(address), safe)
                entry["tx_hash"] = tx_hash
                entry["link"] = chain.tx_link(tx_hash) if tx_hash else None
                if tx_hash is None:
                    entry["note"] = "nothing worth sending"
            except Exception as exc:
                entry["error"] = self._error_text(exc)
            swept.append(entry)
        return {"ok": all("error" not in e for e in swept), "chain": chain.name, "safe": safe, "operators": swept}

    # -- approval --------------------------------------------------------------------------------

    def _approval(self, tool_name: str, args: dict) -> tuple[str, str, dict]:
        """(text the user approves, key, record) for a write tool. The record pins what the text
        describes; the handler takes it back and refuses to send anything else. No RPC is made here, so
        the hook stays fast: the simulation shown is the one this process ran and kept in memory."""
        self._require_enabled()
        if tool_name == "lifeboat_execute":
            plan = self._load_current_plan(self._plan_arg(args))
            sim = self._sim_for(plan)
            if not sim or not sim.get("ok"):
                raise ConfigError(
                    f"plan {plan.id} has no passing simulation from this session; run lifeboat_simulate first"
                )
            gas = sim.get("gas")
            if not gas:
                raise ConfigError("the gas cost could not be estimated, so there is no ceiling to approve; "
                                  "run lifeboat_simulate again")
            if not sim.get("evidence"):
                raise ConfigError(NO_EVIDENCE)
            plan.simulation = sim
            lines = [summarize(plan), f"why this wallet qualifies for a rescue: {sim['evidence']}",
                     "expected result:"]
            for b in sim["balances"]:
                lines.append(
                    f"  {b['asset']}: wallet {b['victim_before']} -> {b['victim_after']}, "
                    f"safe {b['safe_before']} -> {b['safe_after']}"
                )
            lines.append(
                "the transaction reverts as a whole if the safe address would receive less than shown"
            )
            lines.append(
                f"gas: at most {_eth(int(gas['max_cost_wei']))} native, paid by the operator "
                f"(it held {_eth(int(gas['operator_balance_wei']))} at simulation time)"
            )
            record = {
                "digest": _plan_digest(plan),
                "gains": {asset: int(amount) for asset, amount in sim["gains"].items()},
                "ceiling": int(gas["max_cost_wei"]),
            }
            return "\n".join(lines), plan.id, record
        if tool_name == "lifeboat_sweep_back":
            chain = get_chain(self._chain_arg(args))
            operators = self.operators.addresses()
            if not operators:
                raise ConfigError("there is no operator wallet to sweep")
            safe = self.safe()
            text = "\n".join([
                f"lifeboat sweep-back on {chain.name} (chain {chain.id})",
                f"  send all remaining gas to the safe address {safe}",
                *[f"  from operator {address}" for address in operators],
            ])
            return text, f"sweep-{chain.id}", {"digest": _digest([chain.id, safe, operators])}
        raise ConfigError(f"{tool_name} has no approval text")

    def approval_message(self, tool_name: str, args: dict) -> str:
        return self._approval(tool_name, args)[0]

    def pre_tool_call(self, tool_name: str = "", args: dict | None = None, **_kwargs):
        if tool_name not in WRITE_TOOLS:
            return None
        try:
            bypassed = bool(self._gate_bypassed())
        except Exception:
            bypassed = True
        if bypassed:
            return {
                "action": "block",
                "message": (
                    "lifeboat: nobody would be asked for approval here (yolo mode, approvals off, an "
                    "unattended session such as cron, -q, webhook or API, or the plugin host process). "
                    "lifeboat only sends a transaction after a person approves it in an interactive session."
                ),
            }
        try:
            message, key, record = self._approval(tool_name, args if isinstance(args, dict) else {})
        except Exception as exc:
            return {"action": "block", "message": f"lifeboat: {self._error_text(exc)}"}
        self._approvals[key] = {**record, "at": time.time()}
        # A fresh rule key per call: an "always allow" answer must never cover a later transaction.
        return {
            "action": "approve",
            "message": self._clean(message),
            "rule_key": f"lifeboat:{tool_name}:{uuid.uuid4().hex}",
        }

    # -- slash command ---------------------------------------------------------------------------

    def command(self, raw_args: str = "") -> str:
        try:
            status = self._status({})
        except Exception as exc:
            return self._clean(f"{STEPS}\n\nstatus unavailable: {self._error_text(exc)}")
        setup = status["setup"]
        lines = [
            STEPS, "",
            f"drained wallet: {setup['drained_wallet']}",
            f"safe address:   {setup['safe_address']}",
            f"transactions:   {'enabled' if setup['execute_enabled'] else 'off (read-only)'}",
        ]
        for op in status["operators"]:
            held = ", ".join(f"{chain}: {wei}" for chain, wei in op["balance_wei"].items()) or "no chain read yet"
            lines.append(f"operator:       {op['address']} ({held})")
        for plan in status["plans"]:
            lines.append(f"plan {plan['plan_id']} on {plan['chain']}: {plan['calls']} calls, {plan['simulation']}")
        for receipt in status["receipts"]:
            lines.append(f"receipt {receipt['tx_hash']}: {'confirmed' if receipt['ok'] else 'NOT confirmed'}")
        lines += status["hints"]
        return self._clean("\n".join(lines))
