"""lifeboat: rescue what a sweeper left behind in a drained EVM wallet. Hermes entry point."""

from __future__ import annotations

from pathlib import Path

from . import schemas
from .tools import Runtime

TOOLSET = "lifeboat"


def _secret_getter():
    """Hermes resolves secrets per profile. Outside Hermes (tests, scripts) the process env is used."""
    try:
        from agent.secret_scope import get_secret

        return get_secret
    except Exception:
        import os

        return lambda name, default=None: os.environ.get(name, default)


def _gate_bypassed() -> bool:
    """True when Hermes would let an "approve" request through without asking anyone. The gate skips its
    prompt in yolo mode, with approvals off, and in sessions where nobody can answer (cron, `-q`,
    webhook and API sessions), which a config switch can turn into silent approval. lifeboat must not
    send a transaction in any of them. In the plugin host process the session's yolo switch cannot be
    seen at all, so write tools need in-process plugin loading. Any doubt, including a Hermes version
    where this cannot be read, counts as bypassed."""
    import os

    if os.environ.get("HERMES_PLUGIN_HOST_PROCESS") == "1":
        return True
    try:
        from tools import approval, approval_context

        return bool(
            approval._yolo_active()
            or approval_context._get_approval_mode() == "off"
            or approval_context._no_user_can_answer()
        )
    except Exception:
        return True


def register(ctx) -> None:
    runtime = Runtime(
        data_dir=lambda: Path(ctx.state.data_dir),
        get_secret=_secret_getter(),
        get_config=ctx.get_config,
        on_patterns=ctx.register_redaction_patterns,
        gate_bypassed=lambda: _gate_bypassed(),
    )
    for name, schema in schemas.READ_TOOLS:
        ctx.register_tool(name=name, toolset=TOOLSET, schema=schema, handler=runtime.handler(name), emoji="🛟")
    for name, schema in schemas.WRITE_TOOLS:
        ctx.register_tool(name=name, toolset=TOOLSET, schema=schema, handler=runtime.handler(name),
                          check_fn=runtime.execute_enabled, emoji="🛟")
    ctx.register_hook("pre_tool_call", runtime.pre_tool_call)
    ctx.register_command(
        "lifeboat", runtime.command,
        description="Rescue steps and current lifeboat status", args_hint="[status]",
    )
    runtime.prime()
