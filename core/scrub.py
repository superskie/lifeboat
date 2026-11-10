"""Removes known secrets from text before it leaves the plugin (tool results, errors)."""

from __future__ import annotations

import re
import threading

REDACTED = "[redacted]"
_MIN_LEN = 32
_URL = re.compile(r"https?://[^\s'\"<>)\]]+", re.IGNORECASE)


# HTTP client errors print the host and the request path apart from each other.
_REQUEST_PATH = re.compile(r"(with url: |host=)\S+", re.IGNORECASE)


def strip_urls(text: str) -> str:
    """Error text from HTTP clients carries the full RPC URL, and provider URLs contain API keys."""
    text = _URL.sub("[url]", str(text))
    return _REQUEST_PATH.sub(r"\1[url]", text)


class Scrubber:
    def __init__(self) -> None:
        self._secrets: set[str] = set()
        self._lock = threading.Lock()

    def add(self, secret: str | None) -> None:
        if not secret:
            return
        value = secret.strip().lower()
        if value.startswith("0x"):
            value = value[2:]
        if len(value) < _MIN_LEN:
            return
        with self._lock:
            self._secrets.add(value)

    def clean(self, text: str) -> str:
        with self._lock:
            secrets = sorted(self._secrets, key=len, reverse=True)
        for secret in secrets:
            text = re.sub(r"(?:0x)?" + re.escape(secret), REDACTED, text, flags=re.IGNORECASE)
        return text

    def patterns(self) -> list[str]:
        """Patterns for Hermes redaction: each secret with and without 0x, in any letter case.

        Hermes wants at least two literal characters in front, forbids an identifier character right
        before a match, and prints the literal start of a pattern inside its redaction marker. So the
        literal part is two characters and no more: "0x" for the prefixed form, where a bare pattern
        would be blocked by the "x" in front of it, and the first two digits for the bare form.
        """
        with self._lock:
            secrets = sorted(self._secrets)
        out: list[str] = []
        for secret in secrets:
            if not re.fullmatch(r"[0-9a-f]+", secret):
                continue
            heads = {a + b for a in {secret[0], secret[0].upper()} for b in {secret[1], secret[1].upper()}}
            for pattern in [f"0x(?i:{secret})", f"0X(?i:{secret})",
                            *(f"{head}(?i:{secret[2:]})" for head in sorted(heads))]:
                if pattern not in out:
                    out.append(pattern)
        return out
