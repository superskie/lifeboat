"""Plans, jobs and receipts as JSON files under the plugin data directory. No keys here."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

_ID = re.compile(r"^[a-z0-9-]{4,64}$")


class NotFound(KeyError):
    pass


class Store:
    def __init__(self, data_dir: Path) -> None:
        self.root = Path(data_dir)

    def _path(self, kind: str, item_id: str) -> Path:
        if not _ID.fullmatch(item_id or ""):
            raise NotFound(f"invalid {kind} id: {item_id!r}")
        return self.root / kind / f"{item_id}.json"

    def _write(self, kind: str, item_id: str, doc: dict) -> None:
        path = self._path(kind, item_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)

    def _read(self, kind: str, item_id: str) -> dict:
        path = self._path(kind, item_id)
        if not path.exists():
            raise NotFound(f"no {kind[:-1]} with id {item_id}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _all(self, kind: str) -> list[dict]:
        folder = self.root / kind
        if not folder.exists():
            return []
        docs = [json.loads(p.read_text(encoding="utf-8")) for p in folder.glob("*.json")]
        return sorted(docs, key=lambda d: d.get("created_at", 0))

    def save_plan(self, plan) -> None:
        self._write("plans", plan.id, plan.to_dict())

    def load_plan(self, plan_id: str):
        from .plan import Plan

        return Plan.from_dict(self._read("plans", plan_id))

    def plans(self) -> list:
        from .plan import Plan

        return [Plan.from_dict(d) for d in self._all("plans")]

    def save_job(self, job_id: str, doc: dict) -> None:
        self._write("jobs", job_id, doc)

    def load_job(self, job_id: str) -> dict:
        return self._read("jobs", job_id)

    def jobs(self) -> list[dict]:
        return self._all("jobs")

    def save_receipt(self, receipt_id: str, doc: dict) -> None:
        self._write("receipts", receipt_id, doc)

    def receipts(self) -> list[dict]:
        return self._all("receipts")

    def save_meta(self, name: str, doc: dict) -> None:
        self._write("meta", name, doc)

    def load_meta(self, name: str) -> dict:
        try:
            return self._read("meta", name)
        except NotFound:
            return {}
