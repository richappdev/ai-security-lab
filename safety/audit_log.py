"""Append-only JSONL audit logging for tool calls."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any


AUDIT_FILE = "audit.jsonl"


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def append_audit_record(record: dict[str, Any], repo_root: str | Path | None = None, output_directory: str = "logs") -> Path:
    root = Path(repo_root).resolve() if repo_root is not None else Path(__file__).resolve().parents[1]
    log_dir = root / output_directory
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / AUDIT_FILE

    normalized_record = dict(record)
    normalized_record.setdefault("recorded_at", utc_now_iso())

    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(normalized_record, sort_keys=True) + "\n")

    return log_path
