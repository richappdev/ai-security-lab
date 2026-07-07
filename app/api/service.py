"""Service helpers that connect API requests to guarded tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
from urllib.request import urlopen
from uuid import uuid4

from tools.passive.headers import inspect_headers


DEFAULT_OPERATOR = "local-user"
DEFAULT_TIMEOUT_SECONDS = 10


def default_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def new_run_id() -> str:
    return f"run-{uuid4()}"


def run_passive_header_scan(
    target: str,
    operator: str = DEFAULT_OPERATOR,
    run_id: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
) -> dict[str, Any]:
    return inspect_headers(
        target=target,
        operator=operator or DEFAULT_OPERATOR,
        run_id=run_id or new_run_id(),
        timeout_seconds=timeout_seconds,
        repo_root=repo_root or default_repo_root(),
        opener=opener,
    )
