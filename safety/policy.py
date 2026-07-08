"""Policy loading and execution limit helpers for lab tools."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    """Raised when policy configuration or requested limits are invalid."""


@dataclass(frozen=True)
class ExecutionLimits:
    default_timeout_seconds: int
    max_timeout_seconds: int
    max_requests_per_minute: int
    max_same_origin_pages: int


@dataclass(frozen=True)
class SafetyPolicy:
    version: int
    scope: dict[str, Any]
    limits: ExecutionLimits
    allowed_activity: tuple[str, ...]
    blocked_activity: tuple[str, ...]
    audit: dict[str, Any]


@dataclass(frozen=True)
class ResolvedExecutionLimits:
    timeout_seconds: int
    rate_limit_per_minute: int


def _parse_scalar(value: str) -> Any:
    normalized = value.strip()
    if normalized.lower() == "true":
        return True
    if normalized.lower() == "false":
        return False
    try:
        return int(normalized)
    except ValueError:
        return normalized


def _parse_policy_yaml(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    section: str | None = None
    nested_key: str | None = None

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()

        if indent == 0:
            if ":" not in stripped:
                raise PolicyError(f"invalid policy line: {raw_line}")
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value:
                data[key] = _parse_scalar(value)
                section = None
            else:
                data[key] = {}
                section = key
            nested_key = None
            continue

        if section is None:
            raise PolicyError(f"policy line is outside a section: {raw_line}")

        if stripped.startswith("- "):
            if nested_key and isinstance(data.get(section), dict):
                data[section][nested_key].append(_parse_scalar(stripped[2:]))
            else:
                if not isinstance(data.get(section), list):
                    data[section] = []
                data[section].append(_parse_scalar(stripped[2:]))
            continue

        if ":" not in stripped:
            raise PolicyError(f"invalid policy line: {raw_line}")

        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        container = data.setdefault(section, {})

        if value:
            container[key] = _parse_scalar(value)
            nested_key = None
        else:
            container[key] = []
            nested_key = key

    return data


def _require_int(mapping: dict[str, Any], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int):
        raise PolicyError(f"policy value must be an integer: {key}")
    return value


def repo_root_from(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path).resolve()
    return Path(__file__).resolve().parents[1]


def load_policy(repo_root: str | Path | None = None, policy_file: str | Path = "safety/policy.yml") -> SafetyPolicy:
    root = repo_root_from(repo_root)
    policy_path = root / policy_file
    if not policy_path.exists():
        raise PolicyError(f"policy file is missing: {policy_path}")

    raw = _parse_policy_yaml(policy_path.read_text(encoding="utf-8"))
    limits = raw.get("limits")
    if not isinstance(limits, dict):
        raise PolicyError("policy limits section is missing")

    return SafetyPolicy(
        version=_require_int(raw, "version"),
        scope=dict(raw.get("scope") or {}),
        limits=ExecutionLimits(
            default_timeout_seconds=_require_int(limits, "default_timeout_seconds"),
            max_timeout_seconds=_require_int(limits, "max_timeout_seconds"),
            max_requests_per_minute=_require_int(limits, "max_requests_per_minute"),
            max_same_origin_pages=_require_int(limits, "max_same_origin_pages"),
        ),
        allowed_activity=tuple(raw.get("allowed_activity") or ()),
        blocked_activity=tuple(raw.get("blocked_activity") or ()),
        audit=dict(raw.get("audit") or {}),
    )


def resolve_execution_limits(
    *,
    requested_timeout_seconds: int | None,
    requested_rate_limit_per_minute: int | None,
    repo_root: str | Path | None = None,
) -> ResolvedExecutionLimits:
    policy = load_policy(repo_root)
    timeout_seconds = (
        requested_timeout_seconds
        if requested_timeout_seconds is not None
        else policy.limits.default_timeout_seconds
    )
    rate_limit_per_minute = (
        requested_rate_limit_per_minute
        if requested_rate_limit_per_minute is not None
        else policy.limits.max_requests_per_minute
    )

    if timeout_seconds < 1:
        raise PolicyError("timeout_seconds must be at least 1")
    if timeout_seconds > policy.limits.max_timeout_seconds:
        raise PolicyError(
            f"timeout_seconds exceeds policy maximum of {policy.limits.max_timeout_seconds}"
        )
    if rate_limit_per_minute < 1:
        raise PolicyError("rate_limit_per_minute must be at least 1")
    if rate_limit_per_minute > policy.limits.max_requests_per_minute:
        raise PolicyError(
            f"rate_limit_per_minute exceeds policy maximum of {policy.limits.max_requests_per_minute}"
        )

    return ResolvedExecutionLimits(
        timeout_seconds=timeout_seconds,
        rate_limit_per_minute=rate_limit_per_minute,
    )
