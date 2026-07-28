"""Schema-aware recursive redaction for events and evidence."""

from __future__ import annotations

import os
import re
from copy import deepcopy
from typing import Any

DEFAULT_SENSITIVE_FIELDS = {
    "authorization",
    "api_key",
    "apikey",
    "password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "cookie",
    "set-cookie",
}
SECRET_PATTERNS = (
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\b(?:sk|ghp|glpat)-[A-Za-z0-9_-]{8,}\b"),
)
REDACTED = "[REDACTED]"


class UnredactedSecretError(ValueError):
    """Raised when a configured seeded secret remains after redaction."""


def sensitive_fields() -> set[str]:
    configured = {
        item.strip().lower()
        for item in os.environ.get("EVIDENCE_SENSITIVE_FIELDS", "").split(",")
        if item.strip()
    }
    return DEFAULT_SENSITIVE_FIELDS | configured


def _redact_string(value: str) -> str:
    result = value
    for pattern in SECRET_PATTERNS:
        result = pattern.sub(lambda match: f"{match.group(1)} {REDACTED}" if match.lastindex else REDACTED, result)
    for secret in (
        item for item in os.environ.get("EVIDENCE_SEEDED_SECRETS", "").split(",") if item
    ):
        result = result.replace(secret, REDACTED)
    return result


def redact_value(value: Any, *, parent_key: str | None = None) -> Any:
    if parent_key and parent_key.lower() in sensitive_fields():
        return REDACTED
    if isinstance(value, dict):
        return {key: redact_value(item, parent_key=str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item, parent_key=parent_key) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return deepcopy(value)


def redact_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    redacted = [redact_value(event) for event in events]
    encoded = repr(redacted)
    leaked = [
        secret
        for secret in os.environ.get("EVIDENCE_SEEDED_SECRETS", "").split(",")
        if secret and secret in encoded
    ]
    if leaked:
        raise UnredactedSecretError("seeded secret remained after redaction")
    return redacted
