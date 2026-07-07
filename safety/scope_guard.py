"""Scope checks shared by lab tools before any network request."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse, urlunparse


class ScopeError(ValueError):
    """Raised when a target is outside the approved lab scope."""


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    normalized_target: str
    allowed: bool
    reason: str


LOCAL_HOSTNAMES = {"localhost"}
LOCAL_SUFFIXES = (".local",)


def repo_root_from(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path).resolve()
    return Path(__file__).resolve().parents[1]


def normalize_url(raw_url: str) -> str:
    parsed = urlparse(raw_url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ScopeError("target must use http or https")
    if not parsed.hostname:
        raise ScopeError("target must include a hostname")

    hostname = parsed.hostname.lower()
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"

    path = parsed.path or ""
    if path == "/":
        path = ""

    return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))


def load_allowlist(repo_root: str | Path | None = None, allowlist_file: str | Path = "targets.allowlist") -> set[str]:
    root = repo_root_from(repo_root)
    allowlist_path = root / allowlist_file
    if not allowlist_path.exists():
        raise ScopeError(f"allowlist file is missing: {allowlist_path}")

    allowed: set[str] = set()
    for line in allowlist_path.read_text(encoding="utf-8").splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        allowed.add(normalize_url(candidate))
    return allowed


def _host_is_local_lab(hostname: str) -> bool:
    host = hostname.lower()
    if host in LOCAL_HOSTNAMES or host.endswith(LOCAL_SUFFIXES):
        return True

    try:
        ip = ip_address(host)
    except ValueError:
        return False

    return ip.is_loopback


def check_target_allowed(target: str, repo_root: str | Path | None = None) -> ScopeDecision:
    normalized = normalize_url(target)
    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""

    if not _host_is_local_lab(hostname):
        return ScopeDecision(target, normalized, False, "target host is not a localhost or lab-local alias")

    allowed_targets = load_allowlist(repo_root)
    if normalized not in allowed_targets:
        return ScopeDecision(target, normalized, False, "target is not listed in targets.allowlist")

    return ScopeDecision(target, normalized, True, "target is allowlisted")


def require_target_allowed(target: str, repo_root: str | Path | None = None) -> ScopeDecision:
    decision = check_target_allowed(target, repo_root)
    if not decision.allowed:
        raise ScopeError(decision.reason)
    return decision
