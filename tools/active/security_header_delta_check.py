"""Low-risk security header delta check for allowlisted lab routes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

from safety.audit_log import append_audit_record, utc_now_iso
from safety.policy import PolicyError, resolve_execution_limits
from safety.rate_limit import RateLimiter
from safety.scope_guard import ScopeError, check_target_allowed


TOOL_NAME = "lab_security_header_delta_check"
RISK = "active-low-risk"
SECURITY_HEADERS = (
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security",
)


def _header_mapping(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if hasattr(headers, "items"):
        return {str(name): str(value) for name, value in headers.items()}
    return {}


def _canonical_header_lookup(headers: dict[str, str]) -> dict[str, tuple[str, str]]:
    return {name.lower(): (name, value) for name, value in headers.items()}


def _build_route_url(normalized_target: str, route_path: str) -> str:
    parsed_route = urlparse(route_path.strip())
    if parsed_route.scheme or parsed_route.netloc:
        raise ScopeError("route_path must be a relative path, not a full URL")
    if not route_path.strip().startswith("/"):
        raise ScopeError("route_path must start with /")
    if parsed_route.fragment:
        raise ScopeError("route_path must not include a fragment")
    if ".." in [segment for segment in parsed_route.path.split("/") if segment]:
        raise ScopeError("route_path must not contain parent-directory segments")

    parsed_target = urlparse(normalized_target)
    return urlunparse(
        (
            parsed_target.scheme,
            parsed_target.netloc,
            parsed_route.path or "/",
            "",
            parsed_route.query,
            "",
        )
    )


def _fetch_headers(
    url: str,
    timeout_seconds: int,
    opener: Callable[..., Any],
) -> tuple[int | None, dict[str, str]]:
    request = Request(
        url,
        headers={"User-Agent": "ai-security-lab/lab-security-header-delta-check"},
        method="GET",
    )
    try:
        response_context = opener(request, timeout=timeout_seconds)
    except HTTPError as exc:
        response_context = exc

    with response_context as response:
        http_status = getattr(response, "status", None) or getattr(response, "code", None)
        headers = _header_mapping(getattr(response, "headers", None))
    return http_status, headers


def _compare_security_headers(
    root_headers: dict[str, str],
    route_headers: dict[str, str],
) -> tuple[list[dict[str, str | None]], list[dict[str, str]]]:
    root_lookup = _canonical_header_lookup(root_headers)
    route_lookup = _canonical_header_lookup(route_headers)
    delta: list[dict[str, str | None]] = []
    findings: list[dict[str, str]] = []

    for header in SECURITY_HEADERS:
        header_key = header.lower()
        root_entry = root_lookup.get(header_key)
        route_entry = route_lookup.get(header_key)
        root_value = root_entry[1] if root_entry else None
        route_value = route_entry[1] if route_entry else None

        if root_value is not None and route_value is None:
            delta.append(
                {
                    "header": header,
                    "type": "missing_on_route",
                    "root_value": root_value,
                    "route_value": None,
                }
            )
            findings.append(
                {
                    "id": "route_missing_security_header",
                    "severity": "info",
                    "evidence": f"{header} is present at root but missing on the route.",
                }
            )
        elif root_value is not None and route_value is not None and root_value != route_value:
            delta.append(
                {
                    "header": header,
                    "type": "changed_on_route",
                    "root_value": root_value,
                    "route_value": route_value,
                }
            )
            findings.append(
                {
                    "id": "route_changed_security_header",
                    "severity": "info",
                    "evidence": f"{header} differs between root and route.",
                }
            )
        elif root_value is None and route_value is not None:
            delta.append(
                {
                    "header": header,
                    "type": "added_on_route",
                    "root_value": None,
                    "route_value": route_value,
                }
            )
            findings.append(
                {
                    "id": "route_adds_security_header",
                    "severity": "info",
                    "evidence": f"{header} is missing at root but present on the route.",
                }
            )

    if not findings:
        findings.append(
            {
                "id": "security_headers_consistent",
                "severity": "info",
                "evidence": "Tracked security headers are consistent between root and route.",
            }
        )

    return delta, findings


def lab_security_header_delta_check(
    target: str,
    route_path: str,
    operator: str,
    run_id: str,
    timeout_seconds: int | None = None,
    rate_limit_per_minute: int | None = None,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
) -> dict[str, Any]:
    started_at = utc_now_iso()

    try:
        limits = resolve_execution_limits(
            requested_timeout_seconds=timeout_seconds,
            requested_rate_limit_per_minute=rate_limit_per_minute,
            repo_root=repo_root,
        )
        decision = check_target_allowed(target, repo_root)
        normalized_target = decision.normalized_target
        if not decision.allowed:
            raise ScopeError(decision.reason)
        route_url = _build_route_url(normalized_target, route_path)
    except (PolicyError, ScopeError) as exc:
        ended_at = utc_now_iso()
        finding_id = "policy_rejected" if isinstance(exc, PolicyError) else "target_rejected"
        append_audit_record(
            {
                "run_id": run_id,
                "operator": operator,
                "tool": TOOL_NAME,
                "target": target,
                "risk": RISK,
                "started_at": started_at,
                "ended_at": ended_at,
                "status": "rejected",
                "result_summary": str(exc),
            },
            repo_root=repo_root,
        )
        return {
            "tool": TOOL_NAME,
            "target": target,
            "route_path": route_path,
            "route_url": None,
            "risk": RISK,
            "status": "rejected",
            "http_status": None,
            "root_http_status": None,
            "route_http_status": None,
            "root_headers": {},
            "route_headers": {},
            "headers": {},
            "delta": [],
            "findings": [{"id": finding_id, "severity": "error", "evidence": str(exc)}],
            "started_at": started_at,
            "ended_at": ended_at,
        }

    append_audit_record(
        {
            "run_id": run_id,
            "operator": operator,
            "tool": TOOL_NAME,
            "target": normalized_target,
            "risk": RISK,
            "started_at": started_at,
            "ended_at": None,
            "status": "started",
            "result_summary": f"security header delta check started for {route_path}",
        },
        repo_root=repo_root,
    )

    status = "completed"
    findings: list[dict[str, str]] = []
    delta: list[dict[str, str | None]] = []
    root_headers: dict[str, str] = {}
    route_headers: dict[str, str] = {}
    root_http_status: int | None = None
    route_http_status: int | None = None

    try:
        limiter = RateLimiter(limits.rate_limit_per_minute)
        limiter.wait()
        root_http_status, root_headers = _fetch_headers(
            normalized_target,
            timeout_seconds=limits.timeout_seconds,
            opener=opener,
        )
        limiter.wait()
        route_http_status, route_headers = _fetch_headers(
            route_url,
            timeout_seconds=limits.timeout_seconds,
            opener=opener,
        )
        delta, findings = _compare_security_headers(root_headers, route_headers)
    except Exception as exc:
        status = "failed"
        findings.append({"id": "request_failed", "severity": "error", "evidence": str(exc)})

    ended_at = utc_now_iso()
    result = {
        "tool": TOOL_NAME,
        "target": normalized_target,
        "route_path": route_path,
        "route_url": route_url,
        "risk": RISK,
        "status": status,
        "http_status": route_http_status,
        "root_http_status": root_http_status,
        "route_http_status": route_http_status,
        "root_headers": root_headers,
        "route_headers": route_headers,
        "headers": route_headers,
        "delta": delta,
        "findings": findings,
        "started_at": started_at,
        "ended_at": ended_at,
    }

    append_audit_record(
        {
            "run_id": run_id,
            "operator": operator,
            "tool": TOOL_NAME,
            "target": normalized_target,
            "risk": RISK,
            "started_at": started_at,
            "ended_at": ended_at,
            "status": status,
            "result_summary": f"route_path={route_path}, delta={len(delta)}, {len(findings)} finding(s)",
        },
        repo_root=repo_root,
    )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a low-risk security header delta check against an allowlisted lab route."
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--route-path", required=True)
    parser.add_argument("--operator", default="local-user")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=None)
    parser.add_argument("--rate-limit-per-minute", type=int, default=None)
    args = parser.parse_args()

    result = lab_security_header_delta_check(
        target=args.target,
        route_path=args.route_path,
        operator=args.operator,
        run_id=args.run_id,
        timeout_seconds=args.timeout_seconds,
        rate_limit_per_minute=args.rate_limit_per_minute,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
