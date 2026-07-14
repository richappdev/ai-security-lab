"""Cancellable bulk known-route existence check for allowlisted lab targets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable, Sequence
from urllib.error import HTTPError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

from safety.audit_log import append_audit_record, utc_now_iso
from safety.cancellation import CancellationToken, JobCancelledError
from safety.policy import PolicyError, resolve_execution_limits
from safety.rate_limit import RateLimiter
from safety.scope_guard import ScopeError, check_target_allowed


TOOL_NAME = "lab_bulk_route_exists_check"
RISK = "active-low-risk"

# Fixed known DVWA / Juice Shop paths only — not open crawling.
KNOWN_LAB_ROUTE_PATHS: tuple[str, ...] = (
    "/",
    "/login",
    "/login.php",
    "/index.php",
    "/setup.php",
    "/security.php",
    "/ftp",
    "/api/Challenges",
    "/rest/products/search?q=",
    "/vulnerabilities/sqli/",
)


def _header_mapping(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if hasattr(headers, "items"):
        return {str(name): str(value) for name, value in headers.items()}
    return {}


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


def _resolve_route_paths(route_paths: Sequence[str] | None) -> tuple[str, ...]:
    if route_paths is None:
        return KNOWN_LAB_ROUTE_PATHS

    resolved: list[str] = []
    seen: set[str] = set()
    allowed = set(KNOWN_LAB_ROUTE_PATHS)
    for raw in route_paths:
        path = raw.strip()
        if path not in allowed:
            raise ScopeError(
                f"route_path is not in the fixed known lab list: {path}"
            )
        if path in seen:
            continue
        seen.add(path)
        resolved.append(path)

    if not resolved:
        raise ScopeError("route_paths must include at least one known lab path")
    return tuple(resolved)


def _probe_route(
    *,
    route_url: str,
    route_path: str,
    timeout_seconds: int,
    opener: Callable[..., Any],
) -> dict[str, Any]:
    request = Request(
        route_url,
        headers={"User-Agent": "ai-security-lab/lab-bulk-route-exists-check"},
        method="HEAD",
    )
    try:
        response_context = opener(request, timeout=timeout_seconds)
    except HTTPError as exc:
        response_context = exc
    with response_context as response:
        http_status = getattr(response, "status", None) or getattr(response, "code", None)
        headers = _header_mapping(getattr(response, "headers", None))

    exists = http_status is not None and 200 <= http_status < 400
    return {
        "route_path": route_path,
        "route_url": route_url,
        "http_status": http_status,
        "exists": exists,
        "headers": headers,
        "status": "completed",
        "error": None,
    }


def lab_bulk_route_exists_check(
    target: str,
    operator: str,
    run_id: str,
    timeout_seconds: int | None = None,
    rate_limit_per_minute: int | None = None,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
    cancellation_token: CancellationToken | None = None,
    route_paths: Sequence[str] | None = None,
) -> dict[str, Any]:
    """
    Send one HEAD request per fixed known lab route path.

    Checks the cancellation token before each request. Raises JobCancelledError
    when cancellation is requested so the job registry can mark the job cancelled.
    """

    started_at = utc_now_iso()
    token = cancellation_token or CancellationToken()
    route_results: list[dict[str, Any]] = []

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
        selected_paths = _resolve_route_paths(route_paths)
        route_urls = {path: _build_route_url(normalized_target, path) for path in selected_paths}
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
            "risk": RISK,
            "status": "rejected",
            "route_paths": list(route_paths) if route_paths is not None else list(KNOWN_LAB_ROUTE_PATHS),
            "checked": 0,
            "exists_count": 0,
            "missing_count": 0,
            "routes": [],
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
            "result_summary": (
                f"bulk route existence check started for {len(selected_paths)} known path(s)"
            ),
        },
        repo_root=repo_root,
    )

    status = "completed"
    findings: list[dict[str, str]] = []
    limiter = RateLimiter(limits.rate_limit_per_minute)

    try:
        for route_path in selected_paths:
            token.raise_if_cancelled()
            limiter.wait()
            token.raise_if_cancelled()
            try:
                probe = _probe_route(
                    route_url=route_urls[route_path],
                    route_path=route_path,
                    timeout_seconds=limits.timeout_seconds,
                    opener=opener,
                )
            except Exception as exc:  # noqa: BLE001 - capture per-route network failures
                probe = {
                    "route_path": route_path,
                    "route_url": route_urls[route_path],
                    "http_status": None,
                    "exists": False,
                    "headers": {},
                    "status": "failed",
                    "error": str(exc),
                }
                findings.append(
                    {
                        "id": "request_failed",
                        "severity": "error",
                        "evidence": f"HEAD {route_path} failed: {exc}",
                    }
                )
                status = "failed"
            route_results.append(probe)
            if probe.get("status") == "completed":
                finding_id = "route_exists" if probe["exists"] else "route_not_found"
                findings.append(
                    {
                        "id": finding_id,
                        "severity": "info",
                        "evidence": (
                            f"HEAD {route_path} returned HTTP {probe['http_status']}."
                        ),
                    }
                )
    except JobCancelledError as exc:
        ended_at = utc_now_iso()
        exists_count = sum(1 for item in route_results if item.get("exists"))
        missing_count = sum(
            1
            for item in route_results
            if item.get("status") == "completed" and not item.get("exists")
        )
        partial = {
            "tool": TOOL_NAME,
            "target": normalized_target,
            "risk": RISK,
            "status": "cancelled",
            "route_paths": list(selected_paths),
            "checked": len(route_results),
            "exists_count": exists_count,
            "missing_count": missing_count,
            "routes": route_results,
            "findings": findings
            + [
                {
                    "id": "job_cancelled",
                    "severity": "info",
                    "evidence": (
                        f"Cancellation requested after {len(route_results)} of "
                        f"{len(selected_paths)} route check(s)."
                    ),
                }
            ],
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
                "status": "cancelled",
                "result_summary": (
                    f"cancelled after {len(route_results)}/{len(selected_paths)} route(s)"
                ),
            },
            repo_root=repo_root,
        )
        raise JobCancelledError(str(exc), result=partial) from exc

    exists_count = sum(1 for item in route_results if item.get("exists"))
    missing_count = sum(
        1
        for item in route_results
        if item.get("status") == "completed" and not item.get("exists")
    )
    ended_at = utc_now_iso()
    result = {
        "tool": TOOL_NAME,
        "target": normalized_target,
        "risk": RISK,
        "status": status,
        "route_paths": list(selected_paths),
        "checked": len(route_results),
        "exists_count": exists_count,
        "missing_count": missing_count,
        "routes": route_results,
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
            "result_summary": (
                f"checked={len(route_results)}, exists={exists_count}, "
                f"missing={missing_count}, {len(findings)} finding(s)"
            ),
        },
        repo_root=repo_root,
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run a cancellable HEAD bulk route existence check against fixed known "
            "lab paths on an allowlisted target."
        )
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--operator", default="local-user")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=None)
    parser.add_argument("--rate-limit-per-minute", type=int, default=None)
    args = parser.parse_args()

    result = lab_bulk_route_exists_check(
        target=args.target,
        operator=args.operator,
        run_id=args.run_id,
        timeout_seconds=args.timeout_seconds,
        rate_limit_per_minute=args.rate_limit_per_minute,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
