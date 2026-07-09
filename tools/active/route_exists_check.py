"""Low-risk single-route existence check for allowlisted lab targets."""

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


TOOL_NAME = "lab_route_exists_check"
RISK = "active-low-risk"


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


def lab_route_exists_check(
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
            "exists": False,
            "headers": {},
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
            "result_summary": f"route existence check started for {route_path}",
        },
        repo_root=repo_root,
    )

    status = "completed"
    findings: list[dict[str, str]] = []
    http_status: int | None = None
    headers: dict[str, str] = {}
    exists = False

    try:
        RateLimiter(limits.rate_limit_per_minute).wait()
        request = Request(
            route_url,
            headers={"User-Agent": "ai-security-lab/lab-route-exists-check"},
            method="HEAD",
        )
        try:
            response_context = opener(request, timeout=limits.timeout_seconds)
        except HTTPError as exc:
            response_context = exc
        with response_context as response:
            http_status = getattr(response, "status", None) or getattr(response, "code", None)
            headers = _header_mapping(getattr(response, "headers", None))

        exists = http_status is not None and 200 <= http_status < 400
        if exists:
            findings.append(
                {
                    "id": "route_exists",
                    "severity": "info",
                    "evidence": f"HEAD {route_path} returned HTTP {http_status}.",
                }
            )
        else:
            findings.append(
                {
                    "id": "route_not_found",
                    "severity": "info",
                    "evidence": f"HEAD {route_path} returned HTTP {http_status}.",
                }
            )
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
        "http_status": http_status,
        "exists": exists,
        "headers": headers,
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
            "result_summary": f"route_path={route_path}, exists={exists}, {len(findings)} finding(s)",
        },
        repo_root=repo_root,
    )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a low-risk HEAD route existence check against an allowlisted lab target."
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--route-path", required=True)
    parser.add_argument("--operator", default="local-user")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=None)
    parser.add_argument("--rate-limit-per-minute", type=int, default=None)
    args = parser.parse_args()

    result = lab_route_exists_check(
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
