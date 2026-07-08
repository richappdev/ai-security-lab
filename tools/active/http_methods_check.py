"""Low-risk HTTP method check for allowlisted lab targets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable
from urllib.request import Request, urlopen

from safety.audit_log import append_audit_record, utc_now_iso
from safety.policy import PolicyError, resolve_execution_limits
from safety.rate_limit import RateLimiter
from safety.scope_guard import ScopeError, check_target_allowed


TOOL_NAME = "lab_http_methods_check"
RISK = "active-low-risk"
RISKY_METHODS = {"DELETE", "PUT", "TRACE"}


def _header_mapping(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if hasattr(headers, "items"):
        return {str(name): str(value) for name, value in headers.items()}
    return {}


def _parse_allow_header(value: str | None) -> list[str]:
    if not value:
        return []
    return sorted({method.strip().upper() for method in value.split(",") if method.strip()})


def lab_http_methods_check(
    target: str,
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
    except (PolicyError, ScopeError) as exc:
        ended_at = utc_now_iso()
        finding_id = "target_rejected" if isinstance(exc, ScopeError) else "policy_rejected"
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
            "http_status": None,
            "allowed_methods": [],
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
            "result_summary": "HTTP method check started",
        },
        repo_root=repo_root,
    )

    status = "completed"
    findings: list[dict[str, str]] = []
    http_status: int | None = None
    headers: dict[str, str] = {}
    allowed_methods: list[str] = []

    try:
        RateLimiter(limits.rate_limit_per_minute).wait()
        request = Request(
            normalized_target,
            headers={"User-Agent": "ai-security-lab/lab-http-methods-check"},
            method="OPTIONS",
        )
        with opener(request, timeout=limits.timeout_seconds) as response:
            http_status = getattr(response, "status", None)
            headers = _header_mapping(getattr(response, "headers", None))
        allow_value = headers.get("Allow") or headers.get("allow")
        allowed_methods = _parse_allow_header(allow_value)
        risky_methods = sorted(RISKY_METHODS.intersection(allowed_methods))
        if risky_methods:
            findings.append(
                {
                    "id": "risky_methods_allowed",
                    "severity": "medium",
                    "evidence": f"OPTIONS reported potentially risky methods: {', '.join(risky_methods)}.",
                }
            )
        elif allowed_methods:
            findings.append(
                {
                    "id": "methods_reported",
                    "severity": "info",
                    "evidence": f"OPTIONS reported allowed methods: {', '.join(allowed_methods)}.",
                }
            )
        else:
            findings.append(
                {
                    "id": "allow_header_missing",
                    "severity": "info",
                    "evidence": "OPTIONS did not include an Allow header.",
                }
            )
    except Exception as exc:
        status = "failed"
        findings.append({"id": "request_failed", "severity": "error", "evidence": str(exc)})

    ended_at = utc_now_iso()
    result = {
        "tool": TOOL_NAME,
        "target": normalized_target,
        "risk": RISK,
        "status": status,
        "http_status": http_status,
        "allowed_methods": allowed_methods,
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
            "result_summary": f"allowed_methods={','.join(allowed_methods) or 'unknown'}, {len(findings)} finding(s)",
        },
        repo_root=repo_root,
    )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a low-risk HTTP OPTIONS method check against an allowlisted lab target."
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--operator", default="local-user")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=None)
    parser.add_argument("--rate-limit-per-minute", type=int, default=None)
    args = parser.parse_args()

    result = lab_http_methods_check(
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
