"""Low-risk reflected-input check for allowlisted lab targets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from safety.audit_log import append_audit_record, utc_now_iso
from safety.policy import PolicyError, resolve_execution_limits
from safety.rate_limit import RateLimiter
from safety.scope_guard import ScopeError, check_target_allowed


TOOL_NAME = "lab_xss_reflection_check"
RISK = "active-low-risk"
DEFAULT_MARKER = "ai_security_lab_reflection_probe"


def _target_with_marker(target: str, marker: str) -> str:
    parsed = urlparse(target)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("codex_reflection_check", marker))
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            urlencode(query),
            "",
        )
    )


def _decode_response_body(response: Any) -> str:
    body = response.read()
    if isinstance(body, str):
        return body

    charset = "utf-8"
    headers = getattr(response, "headers", None)
    if headers is not None and hasattr(headers, "get_content_charset"):
        charset = headers.get_content_charset() or charset
    return body.decode(charset, errors="replace")


def lab_xss_reflection_check(
    target: str,
    operator: str,
    run_id: str,
    marker: str = DEFAULT_MARKER,
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
            "probe_url": None,
            "reflected": False,
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
            "result_summary": "reflected-input check started",
        },
        repo_root=repo_root,
    )

    status = "completed"
    findings: list[dict[str, str]] = []
    http_status: int | None = None
    reflected = False
    probe_url = _target_with_marker(normalized_target, marker)

    try:
        RateLimiter(limits.rate_limit_per_minute).wait()
        request = Request(probe_url, headers={"User-Agent": "ai-security-lab/lab-xss-reflection-check"})
        with opener(request, timeout=limits.timeout_seconds) as response:
            http_status = getattr(response, "status", None)
            body = _decode_response_body(response)
        reflected = marker in body
        if reflected:
            findings.append(
                {
                    "id": "input_reflected",
                    "severity": "low",
                    "evidence": "A harmless marker was reflected in the response body.",
                }
            )
        else:
            findings.append(
                {
                    "id": "input_not_reflected",
                    "severity": "info",
                    "evidence": "The harmless marker was not reflected in the response body.",
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
        "probe_url": probe_url,
        "reflected": reflected,
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
            "result_summary": f"reflected={reflected}, {len(findings)} finding(s)",
        },
        repo_root=repo_root,
    )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a harmless reflected-input check against an allowlisted lab target."
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--operator", default="local-user")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--marker", default=DEFAULT_MARKER)
    parser.add_argument("--timeout-seconds", type=int, default=None)
    parser.add_argument("--rate-limit-per-minute", type=int, default=None)
    args = parser.parse_args()

    result = lab_xss_reflection_check(
        target=args.target,
        operator=args.operator,
        run_id=args.run_id,
        marker=args.marker,
        timeout_seconds=args.timeout_seconds,
        rate_limit_per_minute=args.rate_limit_per_minute,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
