"""Passive cookie attribute inspection for allowlisted lab targets."""

from __future__ import annotations

import argparse
from http.cookies import SimpleCookie
import json
from pathlib import Path
from typing import Any, Callable
from urllib.request import Request, urlopen

from safety.audit_log import append_audit_record, utc_now_iso
from safety.scope_guard import ScopeError, check_target_allowed


TOOL_NAME = "inspect_cookies"
RISK = "passive"
COOKIE_ATTRIBUTES = ("httponly", "secure", "samesite")


def _set_cookie_headers(response: Any) -> list[str]:
    headers = getattr(response, "headers", {})
    if hasattr(headers, "get_all"):
        values = headers.get_all("Set-Cookie")
        if values:
            return [str(value) for value in values]
    if hasattr(headers, "items"):
        return [str(value) for key, value in headers.items() if str(key).lower() == "set-cookie"]
    return []


def _parse_cookie_headers(header_values: list[str]) -> list[dict[str, Any]]:
    cookies: list[dict[str, Any]] = []
    for header_value in header_values:
        parsed = SimpleCookie()
        parsed.load(header_value)
        for morsel in parsed.values():
            cookies.append(
                {
                    "name": morsel.key,
                    "domain": morsel["domain"] or None,
                    "path": morsel["path"] or None,
                    "httponly": bool(morsel["httponly"]),
                    "secure": bool(morsel["secure"]),
                    "samesite": morsel["samesite"] or None,
                }
            )
    return cookies


def _cookie_findings(cookies: list[dict[str, Any]]) -> list[dict[str, str]]:
    if not cookies:
        return [{"id": "no_cookies_observed", "severity": "info", "evidence": "No Set-Cookie headers were observed."}]

    findings: list[dict[str, str]] = []
    for cookie in cookies:
        name = str(cookie["name"])
        for attribute in COOKIE_ATTRIBUTES:
            if not cookie.get(attribute):
                findings.append(
                    {
                        "id": "cookie_missing_attribute",
                        "severity": "info",
                        "evidence": f"{name} cookie did not declare {attribute}.",
                    }
                )
    return findings


def inspect_cookies(
    target: str,
    operator: str,
    run_id: str,
    timeout_seconds: int = 10,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
) -> dict[str, Any]:
    started_at = utc_now_iso()

    try:
        decision = check_target_allowed(target, repo_root)
        normalized_target = decision.normalized_target
        if not decision.allowed:
            raise ScopeError(decision.reason)
    except ScopeError as exc:
        ended_at = utc_now_iso()
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
            "cookies": [],
            "findings": [{"id": "target_rejected", "severity": "error", "evidence": str(exc)}],
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
            "result_summary": "cookie inspection started",
        },
        repo_root=repo_root,
    )

    status = "completed"
    cookies: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    http_status: int | None = None

    try:
        request = Request(normalized_target, headers={"User-Agent": "ai-security-lab/inspect-cookies"})
        with opener(request, timeout=timeout_seconds) as response:
            http_status = getattr(response, "status", None)
            cookies = _parse_cookie_headers(_set_cookie_headers(response))
        findings = _cookie_findings(cookies)
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
        "cookies": cookies,
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
            "result_summary": f"{len(findings)} finding(s)",
        },
        repo_root=repo_root,
    )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect cookie attributes for an allowlisted lab target.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--operator", default="local-user")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    args = parser.parse_args()

    result = inspect_cookies(
        target=args.target,
        operator=args.operator,
        run_id=args.run_id,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
