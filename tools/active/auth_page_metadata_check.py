"""Low-risk authentication page metadata check for allowlisted lab routes."""

from __future__ import annotations

import argparse
import json
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

from safety.audit_log import append_audit_record, utc_now_iso
from safety.policy import PolicyError, resolve_execution_limits
from safety.rate_limit import RateLimiter
from safety.scope_guard import ScopeError, check_target_allowed


TOOL_NAME = "lab_auth_page_metadata_check"
RISK = "active-low-risk"
USERNAME_HINTS = ("user", "email", "login", "account")
CSRF_HINTS = ("csrf", "token", "nonce")


class AuthPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title_parts: list[str] = []
        self.forms: list[dict[str, str]] = []
        self.inputs: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "title":
            self.in_title = True
        elif tag.lower() == "form":
            self.forms.append(
                {
                    "method": attr_map.get("method", "get").upper() or "GET",
                    "action_present": "true" if attr_map.get("action") else "false",
                }
            )
        elif tag.lower() == "input":
            self.inputs.append(
                {
                    "type": attr_map.get("type", "text").lower() or "text",
                    "name": attr_map.get("name", "").lower(),
                    "id": attr_map.get("id", "").lower(),
                    "autocomplete": attr_map.get("autocomplete", "").lower(),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data.strip())

    @property
    def title(self) -> str:
        return " ".join(part for part in self.title_parts if part).strip()


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


def _contains_hint(value: str, hints: tuple[str, ...]) -> bool:
    return any(hint in value for hint in hints)


def _analyze_auth_page(body: str) -> dict[str, Any]:
    parser = AuthPageParser()
    parser.feed(body)

    password_fields = [field for field in parser.inputs if field["type"] == "password"]
    username_like_fields = [
        field
        for field in parser.inputs
        if field["type"] in {"text", "email"}
        and (_contains_hint(field["name"], USERNAME_HINTS) or _contains_hint(field["id"], USERNAME_HINTS))
    ]
    csrf_like_fields = [
        field
        for field in parser.inputs
        if _contains_hint(field["name"], CSRF_HINTS) or _contains_hint(field["id"], CSRF_HINTS)
    ]
    form_methods = sorted({form["method"] for form in parser.forms})
    input_types = sorted({field["type"] for field in parser.inputs})
    title_lower = parser.title.lower()
    has_login_indicators = bool(
        password_fields
        or username_like_fields
        or "login" in title_lower
        or "sign in" in title_lower
        or "authentication" in title_lower
    )

    return {
        "title": parser.title,
        "forms_count": len(parser.forms),
        "input_count": len(parser.inputs),
        "password_fields_count": len(password_fields),
        "username_like_fields_count": len(username_like_fields),
        "csrf_like_fields_count": len(csrf_like_fields),
        "form_methods": form_methods,
        "input_types": input_types,
        "has_login_indicators": has_login_indicators,
    }


def _findings_for_metadata(metadata: dict[str, Any], route_path: str) -> list[dict[str, str]]:
    if metadata["has_login_indicators"]:
        findings = [
            {
                "id": "auth_page_metadata_detected",
                "severity": "info",
                "evidence": f"GET {route_path} exposed authentication-page metadata without submitting a form.",
            }
        ]
    else:
        findings = [
            {
                "id": "auth_page_metadata_not_detected",
                "severity": "info",
                "evidence": f"GET {route_path} did not expose obvious authentication-page metadata.",
            }
        ]

    if metadata["forms_count"] > 0 and metadata["password_fields_count"] == 0:
        findings.append(
            {
                "id": "auth_form_without_password_field",
                "severity": "info",
                "evidence": "A form was present but no password input was detected.",
            }
        )
    return findings


def lab_auth_page_metadata_check(
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
            "headers": {},
            "metadata": {},
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
            "result_summary": f"auth page metadata check started for {route_path}",
        },
        repo_root=repo_root,
    )

    status = "completed"
    http_status: int | None = None
    headers: dict[str, str] = {}
    metadata: dict[str, Any] = {}
    findings: list[dict[str, str]] = []

    try:
        RateLimiter(limits.rate_limit_per_minute).wait()
        request = Request(
            route_url,
            headers={"User-Agent": "ai-security-lab/lab-auth-page-metadata-check"},
            method="GET",
        )
        try:
            response_context = opener(request, timeout=limits.timeout_seconds)
        except HTTPError as exc:
            response_context = exc
        with response_context as response:
            http_status = getattr(response, "status", None) or getattr(response, "code", None)
            headers = _header_mapping(getattr(response, "headers", None))
            body = response.read().decode("utf-8", errors="replace")
        metadata = _analyze_auth_page(body)
        findings = _findings_for_metadata(metadata, route_path)
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
        "headers": headers,
        "metadata": metadata,
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
                f"route_path={route_path}, forms={metadata.get('forms_count', 0)}, "
                f"password_fields={metadata.get('password_fields_count', 0)}, {len(findings)} finding(s)"
            ),
        },
        repo_root=repo_root,
    )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a low-risk GET-only authentication page metadata check against an allowlisted lab route."
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--route-path", required=True)
    parser.add_argument("--operator", default="local-user")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=None)
    parser.add_argument("--rate-limit-per-minute", type=int, default=None)
    args = parser.parse_args()

    result = lab_auth_page_metadata_check(
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
