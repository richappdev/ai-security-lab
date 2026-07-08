"""Passive form discovery for allowlisted lab targets."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from safety.audit_log import append_audit_record, utc_now_iso
from safety.scope_guard import ScopeError, check_target_allowed


TOOL_NAME = "discover_forms"
RISK = "passive"


class FormParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value for name, value in attrs}
        tag_name = tag.lower()

        if tag_name == "form":
            method = (attributes.get("method") or "GET").upper()
            raw_action = attributes.get("action") or self.page_url
            action = urljoin(self.page_url, raw_action)
            self._current_form = {
                "method": method,
                "action": action,
                "inputs": [],
                "same_origin": _same_origin(self.page_url, action),
            }
            return

        if self._current_form is None:
            return

        if tag_name == "input":
            self._current_form["inputs"].append(
                {
                    "name": attributes.get("name"),
                    "type": (attributes.get("type") or "text").lower(),
                }
            )
        elif tag_name in {"textarea", "select"}:
            self._current_form["inputs"].append(
                {
                    "name": attributes.get("name"),
                    "type": tag_name,
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def close(self) -> None:
        super().close()
        if self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _same_origin(page_url: str, action_url: str) -> bool:
    page = urlparse(page_url)
    action = urlparse(action_url)
    return (page.scheme, page.netloc) == (action.scheme, action.netloc)


def _decode_response_body(response: Any) -> str:
    body = response.read()
    if isinstance(body, str):
        return body

    charset = "utf-8"
    headers = getattr(response, "headers", None)
    if headers is not None and hasattr(headers, "get_content_charset"):
        charset = headers.get_content_charset() or charset
    return body.decode(charset, errors="replace")


def _parse_forms(page_url: str, html: str) -> list[dict[str, Any]]:
    parser = FormParser(page_url)
    parser.feed(html)
    parser.close()
    return parser.forms


def _form_findings(forms: list[dict[str, Any]]) -> list[dict[str, str]]:
    if not forms:
        return [{"id": "no_forms_observed", "severity": "info", "evidence": "No forms were observed on the page."}]

    findings: list[dict[str, str]] = []
    for form in forms:
        if not form["same_origin"]:
            findings.append(
                {
                    "id": "cross_origin_form_action",
                    "severity": "info",
                    "evidence": f"Form action points to a different origin: {form['action']}",
                }
            )
    return findings


def discover_forms(
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
            "forms": [],
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
            "result_summary": "form discovery started",
        },
        repo_root=repo_root,
    )

    status = "completed"
    forms: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    http_status: int | None = None

    try:
        request = Request(normalized_target, headers={"User-Agent": "ai-security-lab/discover-forms"})
        with opener(request, timeout=timeout_seconds) as response:
            http_status = getattr(response, "status", None)
            forms = _parse_forms(normalized_target, _decode_response_body(response))
        findings = _form_findings(forms)
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
        "forms": forms,
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
            "result_summary": f"{len(forms)} form(s), {len(findings)} finding(s)",
        },
        repo_root=repo_root,
    )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover forms on an allowlisted lab target without submitting them.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--operator", default="local-user")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    args = parser.parse_args()

    result = discover_forms(
        target=args.target,
        operator=args.operator,
        run_id=args.run_id,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
