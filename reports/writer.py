"""Markdown report writer for guarded lab tool results."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from safety.audit_log import utc_now_iso


DEFAULT_OUTPUT_DIRECTORY = "reports"
REPORT_FORMAT = "markdown"


def _repo_root(repo_root: str | Path | None = None) -> Path:
    if repo_root is not None:
        return Path(repo_root).resolve()
    return Path(__file__).resolve().parents[1]


def _slug(value: str, fallback: str = "scan") -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower()).strip("-._")
    return cleaned[:80] or fallback


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _finding_rows(findings: list[dict[str, Any]]) -> list[str]:
    if not findings:
        return ["| none | none | No findings were reported. |"]

    rows = []
    for finding in findings:
        rows.append(
            "| {id} | {severity} | {evidence} |".format(
                id=_cell(finding.get("id", "unknown")),
                severity=_cell(finding.get("severity", "unknown")),
                evidence=_cell(finding.get("evidence", "")),
            )
        )
    return rows


def _header_rows(headers: dict[str, Any]) -> list[str]:
    if not headers:
        return ["| none | No response headers were captured. |"]

    return [f"| {_cell(name)} | {_cell(value)} |" for name, value in sorted(headers.items())]


def render_markdown_report(
    tool_result: dict[str, Any],
    operator: str,
    run_id: str,
    generated_at: str | None = None,
) -> str:
    generated = generated_at or utc_now_iso()
    findings = tool_result.get("findings") or []
    headers = tool_result.get("headers") or {}

    lines = [
        "# Security Lab Scan Report",
        "",
        "## Summary",
        "",
        f"- Run ID: `{run_id}`",
        f"- Operator: `{operator}`",
        f"- Generated at: `{generated}`",
        f"- Tool: `{tool_result.get('tool', 'unknown')}`",
        f"- Risk level: `{tool_result.get('risk', 'unknown')}`",
        f"- Status: `{tool_result.get('status', 'unknown')}`",
        f"- Target: `{tool_result.get('target', 'unknown')}`",
        f"- HTTP status: `{tool_result.get('http_status', 'n/a')}`",
        f"- Started at: `{tool_result.get('started_at', 'unknown')}`",
        f"- Ended at: `{tool_result.get('ended_at', 'unknown')}`",
        "",
        "## Findings",
        "",
        "| ID | Severity | Evidence |",
        "| --- | --- | --- |",
        *_finding_rows(findings),
        "",
        "## Evidence",
        "",
        "| Header | Value |",
        "| --- | --- |",
        *_header_rows(headers),
        "",
        "## Remediation Notes",
        "",
        "- Review missing security headers and add them where appropriate for the target application.",
        "- Confirm findings manually before treating them as vulnerabilities.",
        "- Keep follow-up testing limited to explicitly allowlisted lab targets.",
        "",
        "## Test Limitations",
        "",
        "- This report is generated for a local, authorized lab environment only.",
        "- Passive results describe observed responses and do not prove exploitability.",
        "- No public, third-party, school, government, or company systems are in scope.",
        "",
    ]
    return "\n".join(lines)


def write_markdown_report(
    tool_result: dict[str, Any],
    operator: str,
    run_id: str,
    repo_root: str | Path | None = None,
    output_directory: str = DEFAULT_OUTPUT_DIRECTORY,
) -> dict[str, str]:
    root = _repo_root(repo_root)
    output_dir = root / output_directory
    output_dir.mkdir(parents=True, exist_ok=True)

    generated_at = utc_now_iso()
    tool = _slug(str(tool_result.get("tool", "tool")), "tool")
    filename = f"{_slug(run_id, 'run')}-{tool}.md"
    report_path = output_dir / filename
    report_path.write_text(
        render_markdown_report(tool_result, operator=operator, run_id=run_id, generated_at=generated_at),
        encoding="utf-8",
    )

    return {
        "format": REPORT_FORMAT,
        "path": str(report_path),
        "filename": filename,
        "generated_at": generated_at,
    }
