"""CI release-gate helpers (GitHub/GitLab check payloads)."""

from __future__ import annotations

from typing import Any

from domain import GateResult


def build_check_run_payload(
    *,
    suite_name: str,
    gate_result: str,
    failed_count: int,
    run_ids: list[str],
    evidence_uris: list[str],
) -> dict[str, Any]:
    conclusion = "success" if gate_result == GateResult.PASS.value else "failure"
    summary = (
        f"Suite `{suite_name}` {gate_result}. "
        f"failed_scenarios={failed_count}. runs={', '.join(run_ids) or 'none'}."
    )
    return {
        "name": f"agent-security/{suite_name}",
        "head_sha": None,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": f"Agent security suite: {gate_result}",
            "summary": summary,
            "text": "\n".join(f"- evidence: {u}" for u in evidence_uris) or "No evidence URIs",
        },
    }


def should_fail_release(gate_result: str, *, max_failed: int = 0, failed_count: int = 0) -> bool:
    if gate_result == GateResult.FAIL.value:
        return failed_count > max_failed
    return False
