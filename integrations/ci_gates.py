"""CI release-gate helpers and GitHub/GitLab publishers."""

from __future__ import annotations

import os
from typing import Any

import httpx

from domain import GateResult


def build_check_run_payload(
    *,
    suite_name: str,
    gate_result: str,
    failed_count: int,
    run_ids: list[str],
    evidence_uris: list[str],
    head_sha: str | None = None,
) -> dict[str, Any]:
    conclusion = "success" if gate_result == GateResult.PASS.value else "failure"
    summary = (
        f"Suite `{suite_name}` {gate_result}. "
        f"failed_scenarios={failed_count}. runs={', '.join(run_ids) or 'none'}."
    )
    return {
        "name": f"agent-security/{suite_name}",
        "head_sha": head_sha,
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


def build_gitlab_status_payload(
    *,
    suite_name: str,
    gate_result: str,
    target_url: str | None = None,
) -> dict[str, Any]:
    state = "success" if gate_result == GateResult.PASS.value else "failed"
    return {
        "state": state,
        "name": f"agent-security/{suite_name}",
        "description": f"Agent security suite {gate_result}",
        "target_url": target_url,
    }


def publish_github_check_run(
    payload: dict[str, Any],
    *,
    owner: str | None = None,
    repo: str | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """POST a GitHub check run when credentials are configured; otherwise dry-run."""
    owner = owner or os.environ.get("GITHUB_OWNER")
    repo = repo or os.environ.get("GITHUB_REPO")
    token = token or os.environ.get("GITHUB_TOKEN")
    if not (owner and repo and token and payload.get("head_sha")):
        return {"published": False, "dry_run": True, "payload": payload}
    url = f"https://api.github.com/repos/{owner}/{repo}/check-runs"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    response = httpx.post(url, headers=headers, json=payload, timeout=30.0)
    return {
        "published": response.is_success,
        "status_code": response.status_code,
        "body": response.json() if response.content else {},
    }


def publish_gitlab_commit_status(
    payload: dict[str, Any],
    *,
    project_id: str | None = None,
    sha: str | None = None,
    token: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    project_id = project_id or os.environ.get("GITLAB_PROJECT_ID")
    token = token or os.environ.get("GITLAB_TOKEN")
    base_url = (base_url or os.environ.get("GITLAB_BASE_URL", "https://gitlab.com")).rstrip("/")
    if not (project_id and token and sha):
        return {"published": False, "dry_run": True, "payload": payload}
    url = f"{base_url}/api/v4/projects/{project_id}/statuses/{sha}"
    response = httpx.post(
        url,
        headers={"PRIVATE-TOKEN": token},
        data={k: v for k, v in payload.items() if v is not None},
        timeout=30.0,
    )
    return {
        "published": response.is_success,
        "status_code": response.status_code,
        "body": response.json() if response.content else {},
    }
