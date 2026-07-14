"""Execute validated agent plans through guarded service helpers only."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
from urllib.request import urlopen
from uuid import uuid4

from agents.planner import AgentPlan, PlanValidationError, PlannedTool, validate_plan
from app.api import service
from reports.writer import write_aggregate_markdown_report
from safety.audit_log import utc_now_iso


DEFAULT_OPERATOR = "local-user"


def _new_plan_id() -> str:
    return f"plan-{uuid4()}"


def _new_run_id() -> str:
    return f"run-{uuid4()}"


def _invoke_tool(
    planned: PlannedTool,
    *,
    target: str,
    operator: str,
    run_id: str,
    timeout_seconds: int,
    rate_limit_per_minute: int | None,
    repo_root: Path,
    opener: Callable[..., Any],
) -> dict[str, Any]:
    """Dispatch to service helpers — never call lab targets directly."""

    common = {
        "target": target,
        "operator": operator,
        "run_id": run_id,
        "timeout_seconds": timeout_seconds,
        "repo_root": repo_root,
        "opener": opener,
        "generate_report": False,
    }

    if planned.name == "inspect_headers":
        return service.run_passive_header_scan(**common)
    if planned.name == "inspect_cookies":
        return service.run_passive_cookie_scan(**common)
    if planned.name == "discover_forms":
        return service.run_passive_form_scan(**common)
    if planned.name == "lab_xss_reflection_check":
        return service.run_active_xss_reflection_scan(
            **common,
            rate_limit_per_minute=rate_limit_per_minute,
        )
    if planned.name == "lab_http_methods_check":
        return service.run_active_http_methods_scan(
            **common,
            rate_limit_per_minute=rate_limit_per_minute,
        )
    if planned.name == "lab_route_exists_check":
        return service.run_active_route_exists_scan(
            **common,
            route_path=str(planned.params["route_path"]),
            rate_limit_per_minute=rate_limit_per_minute,
        )
    if planned.name == "lab_security_header_delta_check":
        return service.run_active_security_header_delta_scan(
            **common,
            route_path=str(planned.params["route_path"]),
            rate_limit_per_minute=rate_limit_per_minute,
        )
    if planned.name == "lab_auth_page_metadata_check":
        return service.run_active_auth_page_metadata_scan(
            **common,
            route_path=str(planned.params["route_path"]),
            rate_limit_per_minute=rate_limit_per_minute,
        )
    if planned.name == "lab_bulk_route_exists_check":
        return service.run_active_bulk_route_exists_scan(
            **common,
            rate_limit_per_minute=rate_limit_per_minute,
        )

    raise PlanValidationError(f"no guarded service helper registered for tool: {planned.name}")


def execute_plan(
    plan: AgentPlan,
    *,
    repo_root: str | Path | None = None,
    opener: Callable[..., Any] = urlopen,
    generate_report: bool = True,
    stop_on_failure: bool = True,
    reorder_passive_first: bool = True,
) -> dict[str, Any]:
    """
    Run an agent plan by invoking existing service.py helpers only.

    Agents must never call lab targets directly. This bridge is the only
    orchestration path from a plan to tool execution.
    """

    root = Path(repo_root).resolve() if repo_root is not None else service.default_repo_root()
    validated = validate_plan(plan, repo_root=root, reorder_passive_first=reorder_passive_first)

    plan_id = _new_plan_id()
    run_id = validated.run_id or _new_run_id()
    operator = validated.operator or DEFAULT_OPERATOR
    started_at = utc_now_iso()
    results: list[dict[str, Any]] = []
    status = "completed"
    error: str | None = None

    for planned in validated.tools:
        try:
            tool_result = _invoke_tool(
                planned,
                target=validated.target,
                operator=operator,
                run_id=run_id,
                timeout_seconds=validated.timeout_seconds,
                rate_limit_per_minute=validated.rate_limit_per_minute,
                repo_root=root,
                opener=opener,
            )
        except Exception as exc:  # noqa: BLE001 - surface tool/safety failures in plan result
            status = "failed"
            error = str(exc)
            results.append(
                {
                    "tool": planned.name,
                    "target": validated.target,
                    "status": "failed",
                    "error": error,
                    "params": dict(planned.params),
                }
            )
            if stop_on_failure:
                break
            continue

        tool_status = str(tool_result.get("status", "unknown"))
        results.append(tool_result)
        if tool_status not in {"completed", "ok", "success"}:
            status = "failed" if stop_on_failure else "partial"
            error = f"tool {planned.name} ended with status {tool_status}"
            if stop_on_failure:
                break

    ended_at = utc_now_iso()
    payload: dict[str, Any] = {
        "plan_id": plan_id,
        "run_id": run_id,
        "target": validated.target,
        "objective": validated.objective,
        "risk_level": validated.risk_level,
        "operator": operator,
        "status": status,
        "tools": [tool.name for tool in validated.tools],
        "results": results,
        "started_at": started_at,
        "ended_at": ended_at,
    }
    if error:
        payload["error"] = error

    if generate_report:
        payload["report"] = write_aggregate_markdown_report(
            plan_result=payload,
            operator=operator,
            run_id=run_id,
            repo_root=root,
        )

    return payload
