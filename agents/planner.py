"""Planner contract: validate agent plans against the tool manifest."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from agents.manifest import ToolManifestEntry, load_tool_manifest


class PlanValidationError(ValueError):
    """Raised when an agent plan violates the agent or tool contract."""


RISK_RANK = {
    "passive": 0,
    "active-low-risk": 1,
    "active-high-risk": 2,
}

TOOLS_REQUIRING_ROUTE_PATH = frozenset(
    {
        "lab_route_exists_check",
        "lab_security_header_delta_check",
        "lab_auth_page_metadata_check",
    }
)

VALID_RISK_LEVELS = frozenset(RISK_RANK)


@dataclass(frozen=True)
class PlannedTool:
    name: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentPlan:
    target: str
    objective: str
    risk_level: str
    tools: tuple[PlannedTool, ...]
    timeout_seconds: int = 10
    rate_limit_per_minute: int | None = None
    operator: str = "local-user"
    run_id: str | None = None


def _normalize_tool(item: PlannedTool | str | Mapping[str, Any]) -> PlannedTool:
    if isinstance(item, PlannedTool):
        return PlannedTool(name=item.name, params=dict(item.params))
    if isinstance(item, str):
        return PlannedTool(name=item, params={})
    if isinstance(item, Mapping):
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise PlanValidationError("planned tool mapping requires a non-empty name")
        params = item.get("params") or {}
        if not isinstance(params, Mapping):
            raise PlanValidationError(f"params for tool {name} must be a mapping")
        extra = {key: value for key, value in item.items() if key not in {"name", "params"}}
        merged = dict(params)
        merged.update(extra)
        return PlannedTool(name=name.strip(), params=dict(merged))
    raise PlanValidationError(f"unsupported planned tool type: {type(item)!r}")


def build_plan(
    *,
    target: str,
    objective: str,
    risk_level: str,
    tools: Sequence[PlannedTool | str | Mapping[str, Any]],
    timeout_seconds: int = 10,
    rate_limit_per_minute: int | None = None,
    operator: str = "local-user",
    run_id: str | None = None,
    repo_root: str | Path | None = None,
    validate: bool = True,
) -> AgentPlan:
    plan = AgentPlan(
        target=target.strip(),
        objective=objective.strip(),
        risk_level=risk_level.strip(),
        tools=tuple(_normalize_tool(item) for item in tools),
        timeout_seconds=timeout_seconds,
        rate_limit_per_minute=rate_limit_per_minute,
        operator=operator.strip() or "local-user",
        run_id=run_id,
    )
    if validate:
        validate_plan(plan, repo_root=repo_root)
    return plan


def _ordered_for_execution(
    tools: Sequence[PlannedTool],
    manifest_by_name: Mapping[str, ToolManifestEntry],
) -> tuple[PlannedTool, ...]:
    """Prefer passive tools before active tools while keeping relative order."""

    passive: list[PlannedTool] = []
    active: list[PlannedTool] = []
    for tool in tools:
        entry = manifest_by_name[tool.name]
        if entry.category == "passive" or entry.risk == "passive":
            passive.append(tool)
        else:
            active.append(tool)
    return tuple(passive + active)


def validate_plan(
    plan: AgentPlan,
    repo_root: str | Path | None = None,
    *,
    reorder_passive_first: bool = False,
) -> AgentPlan:
    if not plan.target:
        raise PlanValidationError("plan target is required")
    if not plan.objective:
        raise PlanValidationError("plan objective is required")
    if plan.risk_level not in VALID_RISK_LEVELS:
        raise PlanValidationError(
            f"risk_level must be one of: {', '.join(sorted(VALID_RISK_LEVELS))}"
        )
    if not plan.tools:
        raise PlanValidationError("plan must select at least one tool from the manifest")
    if plan.timeout_seconds < 1:
        raise PlanValidationError("timeout_seconds must be at least 1")
    if plan.rate_limit_per_minute is not None and plan.rate_limit_per_minute < 1:
        raise PlanValidationError("rate_limit_per_minute must be at least 1")

    manifest_by_name = {entry.name: entry for entry in load_tool_manifest(repo_root=repo_root)}
    plan_rank = RISK_RANK[plan.risk_level]
    seen: set[str] = set()

    for planned in plan.tools:
        if planned.name in seen:
            raise PlanValidationError(f"duplicate tool in plan: {planned.name}")
        seen.add(planned.name)

        entry = manifest_by_name.get(planned.name)
        if entry is None:
            raise PlanValidationError(f"tool is not listed in tools/manifest.yml: {planned.name}")
        if not entry.audit_required:
            raise PlanValidationError(f"tool must require audit logging: {planned.name}")
        if entry.timeout_seconds < 1:
            raise PlanValidationError(f"tool timeout_seconds must be positive: {planned.name}")

        tool_rank = RISK_RANK.get(entry.risk)
        if tool_rank is None:
            raise PlanValidationError(f"tool has unsupported risk label: {planned.name}")
        if tool_rank > plan_rank:
            raise PlanValidationError(
                f"tool {planned.name} risk {entry.risk} exceeds plan risk_level {plan.risk_level}"
            )

        if planned.name in TOOLS_REQUIRING_ROUTE_PATH:
            route_path = planned.params.get("route_path")
            if not isinstance(route_path, str) or not route_path.strip():
                raise PlanValidationError(f"tool {planned.name} requires params.route_path")

    ordered = (
        _ordered_for_execution(plan.tools, manifest_by_name)
        if reorder_passive_first
        else plan.tools
    )
    if ordered == plan.tools:
        return plan
    return AgentPlan(
        target=plan.target,
        objective=plan.objective,
        risk_level=plan.risk_level,
        tools=ordered,
        timeout_seconds=plan.timeout_seconds,
        rate_limit_per_minute=plan.rate_limit_per_minute,
        operator=plan.operator,
        run_id=plan.run_id,
    )
