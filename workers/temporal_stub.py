"""Temporal workflow stubs for durable commercial runs (Private Beta)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import uuid4


@dataclass
class CapabilityDocument:
    """Short-lived per-run capability revalidated before sensitive ops."""

    capability_id: str
    organization_id: str
    run_id: str
    allowed_tools: list[str]
    allowed_targets: list[str]
    expires_at: datetime
    request_ceiling: int
    cost_ceiling: int
    time_ceiling_seconds: int
    network_policy: str = "deny_public"

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(timezone.utc)) >= self.expires_at

    def allows_tool(self, tool: str) -> bool:
        return tool in self.allowed_tools and not self.is_expired()

    def revalidate(self, *, tool: str | None = None) -> None:
        if self.is_expired():
            raise PermissionError("capability expired")
        if tool is not None and tool not in self.allowed_tools:
            raise PermissionError(f"tool not permitted by capability: {tool}")


@dataclass
class WorkflowHandle:
    workflow_id: str
    run_id: str
    status: str = "running"
    result: dict[str, Any] | None = None


@dataclass
class InProcessTemporal:
    """Local stand-in until Temporal Cloud / self-hosted Temporal is wired."""

    workflows: dict[str, WorkflowHandle] = field(default_factory=dict)

    def start_evaluation(
        self,
        *,
        run_id: str,
        execute: Callable[[], dict[str, Any]],
        capability: CapabilityDocument,
    ) -> WorkflowHandle:
        capability.revalidate()
        handle = WorkflowHandle(workflow_id=str(uuid4()), run_id=run_id, status="running")
        self.workflows[handle.workflow_id] = handle
        try:
            handle.result = execute()
            handle.status = "completed"
        except Exception as exc:  # noqa: BLE001
            handle.status = "failed"
            handle.result = {"error": str(exc)}
        return handle

    def cancel(self, workflow_id: str) -> WorkflowHandle:
        handle = self.workflows[workflow_id]
        handle.status = "cancelled"
        return handle

    def describe(self, workflow_id: str) -> WorkflowHandle:
        return self.workflows[workflow_id]


def issue_capability(
    *,
    organization_id: str,
    run_id: str,
    allowed_tools: list[str],
    ttl_seconds: int = 600,
    request_ceiling: int = 100,
    cost_ceiling: int = 100,
    time_ceiling_seconds: int = 300,
) -> CapabilityDocument:
    return CapabilityDocument(
        capability_id=str(uuid4()),
        organization_id=organization_id,
        run_id=run_id,
        allowed_tools=list(allowed_tools),
        allowed_targets=[],
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        request_ceiling=request_ceiling,
        cost_ceiling=cost_ceiling,
        time_ceiling_seconds=time_ceiling_seconds,
    )
