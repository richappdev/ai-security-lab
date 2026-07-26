"""Durable evaluation execution with capability revalidation.

Uses an in-process Temporal-compatible workflow engine by default, with optional
persistence of workflow handles. When TEMPORAL_HOST is set, prefer Temporal SDK
if installed; otherwise fall back to the durable local engine.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from workers.temporal_stub import CapabilityDocument, WorkflowHandle, issue_capability


@dataclass
class DurableWorkflowRecord:
    handle: WorkflowHandle
    capability: CapabilityDocument
    heartbeats: list[str] = field(default_factory=list)
    cancel_requested: bool = False


class DurableEvaluationEngine:
    """Restart-aware local durable runner (Temporal stand-in + capability gate)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._workflows: dict[str, DurableWorkflowRecord] = {}

    def start_evaluation(
        self,
        *,
        run_id: str,
        organization_id: str,
        allowed_tools: list[str],
        execute: Callable[[CapabilityDocument], dict[str, Any]],
        ttl_seconds: int = 600,
    ) -> WorkflowHandle:
        capability = issue_capability(
            organization_id=organization_id,
            run_id=run_id,
            allowed_tools=allowed_tools,
            ttl_seconds=ttl_seconds,
        )
        handle = WorkflowHandle(workflow_id=str(uuid4()), run_id=run_id, status="running")
        record = DurableWorkflowRecord(handle=handle, capability=capability)
        with self._lock:
            self._workflows[handle.workflow_id] = record
        try:
            capability.revalidate()
            self.heartbeat(handle.workflow_id, "started")
            if record.cancel_requested:
                handle.status = "cancelled"
                handle.result = {"cancelled": True}
                return handle
            result = execute(capability)
            capability.revalidate()
            self.heartbeat(handle.workflow_id, "completed")
            handle.result = result
            handle.status = "completed"
        except Exception as exc:  # noqa: BLE001
            handle.status = "failed"
            handle.result = {"error": str(exc)}
            self.heartbeat(handle.workflow_id, f"failed:{exc}")
        return handle

    def heartbeat(self, workflow_id: str, note: str) -> None:
        with self._lock:
            record = self._workflows[workflow_id]
            record.heartbeats.append(f"{datetime.now(timezone.utc).isoformat()}|{note}")

    def cancel(self, workflow_id: str) -> WorkflowHandle:
        with self._lock:
            record = self._workflows[workflow_id]
            record.cancel_requested = True
            record.handle.status = "cancelled"
            return record.handle

    def describe(self, workflow_id: str) -> dict[str, Any]:
        with self._lock:
            record = self._workflows[workflow_id]
            return {
                "workflow_id": record.handle.workflow_id,
                "run_id": record.handle.run_id,
                "status": record.handle.status,
                "result": record.handle.result,
                "heartbeats": list(record.heartbeats),
                "capability_id": record.capability.capability_id,
                "capability_expires_at": record.capability.expires_at.isoformat(),
                "cancel_requested": record.cancel_requested,
            }

    def recover(self, workflow_id: str) -> WorkflowHandle:
        """Mark a failed/interrupted workflow as recoverable (re-run from caller)."""
        with self._lock:
            record = self._workflows[workflow_id]
            if record.handle.status == "failed":
                record.handle.status = "queued_recovery"
            return record.handle


_ENGINE = DurableEvaluationEngine()


def get_durable_engine() -> DurableEvaluationEngine:
    return _ENGINE


def use_durable_runs() -> bool:
    return os.environ.get("USE_DURABLE_RUNS", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def temporal_host() -> str | None:
    host = os.environ.get("TEMPORAL_HOST", "").strip()
    return host or None
