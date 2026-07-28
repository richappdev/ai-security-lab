"""Temporal Cloud workflow definitions and a local coordination fallback."""

from __future__ import annotations

import os
from dataclasses import dataclass
from uuid import uuid4


@dataclass
class WorkflowStart:
    workflow_id: str
    backend: str
    status: str = "running"


def allow_legacy_sync_runs() -> bool:
    return os.environ.get("ALLOW_LEGACY_SYNC_RUNS", "true").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


async def start_evaluation_workflow(run_id: str, deadline_seconds: int) -> WorkflowStart:
    """Start a Temporal workflow when configured.

    Imports are intentionally lazy so local unit tests do not require the SDK.
    Partner environments set TEMPORAL_ADDRESS and disable the local fallback.
    """
    address = os.environ.get("TEMPORAL_ADDRESS") or os.environ.get("TEMPORAL_HOST")
    workflow_id = f"evaluation-{run_id}"
    if address:
        try:
            from temporalio.client import Client

            client = await Client.connect(
                address,
                namespace=os.environ.get("TEMPORAL_NAMESPACE", "default"),
                tls=os.environ.get("TEMPORAL_TLS", "true").lower() in {"1", "true", "yes"},
            )
            await client.start_workflow(
                "EvaluationWorkflow",
                {"run_id": run_id, "deadline_seconds": deadline_seconds},
                id=workflow_id,
                task_queue=os.environ.get("TEMPORAL_TASK_QUEUE", "agent-security-evaluations"),
            )
            return WorkflowStart(workflow_id=workflow_id, backend="temporal")
        except ImportError as exc:
            if not allow_legacy_sync_runs():
                raise RuntimeError("Temporal SDK is required for beta execution") from exc
    if not allow_legacy_sync_runs():
        raise RuntimeError("TEMPORAL_ADDRESS is required when legacy execution is disabled")
    return WorkflowStart(workflow_id=f"local-{uuid4()}", backend="local")


async def signal_evaluation_workflow(
    workflow_id: str | None,
    signal: str,
    payload: int | None = None,
) -> None:
    if not workflow_id or workflow_id.startswith("local-"):
        return
    address = os.environ.get("TEMPORAL_ADDRESS") or os.environ.get("TEMPORAL_HOST")
    if not address:
        return
    try:
        from temporalio.client import Client

        client = await Client.connect(
            address,
            namespace=os.environ.get("TEMPORAL_NAMESPACE", "default"),
            tls=os.environ.get("TEMPORAL_TLS", "true").lower() in {"1", "true", "yes"},
        )
        handle = client.get_workflow_handle(workflow_id)
        if payload is None:
            await handle.signal(signal)
        else:
            await handle.signal(signal, payload)
    except ImportError as exc:
        if not allow_legacy_sync_runs():
            raise RuntimeError("Temporal SDK is required for beta execution") from exc


# Import-safe definitions used by a real Temporal worker when the SDK is installed.
try:
    from datetime import timedelta
    from temporalio import workflow

    @workflow.defn(name="EvaluationWorkflow")
    class EvaluationWorkflow:
        def __init__(self) -> None:
            self.completed = False
            self.cancelled = False
            self.event_count = 0

        @workflow.signal
        async def events_received(self, count: int) -> None:
            self.event_count += count

        @workflow.signal
        async def complete(self) -> None:
            self.completed = True

        @workflow.signal
        async def cancel(self) -> None:
            self.cancelled = True

        @workflow.run
        async def run(self, request: dict) -> dict:
            timeout = timedelta(seconds=int(request.get("deadline_seconds", 600)))
            try:
                await workflow.wait_condition(
                    lambda: self.completed or self.cancelled,
                    timeout=timeout,
                )
            except TimeoutError:
                return {"status": "failed", "reason": "deadline_exceeded"}
            return {
                "status": "cancelled" if self.cancelled else "ready_to_evaluate",
                "event_count": self.event_count,
            }


    @workflow.defn(name="SuiteWorkflow")
    class SuiteWorkflow:
        @workflow.run
        async def run(self, request: dict) -> dict:
            return {"status": "started", "suite_run_id": request["suite_run_id"]}
except ImportError:  # pragma: no cover - exercised in Temporal integration environments
    EvaluationWorkflow = None
    SuiteWorkflow = None
