"""In-process job registry for cancellable multi-request tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock, Thread
from typing import Any, Callable, Literal
from uuid import uuid4

from safety.audit_log import append_audit_record, utc_now_iso
from safety.cancellation import CancellationToken, JobCancelledError

# Re-export so existing imports from app.api.jobs keep working.
__all__ = [
    "CancellationToken",
    "JobCancelledError",
    "JobNotFoundError",
    "JobRecord",
    "JobRegistry",
    "job_registry",
]


JobStatus = Literal["queued", "running", "completed", "failed", "cancel_requested", "cancelled"]
TerminalStatus = Literal["completed", "failed", "cancelled"]


class JobNotFoundError(KeyError):
    """Raised when a requested job ID is not registered."""


@dataclass
class JobRecord:
    job_id: str
    tool: str
    target: str
    operator: str
    status: JobStatus = "queued"
    created_at: str = field(default_factory=utc_now_iso)
    started_at: str | None = None
    ended_at: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    token: CancellationToken = field(default_factory=CancellationToken, repr=False)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "job_id": self.job_id,
            "tool": self.tool,
            "target": self.target,
            "operator": self.operator,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }
        if self.result is not None:
            payload["result"] = self.result
        if self.error is not None:
            payload["error"] = self.error
        return payload


class JobRegistry:
    """Small process-local registry for future cancellable active jobs."""

    def __init__(self, repo_root: str | None = None) -> None:
        self._jobs: dict[str, JobRecord] = {}
        self._lock = Lock()
        self._repo_root = repo_root

    def create_job(
        self,
        *,
        tool: str,
        target: str,
        operator: str,
        job_id: str | None = None,
    ) -> JobRecord:
        record = JobRecord(
            job_id=job_id or f"job-{uuid4()}",
            tool=tool,
            target=target,
            operator=operator,
        )
        with self._lock:
            if record.job_id in self._jobs:
                raise ValueError(f"job already exists: {record.job_id}")
            self._jobs[record.job_id] = record
        return record

    def get_job(self, job_id: str) -> JobRecord:
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError as exc:
                raise JobNotFoundError(job_id) from exc

    def snapshot(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            try:
                return self._jobs[job_id].to_dict()
            except KeyError as exc:
                raise JobNotFoundError(job_id) from exc

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            try:
                record = self._jobs[job_id]
            except KeyError as exc:
                raise JobNotFoundError(job_id) from exc

            if record.status in ("completed", "failed", "cancelled"):
                return record.to_dict()

            record.token.cancel()
            record.status = "cancel_requested"
            return record.to_dict()

    def run_job(
        self,
        *,
        tool: str,
        target: str,
        operator: str,
        runner: Callable[[CancellationToken], dict[str, Any]],
        job_id: str | None = None,
        start_thread: bool = True,
    ) -> JobRecord:
        record = self.create_job(tool=tool, target=target, operator=operator, job_id=job_id)

        def execute() -> None:
            self._mark_started(record.job_id)
            try:
                record.token.raise_if_cancelled()
                result = runner(record.token)
            except JobCancelledError as exc:
                self._mark_terminal(
                    record.job_id,
                    "cancelled",
                    result=exc.result,
                    error=str(exc) or "job cancellation requested",
                )
            except Exception as exc:  # pragma: no cover - defensive boundary for background jobs
                self._mark_terminal(record.job_id, "failed", error=str(exc))
            else:
                self._mark_terminal(record.job_id, "completed", result=result)

        if start_thread:
            Thread(target=execute, name=record.job_id, daemon=True).start()
        else:
            execute()
        return record

    def _mark_started(self, job_id: str) -> None:
        with self._lock:
            record = self._jobs[job_id]
            if record.status == "cancel_requested":
                return
            record.status = "running"
            record.started_at = utc_now_iso()

    def _mark_terminal(
        self,
        job_id: str,
        status: TerminalStatus,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            record = self._jobs[job_id]
            record.status = status
            record.result = result
            record.error = error
            record.ended_at = utc_now_iso()
            audit_record = {
                "run_id": job_id,
                "operator": record.operator,
                "target": record.target,
                "tool": record.tool,
                "status": status,
                "risk": "job-control",
                "started_at": record.started_at,
                "ended_at": record.ended_at,
                "result_summary": error or "job completed",
            }

        append_audit_record(audit_record, repo_root=self._repo_root)


job_registry = JobRegistry()
