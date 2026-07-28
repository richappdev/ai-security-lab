"""Temporal worker process for Private Beta."""

from __future__ import annotations

import asyncio
import os


async def run_worker() -> None:
    from temporalio.worker import Worker

    from workers.temporal_client import connect_temporal
    from workers.workflows import EvaluationWorkflow, SuiteWorkflow

    client = await connect_temporal()
    worker = Worker(
        client,
        task_queue=os.environ.get("TEMPORAL_TASK_QUEUE", "agent-security-evaluations"),
        workflows=[EvaluationWorkflow, SuiteWorkflow],
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(run_worker())
