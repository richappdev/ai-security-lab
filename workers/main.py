"""Temporal worker process for Private Beta."""

from __future__ import annotations

import asyncio
import os


async def run_worker() -> None:
    from temporalio.client import Client
    from temporalio.worker import Worker

    from workers.workflows import EvaluationWorkflow, SuiteWorkflow

    address = os.environ["TEMPORAL_ADDRESS"]
    client = await Client.connect(
        address,
        namespace=os.environ.get("TEMPORAL_NAMESPACE", "default"),
        tls=os.environ.get("TEMPORAL_TLS", "true").lower() in {"1", "true", "yes"},
    )
    worker = Worker(
        client,
        task_queue=os.environ.get("TEMPORAL_TASK_QUEUE", "agent-security-evaluations"),
        workflows=[EvaluationWorkflow, SuiteWorkflow],
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(run_worker())
