"""Temporal workflow integration tests (run when the SDK is installed)."""

from __future__ import annotations

import unittest
from datetime import timedelta

try:
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    from workers.workflows import EvaluationWorkflow

    TEMPORAL_AVAILABLE = EvaluationWorkflow is not None
except ImportError:
    TEMPORAL_AVAILABLE = False


@unittest.skipUnless(TEMPORAL_AVAILABLE, "Temporal SDK not installed")
class TemporalWorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.environment = await WorkflowEnvironment.start_time_skipping()
        self.worker = Worker(
            self.environment.client,
            task_queue="test-evaluations",
            workflows=[EvaluationWorkflow],
        )
        self.worker_context = self.worker
        await self.worker_context.__aenter__()

    async def asyncTearDown(self) -> None:
        await self.worker_context.__aexit__(None, None, None)
        await self.environment.shutdown()

    async def test_event_signals_complete_workflow_without_duplicate_work(self):
        handle = await self.environment.client.start_workflow(
            EvaluationWorkflow.run,
            {"run_id": "run-1", "deadline_seconds": 60},
            id="run-1",
            task_queue="test-evaluations",
            execution_timeout=timedelta(minutes=2),
        )
        await handle.signal(EvaluationWorkflow.events_received, 3)
        await handle.signal(EvaluationWorkflow.events_received, 0)
        await handle.signal(EvaluationWorkflow.complete)
        result = await handle.result()
        self.assertEqual(result["status"], "ready_to_evaluate")
        self.assertEqual(result["event_count"], 3)

    async def test_cancel_signal_terminates_workflow(self):
        handle = await self.environment.client.start_workflow(
            EvaluationWorkflow.run,
            {"run_id": "run-2", "deadline_seconds": 60},
            id="run-2",
            task_queue="test-evaluations",
        )
        await handle.signal(EvaluationWorkflow.cancel)
        result = await handle.result()
        self.assertEqual(result["status"], "cancelled")


if __name__ == "__main__":
    unittest.main()
