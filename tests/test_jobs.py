from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from threading import Event

from app.api.jobs import JobNotFoundError, JobRegistry


class JobRegistryTests(unittest.TestCase):
    def test_create_and_read_job_snapshot(self):
        registry = JobRegistry()

        registry.create_job(
            job_id="job-read-test",
            tool="future_bulk_route_check",
            target="http://127.0.0.1:3000",
            operator="job-test",
        )
        snapshot = registry.snapshot("job-read-test")

        self.assertEqual(snapshot["job_id"], "job-read-test")
        self.assertEqual(snapshot["status"], "queued")
        self.assertEqual(snapshot["tool"], "future_bulk_route_check")

    def test_missing_job_raises_not_found(self):
        registry = JobRegistry()

        with self.assertRaises(JobNotFoundError):
            registry.snapshot("missing-job")

    def test_cancel_queued_job_marks_cancel_requested(self):
        registry = JobRegistry()
        registry.create_job(
            job_id="job-cancel-test",
            tool="future_bulk_route_check",
            target="http://127.0.0.1:3000",
            operator="job-test",
        )

        snapshot = registry.cancel_job("job-cancel-test")

        self.assertEqual(snapshot["status"], "cancel_requested")

    def test_cancel_completed_job_keeps_completed_state(self):
        with tempfile.TemporaryDirectory() as repo:
            registry = JobRegistry(repo_root=repo)
            registry.run_job(
                job_id="job-complete-test",
                tool="future_bulk_route_check",
                target="http://127.0.0.1:3000",
                operator="job-test",
                runner=lambda token: {"ok": True},
                start_thread=False,
            )

            snapshot = registry.cancel_job("job-complete-test")

        self.assertEqual(snapshot["status"], "completed")
        self.assertEqual(snapshot["result"], {"ok": True})

    def test_failed_job_records_error(self):
        with tempfile.TemporaryDirectory() as repo:
            registry = JobRegistry(repo_root=repo)

            def failing_runner(token):
                raise RuntimeError("planned failure")

            registry.run_job(
                job_id="job-fail-test",
                tool="future_bulk_route_check",
                target="http://127.0.0.1:3000",
                operator="job-test",
                runner=failing_runner,
                start_thread=False,
            )
            snapshot = registry.snapshot("job-fail-test")

        self.assertEqual(snapshot["status"], "failed")
        self.assertEqual(snapshot["error"], "planned failure")

    def test_cancellable_multistep_job_stops_when_cancel_requested(self):
        with tempfile.TemporaryDirectory() as repo:
            registry = JobRegistry(repo_root=repo)
            started = Event()

            def cancellable_runner(token):
                started.set()
                for step in range(100):
                    token.raise_if_cancelled()
                    time.sleep(0.005)
                return {"steps": step + 1}

            registry.run_job(
                job_id="job-cancellable-test",
                tool="future_bulk_route_check",
                target="http://127.0.0.1:3000",
                operator="job-test",
                runner=cancellable_runner,
            )

            self.assertTrue(started.wait(timeout=1))
            self.assertEqual(registry.cancel_job("job-cancellable-test")["status"], "cancel_requested")

            for _ in range(100):
                snapshot = registry.snapshot("job-cancellable-test")
                if snapshot["status"] == "cancelled":
                    break
                time.sleep(0.01)

            audit_log = Path(repo) / "logs" / "audit.jsonl"
            audit_exists = audit_log.exists()
            audit_text = audit_log.read_text(encoding="utf-8")

        self.assertEqual(snapshot["status"], "cancelled")
        self.assertTrue(audit_exists)
        self.assertIn('"status": "cancelled"', audit_text)


if __name__ == "__main__":
    unittest.main()
