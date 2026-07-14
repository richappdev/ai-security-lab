from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch
from urllib.error import HTTPError

from app.api.jobs import JobRegistry
from safety.cancellation import CancellationToken, JobCancelledError
from safety.rate_limit import RateLimiter
from tools.active.bulk_route_exists_check import (
    KNOWN_LAB_ROUTE_PATHS,
    lab_bulk_route_exists_check,
)


POLICY_TEXT = """version: 1

scope:
  allowed_targets_file: targets.allowlist
  localhost_only_by_default: true
  deny_public_ips: true
  deny_private_network_scan: true
  deny_third_party_domains: true

limits:
  default_timeout_seconds: 10
  max_timeout_seconds: 30
  max_requests_per_minute: 30
  max_same_origin_pages: 25

allowed_activity:
  - passive_http_inspection
  - same_origin_crawl
  - local_lab_active_checks

blocked_activity:
  - public_target_testing
  - credential_stuffing
  - destructive_exploit
  - denial_of_service
  - lateral_movement
  - data_exfiltration

audit:
  required: true
  output_directory: logs
  fields:
    - run_id
    - operator
    - tool
    - target
    - risk
    - started_at
    - ended_at
    - status
    - result_summary
"""


def fast_rate_limiter(requests_per_minute: int) -> RateLimiter:
    return RateLimiter(requests_per_minute, sleeper=lambda _: None)


class FakeHeadResponse:
    def __init__(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def status_map_opener(status_by_path: dict[str, int]):
    def opener(request, timeout):
        if request.get_method() != "HEAD":
            raise AssertionError("expected HEAD request")
        path = request.full_url.split("http://127.0.0.1:3000", 1)[-1]
        if path not in status_by_path:
            raise AssertionError(f"unexpected URL path: {path}")
        status = status_by_path[path]
        if status >= 400:
            raise HTTPError(
                url=request.full_url,
                code=status,
                msg="error",
                hdrs={"Content-Type": "text/html"},
                fp=None,
            )
        return FakeHeadResponse(status, {"Content-Type": "text/html"})

    return opener


def should_not_call_network(request, timeout):
    raise AssertionError("network opener should not be called")


class ActiveBulkRouteExistsCheckTests(unittest.TestCase):
    def make_repo(self) -> tempfile.TemporaryDirectory[str]:
        temp_dir = tempfile.TemporaryDirectory()
        root = Path(temp_dir.name)
        (root / "targets.allowlist").write_text(
            "\n".join(
                [
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:8080",
                ]
            ),
            encoding="utf-8",
        )
        (root / "safety").mkdir()
        (root / "safety" / "policy.yml").write_text(POLICY_TEXT, encoding="utf-8")
        return temp_dir

    def test_bulk_route_check_reports_mixed_existence_and_audits(self):
        selected = ("/", "/login", "/login.php")
        opener = status_map_opener(
            {
                "/": 200,
                "/login": 200,
                "/login.php": 404,
            }
        )
        with self.make_repo() as repo:
            with patch(
                "tools.active.bulk_route_exists_check.RateLimiter",
                side_effect=fast_rate_limiter,
            ):
                result = lab_bulk_route_exists_check(
                    target="http://127.0.0.1:3000",
                    operator="tester",
                    run_id="run-bulk-route",
                    repo_root=repo,
                    opener=opener,
                    route_paths=selected,
                )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(result["tool"], "lab_bulk_route_exists_check")
        self.assertEqual(result["risk"], "active-low-risk")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["checked"], 3)
        self.assertEqual(result["exists_count"], 2)
        self.assertEqual(result["missing_count"], 1)
        self.assertEqual(result["route_paths"], list(selected))
        self.assertEqual(len(audit_records), 2)
        self.assertEqual(audit_records[0]["status"], "started")
        self.assertEqual(audit_records[1]["status"], "completed")

    def test_bulk_route_check_defaults_to_known_lab_paths(self):
        calls: list[str] = []

        def counting_opener(request, timeout):
            calls.append(request.full_url)
            return FakeHeadResponse(200)

        with self.make_repo() as repo:
            with patch(
                "tools.active.bulk_route_exists_check.RateLimiter",
                side_effect=fast_rate_limiter,
            ):
                result = lab_bulk_route_exists_check(
                    target="http://127.0.0.1:3000",
                    operator="tester",
                    run_id="run-bulk-default",
                    repo_root=repo,
                    opener=counting_opener,
                )

        self.assertEqual(result["checked"], len(KNOWN_LAB_ROUTE_PATHS))
        self.assertEqual(len(calls), len(KNOWN_LAB_ROUTE_PATHS))
        self.assertEqual(result["route_paths"], list(KNOWN_LAB_ROUTE_PATHS))

    def test_bulk_route_check_rejects_unknown_path_without_network(self):
        with self.make_repo() as repo:
            result = lab_bulk_route_exists_check(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-bulk-unknown-path",
                repo_root=repo,
                opener=should_not_call_network,
                route_paths=["/not-in-fixed-list"],
            )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")

    def test_bulk_route_check_rejects_out_of_scope_without_network(self):
        with self.make_repo() as repo:
            result = lab_bulk_route_exists_check(
                target="https://example.com",
                operator="tester",
                run_id="run-bulk-rejected",
                repo_root=repo,
                opener=should_not_call_network,
                route_paths=["/login"],
            )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")

    def test_bulk_route_check_rejects_policy_violation_without_network(self):
        with self.make_repo() as repo:
            result = lab_bulk_route_exists_check(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-bulk-policy",
                timeout_seconds=31,
                repo_root=repo,
                opener=should_not_call_network,
                route_paths=["/login"],
            )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "policy_rejected")

    def test_bulk_route_check_reports_request_failure(self):
        def failing_opener(request, timeout):
            raise RuntimeError("connection refused")

        with self.make_repo() as repo:
            with patch(
                "tools.active.bulk_route_exists_check.RateLimiter",
                side_effect=fast_rate_limiter,
            ):
                result = lab_bulk_route_exists_check(
                    target="http://127.0.0.1:3000",
                    operator="tester",
                    run_id="run-bulk-failure",
                    repo_root=repo,
                    opener=failing_opener,
                    route_paths=["/login"],
                )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["findings"][0]["id"], "request_failed")

    def test_bulk_route_check_stops_when_cancellation_requested(self):
        token = CancellationToken()
        calls = 0

        def slow_opener(request, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                token.cancel()
            time.sleep(0.01)
            return FakeHeadResponse(200)

        with self.make_repo() as repo:
            with patch(
                "tools.active.bulk_route_exists_check.RateLimiter",
                side_effect=fast_rate_limiter,
            ):
                with self.assertRaises(JobCancelledError) as raised:
                    lab_bulk_route_exists_check(
                        target="http://127.0.0.1:3000",
                        operator="tester",
                        run_id="run-bulk-cancel",
                        repo_root=repo,
                        opener=slow_opener,
                        cancellation_token=token,
                        route_paths=KNOWN_LAB_ROUTE_PATHS[:4],
                    )
            exc = raised.exception
            self.assertIsNotNone(exc.result)
            self.assertEqual(exc.result["status"], "cancelled")
            self.assertGreaterEqual(exc.result["checked"], 1)
            self.assertLess(exc.result["checked"], 4)
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_text = audit_path.read_text(encoding="utf-8")

        self.assertIn('"status": "cancelled"', audit_text)
        self.assertLess(calls, 4)

    def test_bulk_route_job_registry_integration_cancels_between_requests(self):
        with self.make_repo() as repo:
            registry = JobRegistry(repo_root=repo)
            started = Event()

            def runner(token):
                def gated_opener(request, timeout):
                    started.set()
                    time.sleep(0.02)
                    return FakeHeadResponse(200)

                with patch(
                    "tools.active.bulk_route_exists_check.RateLimiter",
                    side_effect=fast_rate_limiter,
                ):
                    return lab_bulk_route_exists_check(
                        target="http://127.0.0.1:3000",
                        operator="tester",
                        run_id="run-bulk-job",
                        repo_root=repo,
                        opener=gated_opener,
                        cancellation_token=token,
                        route_paths=KNOWN_LAB_ROUTE_PATHS[:5],
                    )

            record = registry.run_job(
                job_id="job-bulk-cancel",
                tool="lab_bulk_route_exists_check",
                target="http://127.0.0.1:3000",
                operator="tester",
                runner=runner,
            )
            self.assertTrue(started.wait(timeout=1))
            registry.cancel_job(record.job_id)

            snapshot = None
            for _ in range(100):
                snapshot = registry.snapshot(record.job_id)
                if snapshot["status"] == "cancelled":
                    break
                time.sleep(0.02)

        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot["status"], "cancelled")
        self.assertIsNotNone(snapshot.get("result"))
        self.assertEqual(snapshot["result"]["status"], "cancelled")


if __name__ == "__main__":
    unittest.main()
