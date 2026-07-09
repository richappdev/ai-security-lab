from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError

from tools.active.route_exists_check import lab_route_exists_check


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


class FakeHeadResponse:
    def __init__(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def existing_route_opener(request, timeout):
    if request.get_method() != "HEAD":
        raise AssertionError("expected HEAD request")
    if request.full_url != "http://127.0.0.1:3000/login":
        raise AssertionError(f"unexpected URL: {request.full_url}")
    return FakeHeadResponse(200, {"Content-Type": "text/html"})


def missing_route_opener(request, timeout):
    return FakeHeadResponse(404)


def missing_route_http_error_opener(request, timeout):
    raise HTTPError(
        url=request.full_url,
        code=404,
        msg="Not Found",
        hdrs={"Content-Type": "text/html"},
        fp=None,
    )


def failing_request_opener(request, timeout):
    raise RuntimeError("connection refused")


def should_not_call_network(request, timeout):
    raise AssertionError("network opener should not be called")


class ActiveRouteExistsCheckTests(unittest.TestCase):
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

    def test_route_exists_check_reports_existing_route_and_audits(self):
        with self.make_repo() as repo:
            result = lab_route_exists_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-active-route",
                repo_root=repo,
                opener=existing_route_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(result["tool"], "lab_route_exists_check")
        self.assertEqual(result["risk"], "active-low-risk")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 200)
        self.assertTrue(result["exists"])
        self.assertEqual(result["route_url"], "http://127.0.0.1:3000/login")
        self.assertEqual(result["findings"][0]["id"], "route_exists")
        self.assertEqual(len(audit_records), 2)
        self.assertEqual(audit_records[0]["status"], "started")
        self.assertEqual(audit_records[1]["status"], "completed")

    def test_route_exists_check_reports_missing_route(self):
        with self.make_repo() as repo:
            result = lab_route_exists_check(
                target="http://127.0.0.1:8080",
                route_path="/missing",
                operator="tester",
                run_id="run-active-route-missing",
                repo_root=repo,
                opener=missing_route_opener,
            )

        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["exists"])
        self.assertEqual(result["findings"][0]["id"], "route_not_found")

    def test_route_exists_check_treats_http_error_status_as_completed(self):
        with self.make_repo() as repo:
            result = lab_route_exists_check(
                target="http://127.0.0.1:8080",
                route_path="/missing",
                operator="tester",
                run_id="run-active-route-http-error",
                repo_root=repo,
                opener=missing_route_http_error_opener,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 404)
        self.assertFalse(result["exists"])
        self.assertEqual(result["findings"][0]["id"], "route_not_found")

    def test_route_exists_check_rejects_out_of_scope_without_network(self):
        with self.make_repo() as repo:
            result = lab_route_exists_check(
                target="https://example.com",
                route_path="/login",
                operator="tester",
                run_id="run-active-route-rejected",
                repo_root=repo,
                opener=should_not_call_network,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")
        self.assertEqual(len(audit_records), 1)

    def test_route_exists_check_rejects_policy_violation_without_network(self):
        with self.make_repo() as repo:
            result = lab_route_exists_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-active-route-policy-rejected",
                timeout_seconds=31,
                repo_root=repo,
                opener=should_not_call_network,
            )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "policy_rejected")

    def test_route_exists_check_rejects_absolute_route_without_network(self):
        with self.make_repo() as repo:
            result = lab_route_exists_check(
                target="http://127.0.0.1:3000",
                route_path="https://example.com/login",
                operator="tester",
                run_id="run-active-route-absolute-rejected",
                repo_root=repo,
                opener=should_not_call_network,
            )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")

    def test_route_exists_check_reports_request_failure(self):
        with self.make_repo() as repo:
            result = lab_route_exists_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-active-route-failure",
                repo_root=repo,
                opener=failing_request_opener,
            )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["findings"][0]["id"], "request_failed")


if __name__ == "__main__":
    unittest.main()
