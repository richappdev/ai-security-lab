from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.active.security_header_delta_check import lab_security_header_delta_check


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


class FakeGetResponse:
    def __init__(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def missing_header_opener(request, timeout):
    if request.get_method() != "GET":
        raise AssertionError("expected GET request")
    if request.full_url == "http://127.0.0.1:3000":
        return FakeGetResponse(200, {"X-Frame-Options": "DENY"})
    if request.full_url == "http://127.0.0.1:3000/login":
        return FakeGetResponse(200, {})
    raise AssertionError(f"unexpected URL: {request.full_url}")


def changed_header_opener(request, timeout):
    if request.full_url == "http://127.0.0.1:3000":
        return FakeGetResponse(200, {"Referrer-Policy": "same-origin"})
    if request.full_url == "http://127.0.0.1:3000/account":
        return FakeGetResponse(200, {"Referrer-Policy": "no-referrer"})
    raise AssertionError(f"unexpected URL: {request.full_url}")


def added_header_opener(request, timeout):
    if request.full_url == "http://127.0.0.1:3000":
        return FakeGetResponse(200, {})
    if request.full_url == "http://127.0.0.1:3000/admin":
        return FakeGetResponse(200, {"X-Content-Type-Options": "nosniff"})
    raise AssertionError(f"unexpected URL: {request.full_url}")


def consistent_headers_opener(request, timeout):
    headers = {"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY"}
    if request.full_url in {"http://127.0.0.1:3000", "http://127.0.0.1:3000/login"}:
        return FakeGetResponse(200, headers)
    raise AssertionError(f"unexpected URL: {request.full_url}")


def root_failure_opener(request, timeout):
    if request.full_url == "http://127.0.0.1:3000":
        raise RuntimeError("root unavailable")
    return FakeGetResponse(200, {})


def route_failure_opener(request, timeout):
    if request.full_url == "http://127.0.0.1:3000":
        return FakeGetResponse(200, {})
    raise RuntimeError("route unavailable")


def should_not_call_network(request, timeout):
    raise AssertionError("network opener should not be called")


class ActiveSecurityHeaderDeltaCheckTests(unittest.TestCase):
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

    def test_security_header_delta_reports_missing_route_header_and_audits(self):
        with self.make_repo() as repo:
            result = lab_security_header_delta_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-header-delta",
                repo_root=repo,
                opener=missing_header_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(result["tool"], "lab_security_header_delta_check")
        self.assertEqual(result["risk"], "active-low-risk")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["root_http_status"], 200)
        self.assertEqual(result["route_http_status"], 200)
        self.assertEqual(result["route_url"], "http://127.0.0.1:3000/login")
        self.assertEqual(result["delta"][0]["type"], "missing_on_route")
        self.assertEqual(result["findings"][0]["id"], "route_missing_security_header")
        self.assertEqual(len(audit_records), 2)
        self.assertEqual(audit_records[0]["status"], "started")
        self.assertEqual(audit_records[1]["status"], "completed")

    def test_security_header_delta_reports_changed_route_header(self):
        with self.make_repo() as repo:
            result = lab_security_header_delta_check(
                target="http://127.0.0.1:3000",
                route_path="/account",
                operator="tester",
                run_id="run-header-delta-changed",
                repo_root=repo,
                opener=changed_header_opener,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["delta"][0]["type"], "changed_on_route")
        self.assertEqual(result["findings"][0]["id"], "route_changed_security_header")

    def test_security_header_delta_reports_added_route_header(self):
        with self.make_repo() as repo:
            result = lab_security_header_delta_check(
                target="http://127.0.0.1:3000",
                route_path="/admin",
                operator="tester",
                run_id="run-header-delta-added",
                repo_root=repo,
                opener=added_header_opener,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["delta"][0]["type"], "added_on_route")
        self.assertEqual(result["findings"][0]["id"], "route_adds_security_header")

    def test_security_header_delta_reports_consistent_headers(self):
        with self.make_repo() as repo:
            result = lab_security_header_delta_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-header-delta-consistent",
                repo_root=repo,
                opener=consistent_headers_opener,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["delta"], [])
        self.assertEqual(result["findings"][0]["id"], "security_headers_consistent")

    def test_security_header_delta_rejects_out_of_scope_without_network(self):
        with self.make_repo() as repo:
            result = lab_security_header_delta_check(
                target="https://example.com",
                route_path="/login",
                operator="tester",
                run_id="run-header-delta-rejected",
                repo_root=repo,
                opener=should_not_call_network,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")
        self.assertEqual(len(audit_records), 1)

    def test_security_header_delta_rejects_policy_violation_without_network(self):
        with self.make_repo() as repo:
            result = lab_security_header_delta_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-header-delta-policy-rejected",
                timeout_seconds=31,
                repo_root=repo,
                opener=should_not_call_network,
            )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "policy_rejected")

    def test_security_header_delta_rejects_invalid_route_without_network(self):
        with self.make_repo() as repo:
            result = lab_security_header_delta_check(
                target="http://127.0.0.1:3000",
                route_path="https://example.com/login",
                operator="tester",
                run_id="run-header-delta-absolute-rejected",
                repo_root=repo,
                opener=should_not_call_network,
            )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")

    def test_security_header_delta_reports_root_request_failure(self):
        with self.make_repo() as repo:
            result = lab_security_header_delta_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-header-delta-root-failure",
                repo_root=repo,
                opener=root_failure_opener,
            )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["findings"][0]["id"], "request_failed")

    def test_security_header_delta_reports_route_request_failure(self):
        with self.make_repo() as repo:
            result = lab_security_header_delta_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-header-delta-route-failure",
                repo_root=repo,
                opener=route_failure_opener,
            )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["findings"][0]["id"], "request_failed")


if __name__ == "__main__":
    unittest.main()
