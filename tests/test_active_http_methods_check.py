from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.active.http_methods_check import lab_http_methods_check


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


class FakeOptionsResponse:
    status = 204

    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def methods_opener(request, timeout):
    if request.get_method() != "OPTIONS":
        raise AssertionError("expected OPTIONS request")
    return FakeOptionsResponse({"Allow": "GET, HEAD, OPTIONS"})


def risky_methods_opener(request, timeout):
    return FakeOptionsResponse({"Allow": "GET, PUT, DELETE"})


def failing_opener(request, timeout):
    raise AssertionError("network opener should not be called")


class ActiveHttpMethodsCheckTests(unittest.TestCase):
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

    def test_http_methods_check_reports_allow_header_and_audits(self):
        with self.make_repo() as repo:
            result = lab_http_methods_check(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-active-methods",
                repo_root=repo,
                opener=methods_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(result["tool"], "lab_http_methods_check")
        self.assertEqual(result["risk"], "active-low-risk")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 204)
        self.assertEqual(result["allowed_methods"], ["GET", "HEAD", "OPTIONS"])
        self.assertEqual(result["findings"][0]["id"], "methods_reported")
        self.assertEqual(len(audit_records), 2)
        self.assertEqual(audit_records[0]["status"], "started")
        self.assertEqual(audit_records[1]["status"], "completed")

    def test_http_methods_check_flags_risky_methods(self):
        with self.make_repo() as repo:
            result = lab_http_methods_check(
                target="http://127.0.0.1:8080",
                operator="tester",
                run_id="run-active-risky-methods",
                repo_root=repo,
                opener=risky_methods_opener,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["allowed_methods"], ["DELETE", "GET", "PUT"])
        self.assertEqual(result["findings"][0]["id"], "risky_methods_allowed")

    def test_http_methods_check_rejects_out_of_scope_without_network(self):
        with self.make_repo() as repo:
            result = lab_http_methods_check(
                target="https://example.com",
                operator="tester",
                run_id="run-active-methods-rejected",
                repo_root=repo,
                opener=failing_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")
        self.assertEqual(len(audit_records), 1)

    def test_http_methods_check_rejects_policy_violation_without_network(self):
        with self.make_repo() as repo:
            result = lab_http_methods_check(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-active-methods-policy-rejected",
                timeout_seconds=31,
                repo_root=repo,
                opener=failing_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "policy_rejected")
        self.assertEqual(len(audit_records), 1)


if __name__ == "__main__":
    unittest.main()
