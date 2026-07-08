from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from tools.active.xss_lab_check import lab_xss_reflection_check


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


class FakeReflectionResponse:
    status = 200
    headers = {}

    def __init__(self, body: str) -> None:
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self.body.encode("utf-8")


def reflecting_opener(request, timeout):
    parsed = urlparse(request.full_url)
    marker = parse_qs(parsed.query)["codex_reflection_check"][0]
    return FakeReflectionResponse(f"<html>{marker}</html>")


def non_reflecting_opener(request, timeout):
    return FakeReflectionResponse("<html>no marker here</html>")


def failing_opener(request, timeout):
    raise AssertionError("network opener should not be called")


class ActiveXssLabCheckTests(unittest.TestCase):
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

    def test_reflection_check_detects_harmless_marker_and_audits(self):
        with self.make_repo() as repo:
            result = lab_xss_reflection_check(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-active-reflect",
                repo_root=repo,
                opener=reflecting_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(result["tool"], "lab_xss_reflection_check")
        self.assertEqual(result["risk"], "active-low-risk")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 200)
        self.assertTrue(result["reflected"])
        self.assertEqual(result["findings"][0]["id"], "input_reflected")
        self.assertIn("codex_reflection_check=", result["probe_url"])
        self.assertEqual(len(audit_records), 2)
        self.assertEqual(audit_records[0]["status"], "started")
        self.assertEqual(audit_records[1]["status"], "completed")
        self.assertEqual(audit_records[1]["risk"], "active-low-risk")

    def test_reflection_check_reports_not_reflected(self):
        with self.make_repo() as repo:
            result = lab_xss_reflection_check(
                target="http://127.0.0.1:8080",
                operator="tester",
                run_id="run-active-no-reflect",
                repo_root=repo,
                opener=non_reflecting_opener,
            )

        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["reflected"])
        self.assertEqual(result["findings"][0]["id"], "input_not_reflected")

    def test_reflection_check_rejects_out_of_scope_without_network(self):
        with self.make_repo() as repo:
            result = lab_xss_reflection_check(
                target="https://example.com",
                operator="tester",
                run_id="run-active-rejected",
                repo_root=repo,
                opener=failing_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")
        self.assertEqual(len(audit_records), 1)

    def test_reflection_check_rejects_policy_violation_without_network(self):
        with self.make_repo() as repo:
            result = lab_xss_reflection_check(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-active-policy-rejected",
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
