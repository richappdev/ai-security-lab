from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from safety.audit_log import append_audit_record
from safety.scope_guard import ScopeError, check_target_allowed, require_target_allowed
from tools.passive.cookies import inspect_cookies
from tools.passive.forms import discover_forms
from tools.passive.headers import inspect_headers


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


class FakeResponse:
    status = 200
    headers = {
        "Server": "fake-lab",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def fake_opener(request, timeout):
    return FakeResponse()


class FakeCookieHeaders:
    def get_all(self, name):
        if name.lower() == "set-cookie":
            return [
                "sessionid=abc123; Path=/; HttpOnly; SameSite=Lax",
                "theme=light; Path=/",
            ]
        return []


class FakeCookieResponse:
    status = 200
    headers = FakeCookieHeaders()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def fake_cookie_opener(request, timeout):
    return FakeCookieResponse()


def failing_opener(request, timeout):
    raise AssertionError("network opener should not be called")


class FakeFormResponse:
    status = 200
    headers = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return b"""
        <html>
          <body>
            <form method="post" action="/login">
              <input name="username">
              <input name="password" type="password">
              <textarea name="note"></textarea>
              <select name="role"></select>
            </form>
            <form action="https://example.com/collect">
              <input name="token" type="hidden">
            </form>
          </body>
        </html>
        """


def fake_form_opener(request, timeout):
    return FakeFormResponse()


class SafetyAndHeadersTests(unittest.TestCase):
    def make_repo(self) -> tempfile.TemporaryDirectory[str]:
        temp_dir = tempfile.TemporaryDirectory()
        root = Path(temp_dir.name)
        (root / "targets.allowlist").write_text(
            "\n".join(
                [
                    "http://127.0.0.1:3000",
                    "http://localhost:3000",
                    "http://juice-shop.local:3000",
                ]
            ),
            encoding="utf-8",
        )
        (root / "safety").mkdir()
        (root / "safety" / "policy.yml").write_text(POLICY_TEXT, encoding="utf-8")
        return temp_dir

    def test_allowlisted_local_target_passes(self):
        with self.make_repo() as repo:
            decision = require_target_allowed("http://127.0.0.1:3000/", repo)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.normalized_target, "http://127.0.0.1:3000")

    def test_unknown_or_public_target_is_rejected(self):
        with self.make_repo() as repo:
            public_decision = check_target_allowed("https://example.com", repo)
            local_decision = check_target_allowed("http://127.0.0.1:9999", repo)

            with self.assertRaises(ScopeError):
                require_target_allowed("https://example.com", repo)

        self.assertFalse(public_decision.allowed)
        self.assertFalse(local_decision.allowed)

    def test_audit_log_writes_jsonl(self):
        with self.make_repo() as repo:
            path = append_audit_record(
                {
                    "run_id": "run-1",
                    "operator": "tester",
                    "tool": "inspect_headers",
                    "target": "http://127.0.0.1:3000",
                    "risk": "passive",
                    "started_at": "2026-07-07T00:00:00Z",
                    "ended_at": "2026-07-07T00:00:01Z",
                    "status": "completed",
                    "result_summary": "ok",
                },
                repo_root=repo,
            )
            record = json.loads(path.read_text(encoding="utf-8").splitlines()[0])

        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["tool"], "inspect_headers")

    def test_inspect_headers_output_shape_and_audit(self):
        with self.make_repo() as repo:
            result = inspect_headers(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-headers",
                repo_root=repo,
                opener=fake_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["tool"], "inspect_headers")
        self.assertEqual(result["risk"], "passive")
        self.assertEqual(result["status"], "completed")
        self.assertGreaterEqual(len(result["findings"]), 1)
        self.assertEqual(len(audit_records), 2)

    def test_inspect_headers_rejects_out_of_scope_without_network(self):
        with self.make_repo() as repo:
            result = inspect_headers(
                target="https://example.com",
                operator="tester",
                run_id="run-rejected",
                repo_root=repo,
                opener=failing_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")
        self.assertEqual(len(audit_records), 1)

    def test_inspect_headers_rejects_timeout_above_policy_without_network(self):
        with self.make_repo() as repo:
            result = inspect_headers(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-timeout-rejected",
                timeout_seconds=31,
                repo_root=repo,
                opener=failing_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "policy_rejected")
        self.assertEqual(len(audit_records), 1)

    def test_inspect_headers_passes_resolved_timeout_to_opener(self):
        observed: dict[str, int] = {}

        def observing_opener(request, timeout):
            observed["timeout"] = timeout
            return FakeResponse()

        with self.make_repo() as repo:
            result = inspect_headers(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-timeout-observed",
                timeout_seconds=None,
                repo_root=repo,
                opener=observing_opener,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(observed["timeout"], 10)

    def test_inspect_cookies_output_shape_and_audit(self):
        with self.make_repo() as repo:
            result = inspect_cookies(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-cookies",
                repo_root=repo,
                opener=fake_cookie_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["tool"], "inspect_cookies")
        self.assertEqual(result["risk"], "passive")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["cookies"]), 2)
        self.assertTrue(any(finding["id"] == "cookie_missing_attribute" for finding in result["findings"]))
        self.assertEqual(len(audit_records), 2)

    def test_inspect_cookies_rejects_out_of_scope_without_network(self):
        with self.make_repo() as repo:
            result = inspect_cookies(
                target="https://example.com",
                operator="tester",
                run_id="run-cookies-rejected",
                repo_root=repo,
                opener=failing_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")
        self.assertEqual(len(audit_records), 1)

    def test_discover_forms_with_fake_html(self):
        with self.make_repo() as repo:
            result = discover_forms(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-forms",
                repo_root=repo,
                opener=fake_form_opener,
            )

        self.assertEqual(result["tool"], "discover_forms")
        self.assertEqual(result["risk"], "passive")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(len(result["forms"]), 2)
        self.assertEqual(result["forms"][0]["method"], "POST")
        self.assertEqual(result["forms"][0]["action"], "http://127.0.0.1:3000/login")
        self.assertTrue(result["forms"][0]["same_origin"])
        self.assertEqual(
            result["forms"][0]["inputs"],
            [
                {"name": "username", "type": "text"},
                {"name": "password", "type": "password"},
                {"name": "note", "type": "textarea"},
                {"name": "role", "type": "select"},
            ],
        )
        self.assertFalse(result["forms"][1]["same_origin"])
        self.assertTrue(any(finding["id"] == "cross_origin_form_action" for finding in result["findings"]))

    def test_discover_forms_rejects_out_of_scope_without_network(self):
        with self.make_repo() as repo:
            result = discover_forms(
                target="https://example.com",
                operator="tester",
                run_id="run-forms-rejected",
                repo_root=repo,
                opener=failing_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")
        self.assertEqual(len(audit_records), 1)

    def test_discover_forms_audit_log_shape(self):
        with self.make_repo() as repo:
            discover_forms(
                target="http://127.0.0.1:3000",
                operator="tester",
                run_id="run-forms-audit",
                repo_root=repo,
                opener=fake_form_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(audit_records), 2)
        self.assertEqual(audit_records[0]["tool"], "discover_forms")
        self.assertEqual(audit_records[0]["status"], "started")
        self.assertEqual(audit_records[1]["status"], "completed")
        self.assertEqual(audit_records[1]["result_summary"], "2 form(s), 1 finding(s)")


if __name__ == "__main__":
    unittest.main()
