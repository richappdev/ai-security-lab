from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError

from tools.active.auth_page_metadata_check import lab_auth_page_metadata_check


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
    def __init__(self, status: int, body: str, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self.body.encode("utf-8")

    def close(self):
        self.closed = True
        return None


def auth_page_opener(request, timeout):
    if request.get_method() != "GET":
        raise AssertionError("expected GET request")
    if request.data is not None:
        raise AssertionError("auth metadata check must not submit request body data")
    if request.full_url != "http://127.0.0.1:3000/login":
        raise AssertionError(f"unexpected URL: {request.full_url}")
    return FakeGetResponse(
        200,
        """
        <html>
          <head><title>Login</title></head>
          <body>
            <form method="post" action="/login">
              <input type="text" name="username">
              <input type="password" name="password">
              <input type="hidden" name="csrf_token">
            </form>
          </body>
        </html>
        """,
        {"Content-Type": "text/html"},
    )


def non_auth_page_opener(request, timeout):
    return FakeGetResponse(
        200,
        "<html><head><title>Home</title></head><body><form><input name='search'></form></body></html>",
    )


def http_error_opener(request, timeout):
    raise HTTPError(
        url=request.full_url,
        code=404,
        msg="Not Found",
        hdrs={"Content-Type": "text/html"},
        fp=FakeGetResponse(404, "<html><title>Login missing</title></html>"),
    )


def request_failure_opener(request, timeout):
    raise RuntimeError("connection refused")


def should_not_call_network(request, timeout):
    raise AssertionError("network opener should not be called")


class ActiveAuthPageMetadataCheckTests(unittest.TestCase):
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

    def test_auth_page_metadata_reports_login_structure_and_audits(self):
        with self.make_repo() as repo:
            result = lab_auth_page_metadata_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-auth-metadata",
                repo_root=repo,
                opener=auth_page_opener,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(result["tool"], "lab_auth_page_metadata_check")
        self.assertEqual(result["risk"], "active-low-risk")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["route_url"], "http://127.0.0.1:3000/login")
        self.assertTrue(result["metadata"]["has_login_indicators"])
        self.assertEqual(result["metadata"]["forms_count"], 1)
        self.assertEqual(result["metadata"]["password_fields_count"], 1)
        self.assertEqual(result["metadata"]["username_like_fields_count"], 1)
        self.assertEqual(result["metadata"]["csrf_like_fields_count"], 1)
        self.assertEqual(result["findings"][0]["id"], "auth_page_metadata_detected")
        self.assertEqual(len(audit_records), 2)
        self.assertEqual(audit_records[0]["status"], "started")
        self.assertEqual(audit_records[1]["status"], "completed")

    def test_auth_page_metadata_reports_non_auth_page(self):
        with self.make_repo() as repo:
            result = lab_auth_page_metadata_check(
                target="http://127.0.0.1:3000",
                route_path="/",
                operator="tester",
                run_id="run-auth-metadata-home",
                repo_root=repo,
                opener=non_auth_page_opener,
            )

        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["metadata"]["has_login_indicators"])
        self.assertEqual(result["findings"][0]["id"], "auth_page_metadata_not_detected")
        self.assertEqual(result["findings"][1]["id"], "auth_form_without_password_field")

    def test_auth_page_metadata_treats_http_error_body_as_completed(self):
        with self.make_repo() as repo:
            result = lab_auth_page_metadata_check(
                target="http://127.0.0.1:3000",
                route_path="/missing-login",
                operator="tester",
                run_id="run-auth-metadata-http-error",
                repo_root=repo,
                opener=http_error_opener,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http_status"], 404)
        self.assertTrue(result["metadata"]["has_login_indicators"])

    def test_auth_page_metadata_rejects_out_of_scope_without_network(self):
        with self.make_repo() as repo:
            result = lab_auth_page_metadata_check(
                target="https://example.com",
                route_path="/login",
                operator="tester",
                run_id="run-auth-metadata-rejected",
                repo_root=repo,
                opener=should_not_call_network,
            )
            audit_path = Path(repo) / "logs" / "audit.jsonl"
            audit_records = audit_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")
        self.assertEqual(len(audit_records), 1)

    def test_auth_page_metadata_rejects_policy_violation_without_network(self):
        with self.make_repo() as repo:
            result = lab_auth_page_metadata_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-auth-metadata-policy-rejected",
                timeout_seconds=31,
                repo_root=repo,
                opener=should_not_call_network,
            )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "policy_rejected")

    def test_auth_page_metadata_rejects_absolute_route_without_network(self):
        with self.make_repo() as repo:
            result = lab_auth_page_metadata_check(
                target="http://127.0.0.1:3000",
                route_path="https://example.com/login",
                operator="tester",
                run_id="run-auth-metadata-absolute-rejected",
                repo_root=repo,
                opener=should_not_call_network,
            )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["findings"][0]["id"], "target_rejected")

    def test_auth_page_metadata_reports_request_failure(self):
        with self.make_repo() as repo:
            result = lab_auth_page_metadata_check(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="tester",
                run_id="run-auth-metadata-failure",
                repo_root=repo,
                opener=request_failure_opener,
            )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["findings"][0]["id"], "request_failed")


if __name__ == "__main__":
    unittest.main()
