from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from safety.audit_log import append_audit_record
from safety.scope_guard import ScopeError, check_target_allowed, require_target_allowed
from tools.passive.cookies import inspect_cookies
from tools.passive.headers import inspect_headers


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


if __name__ == "__main__":
    unittest.main()
