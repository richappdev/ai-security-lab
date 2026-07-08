from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from app.api.service import run_active_xss_reflection_scan, run_passive_header_scan


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
  - local_lab_active_checks

blocked_activity:
  - public_target_testing

audit:
  required: true
  output_directory: logs
  fields:
    - run_id
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


class AppServiceTests(unittest.TestCase):
    def make_repo(self) -> tempfile.TemporaryDirectory[str]:
        temp_dir = tempfile.TemporaryDirectory()
        root = Path(temp_dir.name)
        (root / "targets.allowlist").write_text("http://127.0.0.1:3000\n", encoding="utf-8")
        (root / "safety").mkdir()
        (root / "safety" / "policy.yml").write_text(POLICY_TEXT, encoding="utf-8")
        return temp_dir

    def test_header_scan_service_calls_guarded_tool(self):
        with self.make_repo() as repo:
            result = run_passive_header_scan(
                target="http://127.0.0.1:3000",
                operator="api-test",
                run_id="run-api-test",
                repo_root=repo,
                opener=fake_opener,
            )

        self.assertEqual(result["tool"], "inspect_headers")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["target"], "http://127.0.0.1:3000")

    def test_header_scan_service_can_write_report(self):
        with self.make_repo() as repo:
            result = run_passive_header_scan(
                target="http://127.0.0.1:3000",
                operator="api-test",
                run_id="run-api-report",
                repo_root=repo,
                opener=fake_opener,
                generate_report=True,
            )

            report_path = Path(result["report"]["path"])

            self.assertEqual(result["status"], "completed")
            self.assertTrue(report_path.exists())
            self.assertEqual(report_path.name, "run-api-report-inspect_headers.md")

    def test_active_xss_reflection_service_calls_guarded_tool(self):
        with self.make_repo() as repo:
            result = run_active_xss_reflection_scan(
                target="http://127.0.0.1:3000",
                operator="api-test",
                run_id="run-api-active-test",
                repo_root=repo,
                opener=reflecting_opener,
            )

        self.assertEqual(result["tool"], "lab_xss_reflection_check")
        self.assertEqual(result["risk"], "active-low-risk")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["reflected"])

    def test_active_xss_reflection_service_can_write_report(self):
        with self.make_repo() as repo:
            result = run_active_xss_reflection_scan(
                target="http://127.0.0.1:3000",
                operator="api-test",
                run_id="run-api-active-report",
                repo_root=repo,
                opener=reflecting_opener,
                generate_report=True,
            )

            report_path = Path(result["report"]["path"])

            self.assertEqual(result["status"], "completed")
            self.assertTrue(report_path.exists())
            self.assertEqual(report_path.name, "run-api-active-report-lab_xss_reflection_check.md")


@unittest.skipUnless(importlib.util.find_spec("fastapi"), "FastAPI is not installed")
class FastAPITests(unittest.TestCase):
    def make_repo(self) -> tempfile.TemporaryDirectory[str]:
        temp_dir = tempfile.TemporaryDirectory()
        root = Path(temp_dir.name)
        (root / "targets.allowlist").write_text("http://127.0.0.1:3000\n", encoding="utf-8")
        (root / "safety").mkdir()
        (root / "safety" / "policy.yml").write_text(POLICY_TEXT, encoding="utf-8")
        return temp_dir

    def test_health_endpoint(self):
        from fastapi.testclient import TestClient

        from app.api.main import app

        client = TestClient(app)
        response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_passive_headers_endpoint(self):
        from fastapi.testclient import TestClient

        from app.api.main import app

        with self.make_repo() as repo:
            with patch("app.api.main.configured_repo_root", return_value=Path(repo)):
                with patch(
                    "app.api.main.run_passive_header_scan",
                    return_value={
                        "tool": "inspect_headers",
                        "target": "http://127.0.0.1:3000",
                        "risk": "passive",
                        "status": "completed",
                        "http_status": 200,
                        "headers": {},
                        "findings": [],
                        "started_at": "2026-07-07T00:00:00Z",
                        "ended_at": "2026-07-07T00:00:01Z",
                    },
                ):
                    client = TestClient(app)
                    response = client.post(
                        "/scan/passive/headers",
                        json={
                            "target": "http://127.0.0.1:3000",
                            "operator": "api-test",
                            "run_id": "run-api-test",
                            "generate_report": True,
                        },
                    )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "completed")

    def test_active_xss_reflection_endpoint(self):
        from fastapi.testclient import TestClient

        from app.api.main import app

        with self.make_repo() as repo:
            with patch("app.api.main.configured_repo_root", return_value=Path(repo)):
                with patch(
                    "app.api.main.run_active_xss_reflection_scan",
                    return_value={
                        "tool": "lab_xss_reflection_check",
                        "target": "http://127.0.0.1:3000",
                        "risk": "active-low-risk",
                        "status": "completed",
                        "http_status": 200,
                        "probe_url": "http://127.0.0.1:3000/?codex_reflection_check=marker",
                        "reflected": True,
                        "findings": [],
                        "started_at": "2026-07-07T00:00:00Z",
                        "ended_at": "2026-07-07T00:00:01Z",
                    },
                ):
                    client = TestClient(app)
                    response = client.post(
                        "/scan/active/xss-reflection",
                        json={
                            "target": "http://127.0.0.1:3000",
                            "operator": "api-test",
                            "run_id": "run-api-active-test",
                            "rate_limit_per_minute": 30,
                            "generate_report": True,
                        },
                    )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "completed")


if __name__ == "__main__":
    unittest.main()
