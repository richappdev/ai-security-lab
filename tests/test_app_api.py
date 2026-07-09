from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from app.api.service import (
    run_active_http_methods_scan,
    run_active_route_exists_scan,
    run_active_security_header_delta_scan,
    run_active_xss_reflection_scan,
    run_passive_header_scan,
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


class FakeOptionsResponse:
    status = 204
    headers = {"Allow": "GET, HEAD, OPTIONS"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def options_opener(request, timeout):
    return FakeOptionsResponse()


class FakeRouteResponse:
    status = 200
    headers = {"Content-Type": "text/html"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def route_opener(request, timeout):
    return FakeRouteResponse()


def security_header_delta_opener(request, timeout):
    if request.full_url == "http://127.0.0.1:3000":
        return FakeRouteResponse()
    if request.full_url == "http://127.0.0.1:3000/login":
        return FakeRouteResponse()
    raise AssertionError(f"unexpected URL: {request.full_url}")


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

    def test_active_http_methods_service_calls_guarded_tool(self):
        with self.make_repo() as repo:
            result = run_active_http_methods_scan(
                target="http://127.0.0.1:3000",
                operator="api-test",
                run_id="run-api-methods-test",
                repo_root=repo,
                opener=options_opener,
            )

        self.assertEqual(result["tool"], "lab_http_methods_check")
        self.assertEqual(result["risk"], "active-low-risk")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["allowed_methods"], ["GET", "HEAD", "OPTIONS"])

    def test_active_route_exists_service_calls_guarded_tool(self):
        with self.make_repo() as repo:
            result = run_active_route_exists_scan(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="api-test",
                run_id="run-api-route-test",
                repo_root=repo,
                opener=route_opener,
            )

        self.assertEqual(result["tool"], "lab_route_exists_check")
        self.assertEqual(result["risk"], "active-low-risk")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["exists"])

    def test_active_security_header_delta_service_calls_guarded_tool(self):
        with self.make_repo() as repo:
            result = run_active_security_header_delta_scan(
                target="http://127.0.0.1:3000",
                route_path="/login",
                operator="api-test",
                run_id="run-api-header-delta-test",
                repo_root=repo,
                opener=security_header_delta_opener,
            )

        self.assertEqual(result["tool"], "lab_security_header_delta_check")
        self.assertEqual(result["risk"], "active-low-risk")
        self.assertEqual(result["status"], "completed")
        self.assertIn("delta", result)


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

    def test_dashboard_redirects_to_static_ui(self):
        from fastapi.testclient import TestClient

        from app.api.main import app

        client = TestClient(app, follow_redirects=False)
        response = client.get("/")

        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["location"], "/ui/")

        page = TestClient(app).get("/ui/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("AI Security Lab Dashboard", page.text)
        self.assertIn("route existence", page.text)
        self.assertIn("7 tools", page.text)

    def test_static_ui_exposes_active_checks(self):
        from fastapi.testclient import TestClient

        from app.api.main import app

        client = TestClient(app)
        review_page = client.get("/ui/repo-review.html")
        testing_page = client.get("/ui/testing.html")

        self.assertEqual(review_page.status_code, 200)
        self.assertEqual(testing_page.status_code, 200)
        self.assertIn("route existence", review_page.text)
        self.assertIn("security header delta", review_page.text)
        self.assertIn("Route existence", testing_page.text)
        self.assertIn("Header delta", testing_page.text)
        self.assertIn("seven built-in checks", testing_page.text)

    def test_job_endpoints_read_and_cancel_registered_job(self):
        from fastapi.testclient import TestClient

        from app.api.main import app
        from app.api.jobs import job_registry

        job_id = "job-api-cancel-test"
        job_registry.create_job(
            job_id=job_id,
            tool="future_bulk_route_check",
            target="http://127.0.0.1:3000",
            operator="api-test",
        )

        client = TestClient(app)
        read_response = client.get(f"/jobs/{job_id}")
        cancel_response = client.post(f"/jobs/{job_id}/cancel")

        self.assertEqual(read_response.status_code, 200)
        self.assertEqual(read_response.json()["status"], "queued")
        self.assertEqual(cancel_response.status_code, 200)
        self.assertEqual(cancel_response.json()["status"], "cancel_requested")

    def test_job_endpoints_return_404_for_missing_job(self):
        from fastapi.testclient import TestClient

        from app.api.main import app

        client = TestClient(app)

        self.assertEqual(client.get("/jobs/missing-job").status_code, 404)
        self.assertEqual(client.post("/jobs/missing-job/cancel").status_code, 404)

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

    def test_active_http_methods_endpoint(self):
        from fastapi.testclient import TestClient

        from app.api.main import app

        with self.make_repo() as repo:
            with patch("app.api.main.configured_repo_root", return_value=Path(repo)):
                with patch(
                    "app.api.main.run_active_http_methods_scan",
                    return_value={
                        "tool": "lab_http_methods_check",
                        "target": "http://127.0.0.1:3000",
                        "risk": "active-low-risk",
                        "status": "completed",
                        "http_status": 204,
                        "allowed_methods": ["GET", "HEAD", "OPTIONS"],
                        "headers": {"Allow": "GET, HEAD, OPTIONS"},
                        "findings": [],
                        "started_at": "2026-07-07T00:00:00Z",
                        "ended_at": "2026-07-07T00:00:01Z",
                    },
                ):
                    client = TestClient(app)
                    response = client.post(
                        "/scan/active/http-methods",
                        json={
                            "target": "http://127.0.0.1:3000",
                            "operator": "api-test",
                            "run_id": "run-api-methods-test",
                            "rate_limit_per_minute": 30,
                            "generate_report": True,
                        },
                    )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "completed")

    def test_active_route_exists_endpoint(self):
        from fastapi.testclient import TestClient

        from app.api.main import app

        with self.make_repo() as repo:
            with patch("app.api.main.configured_repo_root", return_value=Path(repo)):
                with patch(
                    "app.api.main.run_active_route_exists_scan",
                    return_value={
                        "tool": "lab_route_exists_check",
                        "target": "http://127.0.0.1:3000",
                        "route_path": "/login",
                        "route_url": "http://127.0.0.1:3000/login",
                        "risk": "active-low-risk",
                        "status": "completed",
                        "http_status": 200,
                        "exists": True,
                        "headers": {},
                        "findings": [],
                        "started_at": "2026-07-07T00:00:00Z",
                        "ended_at": "2026-07-07T00:00:01Z",
                    },
                ):
                    client = TestClient(app)
                    response = client.post(
                        "/scan/active/route-exists",
                        json={
                            "target": "http://127.0.0.1:3000",
                            "route_path": "/login",
                            "operator": "api-test",
                            "run_id": "run-api-route-test",
                            "rate_limit_per_minute": 30,
                            "generate_report": True,
                        },
                    )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "completed")

    def test_active_security_header_delta_endpoint(self):
        from fastapi.testclient import TestClient

        from app.api.main import app

        with self.make_repo() as repo:
            with patch("app.api.main.configured_repo_root", return_value=Path(repo)):
                with patch(
                    "app.api.main.run_active_security_header_delta_scan",
                    return_value={
                        "tool": "lab_security_header_delta_check",
                        "target": "http://127.0.0.1:3000",
                        "route_path": "/login",
                        "route_url": "http://127.0.0.1:3000/login",
                        "risk": "active-low-risk",
                        "status": "completed",
                        "http_status": 200,
                        "root_http_status": 200,
                        "route_http_status": 200,
                        "root_headers": {},
                        "route_headers": {},
                        "headers": {},
                        "delta": [],
                        "findings": [],
                        "started_at": "2026-07-07T00:00:00Z",
                        "ended_at": "2026-07-07T00:00:01Z",
                    },
                ):
                    client = TestClient(app)
                    response = client.post(
                        "/scan/active/security-header-delta",
                        json={
                            "target": "http://127.0.0.1:3000",
                            "route_path": "/login",
                            "operator": "api-test",
                            "run_id": "run-api-header-delta-test",
                            "rate_limit_per_minute": 30,
                            "generate_report": True,
                        },
                    )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "completed")

    def test_active_security_header_delta_schema_includes_route_path(self):
        from fastapi.testclient import TestClient

        from app.api.main import app

        client = TestClient(app)
        schema = client.get("/openapi.json").json()
        request_schema = schema["components"]["schemas"]["ActiveSecurityHeaderDeltaRequest"]

        self.assertIn("route_path", request_schema["properties"])
        self.assertIn("route_path", request_schema["required"])


if __name__ == "__main__":
    unittest.main()
