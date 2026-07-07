from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.api.service import run_passive_header_scan


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


class AppServiceTests(unittest.TestCase):
    def make_repo(self) -> tempfile.TemporaryDirectory[str]:
        temp_dir = tempfile.TemporaryDirectory()
        root = Path(temp_dir.name)
        (root / "targets.allowlist").write_text("http://127.0.0.1:3000\n", encoding="utf-8")
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


@unittest.skipUnless(importlib.util.find_spec("fastapi"), "FastAPI is not installed")
class FastAPITests(unittest.TestCase):
    def make_repo(self) -> tempfile.TemporaryDirectory[str]:
        temp_dir = tempfile.TemporaryDirectory()
        root = Path(temp_dir.name)
        (root / "targets.allowlist").write_text("http://127.0.0.1:3000\n", encoding="utf-8")
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
                        },
                    )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "completed")


if __name__ == "__main__":
    unittest.main()
