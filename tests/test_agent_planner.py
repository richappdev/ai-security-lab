from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.bridge import execute_plan
from agents.manifest import ManifestError, load_tool_manifest
from agents.planner import AgentPlan, PlanValidationError, PlannedTool, build_plan, validate_plan
from reports.writer import render_aggregate_markdown_report


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


MANIFEST_TEXT = """version: 1

tools:
  - name: inspect_headers
    category: passive
    risk: passive
    entrypoint: tools/passive/headers.py
    allowed_targets_file: targets.allowlist
    requires_network: true
    timeout_seconds: 10
    audit_required: true
    description: Inspect HTTP response headers for common security headers.

  - name: inspect_cookies
    category: passive
    risk: passive
    entrypoint: tools/passive/cookies.py
    allowed_targets_file: targets.allowlist
    requires_network: true
    timeout_seconds: 10
    audit_required: true
    description: Inspect cookie attributes such as HttpOnly, Secure, and SameSite.

  - name: lab_route_exists_check
    category: active
    risk: active-low-risk
    entrypoint: tools/active/route_exists_check.py
    allowed_targets_file: targets.allowlist
    requires_network: true
    timeout_seconds: 10
    audit_required: true
    description: Send a single-request HEAD check for one known route path on an approved lab target only.
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


class FakeCookieHeaders:
    def get_all(self, name):
        if name.lower() == "set-cookie":
            return ["sessionid=abc123; Path=/; HttpOnly; SameSite=Lax"]
        return []


class FakeCookieResponse:
    status = 200
    headers = FakeCookieHeaders()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def fake_opener(request, timeout):
    method = getattr(request, "get_method", lambda: "GET")()
    if method == "HEAD":
        return FakeResponse()
    return FakeCookieResponse()


def prepare_repo(root: Path) -> None:
    (root / "tools").mkdir(parents=True, exist_ok=True)
    (root / "safety").mkdir(parents=True, exist_ok=True)
    (root / "tools" / "manifest.yml").write_text(MANIFEST_TEXT, encoding="utf-8")
    (root / "safety" / "policy.yml").write_text(POLICY_TEXT, encoding="utf-8")
    (root / "targets.allowlist").write_text("http://127.0.0.1:3000\n", encoding="utf-8")


class ManifestReaderTests(unittest.TestCase):
    def test_load_repo_manifest_includes_known_tools(self):
        entries = load_tool_manifest()
        names = {entry.name for entry in entries}
        self.assertIn("inspect_headers", names)
        self.assertIn("lab_auth_page_metadata_check", names)
        self.assertTrue(all(entry.audit_required for entry in entries))

    def test_load_manifest_rejects_empty_tools(self):
        with tempfile.TemporaryDirectory() as repo:
            root = Path(repo)
            (root / "tools").mkdir()
            (root / "tools" / "manifest.yml").write_text("version: 1\ntools:\n", encoding="utf-8")
            with self.assertRaises(ManifestError):
                load_tool_manifest(repo_root=root)


class PlannerContractTests(unittest.TestCase):
    def test_build_plan_validates_tools_against_manifest(self):
        with tempfile.TemporaryDirectory() as repo:
            root = Path(repo)
            prepare_repo(root)
            plan = build_plan(
                target="http://127.0.0.1:3000",
                objective="passive recon",
                risk_level="passive",
                tools=["inspect_headers", "inspect_cookies"],
                repo_root=root,
            )
            self.assertEqual(len(plan.tools), 2)
            self.assertEqual(plan.tools[0].name, "inspect_headers")

    def test_validate_plan_rejects_unknown_tool(self):
        with tempfile.TemporaryDirectory() as repo:
            root = Path(repo)
            prepare_repo(root)
            plan = AgentPlan(
                target="http://127.0.0.1:3000",
                objective="bad tool",
                risk_level="passive",
                tools=(PlannedTool(name="not_a_real_tool"),),
            )
            with self.assertRaises(PlanValidationError):
                validate_plan(plan, repo_root=root)

    def test_validate_plan_rejects_risk_exceeding_plan(self):
        with tempfile.TemporaryDirectory() as repo:
            root = Path(repo)
            prepare_repo(root)
            plan = AgentPlan(
                target="http://127.0.0.1:3000",
                objective="too risky",
                risk_level="passive",
                tools=(
                    PlannedTool(name="lab_route_exists_check", params={"route_path": "/login"}),
                ),
            )
            with self.assertRaises(PlanValidationError):
                validate_plan(plan, repo_root=root)

    def test_validate_plan_requires_route_path(self):
        with tempfile.TemporaryDirectory() as repo:
            root = Path(repo)
            prepare_repo(root)
            plan = AgentPlan(
                target="http://127.0.0.1:3000",
                objective="route check",
                risk_level="active-low-risk",
                tools=(PlannedTool(name="lab_route_exists_check"),),
            )
            with self.assertRaises(PlanValidationError):
                validate_plan(plan, repo_root=root)

    def test_validate_plan_reorders_passive_before_active(self):
        with tempfile.TemporaryDirectory() as repo:
            root = Path(repo)
            prepare_repo(root)
            plan = AgentPlan(
                target="http://127.0.0.1:3000",
                objective="mixed",
                risk_level="active-low-risk",
                tools=(
                    PlannedTool(name="lab_route_exists_check", params={"route_path": "/login"}),
                    PlannedTool(name="inspect_headers"),
                ),
            )
            ordered = validate_plan(plan, repo_root=root, reorder_passive_first=True)
            self.assertEqual(
                [tool.name for tool in ordered.tools],
                ["inspect_headers", "lab_route_exists_check"],
            )


class AggregateReportTests(unittest.TestCase):
    def test_render_aggregate_report_includes_tool_sections(self):
        report = render_aggregate_markdown_report(
            {
                "plan_id": "plan-1",
                "objective": "recon",
                "risk_level": "passive",
                "status": "completed",
                "target": "http://127.0.0.1:3000",
                "tools": ["inspect_headers", "inspect_cookies"],
                "started_at": "2026-07-14T00:00:00Z",
                "ended_at": "2026-07-14T00:00:02Z",
                "results": [
                    {
                        "tool": "inspect_headers",
                        "risk": "passive",
                        "status": "completed",
                        "findings": [
                            {
                                "id": "missing_security_header",
                                "severity": "info",
                                "evidence": "Content-Security-Policy header was not present.",
                            }
                        ],
                    },
                    {
                        "tool": "inspect_cookies",
                        "risk": "passive",
                        "status": "completed",
                        "findings": [],
                    },
                ],
            },
            operator="tester",
            run_id="run-agg",
            generated_at="2026-07-14T00:00:03Z",
        )
        self.assertIn("# Security Lab Aggregate Scan Report", report)
        self.assertIn("## Tool Results", report)
        self.assertIn("`inspect_headers`", report)
        self.assertIn("Content-Security-Policy", report)


class AgentPlannerBridgeTests(unittest.TestCase):
    def test_execute_plan_uses_service_helpers_not_direct_target_calls(self):
        with tempfile.TemporaryDirectory() as repo:
            root = Path(repo)
            prepare_repo(root)
            plan = build_plan(
                target="http://127.0.0.1:3000",
                objective="headers only",
                risk_level="passive",
                tools=["inspect_headers"],
                run_id="run-bridge",
                repo_root=root,
            )

            with patch("agents.bridge.service.run_passive_header_scan") as mocked:
                mocked.return_value = {
                    "tool": "inspect_headers",
                    "target": "http://127.0.0.1:3000",
                    "risk": "passive",
                    "status": "completed",
                    "findings": [],
                }
                result = execute_plan(plan, repo_root=root, opener=fake_opener, generate_report=True)

            mocked.assert_called_once()
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["results"][0]["tool"], "inspect_headers")
            self.assertTrue(Path(result["report"]["path"]).exists())

    def test_end_to_end_plan_execution_writes_audit_and_aggregate_report(self):
        with tempfile.TemporaryDirectory() as repo:
            root = Path(repo)
            prepare_repo(root)
            plan = build_plan(
                target="http://127.0.0.1:3000",
                objective="passive recon then route check",
                risk_level="active-low-risk",
                tools=[
                    {"name": "lab_route_exists_check", "params": {"route_path": "/login"}},
                    "inspect_headers",
                    "inspect_cookies",
                ],
                operator="planner-test",
                run_id="run-e2e-planner",
                timeout_seconds=10,
                repo_root=root,
            )

            result = execute_plan(plan, repo_root=root, opener=fake_opener, generate_report=True)

            self.assertEqual(result["status"], "completed")
            self.assertEqual(
                [item["tool"] for item in result["results"]],
                ["inspect_headers", "inspect_cookies", "lab_route_exists_check"],
            )

            audit_path = root / "logs" / "audit.jsonl"
            self.assertTrue(audit_path.exists())
            records = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line]
            tools_logged = {record.get("tool") for record in records}
            self.assertIn("inspect_headers", tools_logged)
            self.assertIn("inspect_cookies", tools_logged)
            self.assertIn("lab_route_exists_check", tools_logged)
            self.assertTrue(any(record.get("run_id") == "run-e2e-planner" for record in records))

            report_path = Path(result["report"]["path"])
            self.assertTrue(report_path.exists())
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("Security Lab Aggregate Scan Report", report_text)
            self.assertIn("inspect_headers", report_text)
            self.assertIn("lab_route_exists_check", report_text)

    def test_execute_plan_stops_when_scope_guard_rejects_target(self):
        with tempfile.TemporaryDirectory() as repo:
            root = Path(repo)
            prepare_repo(root)
            plan = build_plan(
                target="http://evil.example",
                objective="should fail",
                risk_level="passive",
                tools=["inspect_headers"],
                run_id="run-rejected",
                repo_root=root,
                validate=False,
            )
            # Re-validate only tools/risk against our temp manifest.
            plan = validate_plan(plan, repo_root=root)
            result = execute_plan(plan, repo_root=root, opener=fake_opener, generate_report=True)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(len(result["results"]), 1)
            self.assertEqual(result["results"][0]["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
