"""Product core: tenancy, scenarios, evidence, isolation."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine

# Force isolated sqlite DB for unit tests (Postgres/RLS exercised when DATABASE_URL is postgres).
os.environ.pop("DATABASE_URL", None)

from app.auth import reset_engine_for_tests
from domain import GateResult, OrgRole
from enterprise import MeteringService, private_worker_pool_spec, siem_cef_line, webhook_payload
from integrations.ci_gates import build_check_run_payload, should_fail_release
from persistence import Base, init_db, session_scope
from persistence.repositories import (
    AuthorizationError,
    create_agent,
    create_organization,
    create_project,
    get_evidence_for_run,
    get_run,
    list_findings_for_run,
    resolve_principal,
)
from scenarios import list_scenario_keys, run_scenario_evaluation
from scenarios.runner import execute_evaluation, execute_suite
from workers.temporal_stub import InProcessTemporal, issue_capability


class ProductCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self.engine = create_engine(
            f"sqlite+pysqlite:///{self.db_path.as_posix()}",
            future=True,
            connect_args={"check_same_thread": False},
        )
        Base.metadata.drop_all(self.engine)
        init_db(self.engine)
        reset_engine_for_tests(self.engine)
        os.environ["EVIDENCE_LOCAL_ROOT"] = str(Path(self._tmpdir.name) / "evidence")

    def tearDown(self) -> None:
        self.engine.dispose()
        self._tmpdir.cleanup()

    def _bootstrap_two_orgs(self):
        with session_scope(engine=self.engine) as session:
            org_a = create_organization(session, "OrgA", "user-a")
            org_b = create_organization(session, "OrgB", "user-b")
            session.flush()
            pa = resolve_principal(session, "user-a", org_a.id)
            pb = resolve_principal(session, "user-b", org_b.id)
            project_a = create_project(session, pa, "ProjectA")
            project_b = create_project(session, pb, "ProjectB")
            session.flush()
            agent_a = create_agent(
                session, pa, project_a.id, "AgentA", allowed_tools=["read_public_doc"]
            )
            agent_b = create_agent(
                session, pb, project_b.id, "AgentB", allowed_tools=["read_public_doc"]
            )
            session.flush()
            return {
                "org_a": org_a.id,
                "org_b": org_b.id,
                "project_a": project_a.id,
                "project_b": project_b.id,
                "agent_a": agent_a.id,
                "agent_b": agent_b.id,
            }

    def test_scenario_pack_present(self):
        keys = list_scenario_keys()
        required = {
            "unauthorized_tool_invocation",
            "direct_prompt_injection",
            "indirect_prompt_injection",
            "sensitive_data_exfiltration",
            "approval_bypass",
        }
        self.assertTrue(required.issubset(set(keys)))
        self.assertGreaterEqual(len(keys), 5)

    def test_confused_deputy_fail_then_pass(self):
        ids = self._bootstrap_two_orgs()
        with session_scope(engine=self.engine) as session:
            principal = resolve_principal(session, "user-a", ids["org_a"])
            failed = execute_evaluation(
                session,
                principal,
                project_id=ids["project_a"],
                agent_id=ids["agent_a"],
                scenario_key="unauthorized_tool_invocation",
                behave_securely=False,
            )
            self.assertEqual(failed["gate_result"], GateResult.FAIL.value)
            self.assertTrue(failed["findings"])
            passed = execute_evaluation(
                session,
                principal,
                project_id=ids["project_a"],
                agent_id=ids["agent_a"],
                scenario_key="unauthorized_tool_invocation",
                behave_securely=True,
                idempotency_key="remediation-rerun-1",
            )
            self.assertEqual(passed["gate_result"], GateResult.PASS.value)
            evidence = get_evidence_for_run(session, principal, passed["run_id"])
            self.assertIsNotNone(evidence)
            self.assertEqual(evidence.result, GateResult.PASS.value)
            self.assertTrue(evidence.content_sha256.startswith("sha256:"))

    def test_all_core_scenarios_pass_when_secure(self):
        ids = self._bootstrap_two_orgs()
        keys = [
            "unauthorized_tool_invocation",
            "direct_prompt_injection",
            "indirect_prompt_injection",
            "sensitive_data_exfiltration",
            "approval_bypass",
            "cancel_scope_respect",
            "mcp_tool_poisoning",
            "resource_exhaustion",
        ]
        with session_scope(engine=self.engine) as session:
            principal = resolve_principal(session, "user-a", ids["org_a"])
            suite = execute_suite(
                session,
                principal,
                project_id=ids["project_a"],
                agent_id=ids["agent_a"],
                scenario_keys=keys,
                behave_securely=True,
            )
            self.assertEqual(suite["suite_gate_result"], GateResult.PASS.value)
            self.assertEqual(suite["failed_count"], 0)

    def test_cross_org_run_access_denied(self):
        ids = self._bootstrap_two_orgs()
        with session_scope(engine=self.engine) as session:
            principal_a = resolve_principal(session, "user-a", ids["org_a"])
            result = execute_evaluation(
                session,
                principal_a,
                project_id=ids["project_a"],
                agent_id=ids["agent_a"],
                scenario_key="unauthorized_tool_invocation",
                behave_securely=True,
            )
            run_id = result["run_id"]
            principal_b = resolve_principal(session, "user-b", ids["org_b"])
            with self.assertRaises(AuthorizationError):
                get_run(session, principal_b, run_id)
            with self.assertRaises(AuthorizationError):
                list_findings_for_run(session, principal_b, run_id)

    def test_viewer_cannot_create_project(self):
        with session_scope(engine=self.engine) as session:
            org = create_organization(session, "OrgView", "owner-1")
            session.flush()
            from persistence.repositories import add_membership

            add_membership(session, org.id, "viewer-1", OrgRole.VIEWER.value)
            session.flush()
            viewer = resolve_principal(session, "viewer-1", org.id)
            with self.assertRaises(AuthorizationError):
                create_project(session, viewer, "Nope")

    def test_idempotent_run_creation(self):
        ids = self._bootstrap_two_orgs()
        with session_scope(engine=self.engine) as session:
            principal = resolve_principal(session, "user-a", ids["org_a"])
            first = execute_evaluation(
                session,
                principal,
                project_id=ids["project_a"],
                agent_id=ids["agent_a"],
                scenario_key="direct_prompt_injection",
                behave_securely=True,
                idempotency_key="idem-1",
            )
            second = execute_evaluation(
                session,
                principal,
                project_id=ids["project_a"],
                agent_id=ids["agent_a"],
                scenario_key="direct_prompt_injection",
                behave_securely=False,
                idempotency_key="idem-1",
            )
            self.assertEqual(first["run_id"], second["run_id"])
            self.assertTrue(second.get("idempotent_replay"))

    def test_ci_gate_payload(self):
        payload = build_check_run_payload(
            suite_name="core",
            gate_result=GateResult.FAIL.value,
            failed_count=2,
            run_ids=["r1", "r2"],
            evidence_uris=["file://x"],
        )
        self.assertEqual(payload["conclusion"], "failure")
        self.assertTrue(should_fail_release(GateResult.FAIL.value, failed_count=2))

    def test_capability_and_temporal_stub(self):
        cap = issue_capability(
            organization_id="org",
            run_id="run",
            allowed_tools=["read_public_doc"],
            ttl_seconds=60,
        )
        self.assertTrue(cap.allows_tool("read_public_doc"))
        with self.assertRaises(PermissionError):
            cap.revalidate(tool="admin_delete")
        temporal = InProcessTemporal()
        handle = temporal.start_evaluation(
            run_id="run",
            execute=lambda: {"ok": True},
            capability=cap,
        )
        self.assertEqual(handle.status, "completed")
        self.assertEqual(handle.result, {"ok": True})

    def test_enterprise_helpers(self):
        meter = MeteringService()
        meter.record("org1", "evaluation.runs", 1.0, scenario="x")
        self.assertEqual(meter.usage_for("org1")["evaluation.runs"], 1.0)
        self.assertIn("CEF:0", siem_cef_line(finding_id="f1", severity="8", title="x"))
        self.assertEqual(webhook_payload("run.completed", {"id": "1"})["event"], "run.completed")
        self.assertEqual(private_worker_pool_spec(customer_id="c1")["status"], "spec_only")

    def test_insecure_scenarios_fail(self):
        from agents.adapters.synthetic import simulate

        for key in [
            "unauthorized_tool_invocation",
            "direct_prompt_injection",
            "indirect_prompt_injection",
            "sensitive_data_exfiltration",
            "approval_bypass",
        ]:
            events = simulate(key, allowed_tools=["read_public_doc"], behave_securely=False)
            outcome = run_scenario_evaluation(key, events)
            self.assertEqual(
                outcome.gate_result,
                GateResult.FAIL,
                msg=f"{key} should fail when insecure",
            )


class ProductApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "api.db"
        self.engine = create_engine(
            f"sqlite+pysqlite:///{self.db_path.as_posix()}",
            future=True,
            connect_args={"check_same_thread": False},
        )
        Base.metadata.drop_all(self.engine)
        init_db(self.engine)
        reset_engine_for_tests(self.engine)
        os.environ["EVIDENCE_LOCAL_ROOT"] = str(Path(self._tmpdir.name) / "evidence")
        from fastapi.testclient import TestClient
        from app.api.main import app

        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.engine.dispose()
        self._tmpdir.cleanup()

    def test_v1_org_project_agent_run_flow(self):
        headers = {"X-User-Sub": "alice"}
        org = self.client.post("/v1/organizations", json={"name": "Acme"}, headers=headers)
        self.assertEqual(org.status_code, 200, org.text)
        org_id = org.json()["id"]
        project = self.client.post(
            f"/v1/organizations/{org_id}/projects",
            json={"name": "Agents"},
            headers=headers,
        )
        self.assertEqual(project.status_code, 200, project.text)
        project_id = project.json()["id"]
        agent = self.client.post(
            f"/v1/organizations/{org_id}/projects/{project_id}/agents",
            json={"name": "bot", "allowed_tools": ["read_public_doc"]},
            headers=headers,
        )
        self.assertEqual(agent.status_code, 200, agent.text)
        agent_id = agent.json()["id"]
        scenarios = self.client.get("/v1/scenarios")
        self.assertEqual(scenarios.status_code, 200)
        self.assertIn("unauthorized_tool_invocation", scenarios.json()["scenarios"])
        run = self.client.post(
            f"/v1/organizations/{org_id}/runs",
            json={
                "project_id": project_id,
                "agent_id": agent_id,
                "scenario_key": "unauthorized_tool_invocation",
                "behave_securely": True,
            },
            headers=headers,
        )
        self.assertEqual(run.status_code, 200, run.text)
        self.assertEqual(run.json()["gate_result"], "pass")
        run_id = run.json()["run_id"]
        got = self.client.get(f"/v1/organizations/{org_id}/runs/{run_id}", headers=headers)
        self.assertEqual(got.status_code, 200)
        self.assertEqual(got.json()["gate_result"], "pass")

        # Cross-tenant denial
        headers_b = {"X-User-Sub": "bob"}
        org_b = self.client.post("/v1/organizations", json={"name": "Other"}, headers=headers_b)
        org_b_id = org_b.json()["id"]
        denied = self.client.get(
            f"/v1/organizations/{org_b_id}/runs/{run_id}",
            headers=headers_b,
        )
        self.assertEqual(denied.status_code, 403)


if __name__ == "__main__":
    unittest.main()
