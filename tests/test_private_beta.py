"""Private Beta: OIDC policy, durable runs, signed evidence, CI gates, findings lifecycle."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine

os.environ.pop("DATABASE_URL", None)
os.environ["ALLOW_DEV_AUTH"] = "true"
os.environ["USE_DURABLE_RUNS"] = "true"
os.environ["EVIDENCE_SIGNING_KEY"] = "test-evidence-key"

from app.auth import allow_dev_auth, auth_config, reset_engine_for_tests
from domain import FindingStatus, GateResult
from evidence import build_manifest, build_sarif, sign_payload, verify_signature
from integrations.ci_gates import build_check_run_payload, publish_github_check_run, should_fail_release
from persistence import Base, init_db, session_scope
from persistence.repositories import (
    create_agent,
    create_organization,
    create_project,
    list_project_findings,
    resolve_principal,
    update_finding_status,
)
from scenarios.runner import execute_evaluation, execute_suite
from workers.durable import DurableEvaluationEngine, get_durable_engine
from workers.temporal_stub import issue_capability


class PrivateBetaTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "beta.db"
        self.engine = create_engine(
            f"sqlite+pysqlite:///{self.db_path.as_posix()}",
            future=True,
            connect_args={"check_same_thread": False},
        )
        Base.metadata.drop_all(self.engine)
        init_db(self.engine)
        reset_engine_for_tests(self.engine)
        os.environ["EVIDENCE_LOCAL_ROOT"] = str(Path(self._tmpdir.name) / "evidence")
        os.environ["ALLOW_DEV_AUTH"] = "true"

    def tearDown(self) -> None:
        self.engine.dispose()
        self._tmpdir.cleanup()

    def _org(self):
        with session_scope(engine=self.engine) as session:
            org = create_organization(session, "BetaOrg", "alice")
            session.flush()
            principal = resolve_principal(session, "alice", org.id)
            project = create_project(session, principal, "proj")
            session.flush()
            agent = create_agent(
                session, principal, project.id, "agent", allowed_tools=["read_public_doc"]
            )
            session.flush()
            return org.id, project.id, agent.id

    def test_auth_config_and_dev_gate(self):
        cfg = auth_config()
        self.assertIn("allow_dev_auth", cfg)
        self.assertTrue(allow_dev_auth())
        os.environ["ALLOW_DEV_AUTH"] = "false"
        self.assertFalse(allow_dev_auth())
        os.environ["ALLOW_DEV_AUTH"] = "true"

    def test_durable_suite_and_signed_evidence(self):
        org_id, project_id, agent_id = self._org()
        with session_scope(engine=self.engine) as session:
            principal = resolve_principal(session, "alice", org_id)
            result = execute_evaluation(
                session,
                principal,
                project_id=project_id,
                agent_id=agent_id,
                scenario_key="unauthorized_tool_invocation",
                behave_securely=True,
                durable=True,
            )
            self.assertEqual(result["gate_result"], GateResult.PASS.value)
            self.assertIn("workflow_id", result)
            self.assertTrue(result["manifest_signature"].startswith("hmac-sha256:"))
            self.assertTrue((result.get("uris") or {}).get("bundle"))
            desc = get_durable_engine().describe(result["workflow_id"])
            self.assertEqual(desc["status"], "completed")
            self.assertTrue(desc["heartbeats"])

    def test_evidence_signature_roundtrip(self):
        manifest, _ = build_manifest(
            organization_id="o",
            project_id="p",
            run_id="r",
            scenario_key="unauthorized_tool_invocation",
            scenario_version="1.0.0",
            agent_version="1.0.0",
            gate_result=GateResult.PASS,
            events=[],
            findings=[],
            sign=True,
        )
        unsigned = dict(manifest)
        sig = unsigned.pop("signature")
        unsigned["signature"] = None
        self.assertTrue(verify_signature(unsigned, sig))
        self.assertFalse(verify_signature(unsigned, "hmac-sha256:deadbeef"))
        sarif = build_sarif(
            run_id="r",
            scenario_key="x",
            gate_result="fail",
            findings=[{"assertion_id": "a", "title": "t", "severity": "high"}],
        )
        self.assertEqual(sarif["version"], "2.1.0")

    def test_findings_lifecycle(self):
        org_id, project_id, agent_id = self._org()
        with session_scope(engine=self.engine) as session:
            principal = resolve_principal(session, "alice", org_id)
            failed = execute_evaluation(
                session,
                principal,
                project_id=project_id,
                agent_id=agent_id,
                scenario_key="direct_prompt_injection",
                behave_securely=False,
                durable=True,
            )
            self.assertEqual(failed["gate_result"], GateResult.FAIL.value)
            findings = list_project_findings(session, principal, project_id)
            self.assertTrue(findings)
            updated = update_finding_status(
                session,
                principal,
                findings[0].id,
                status=FindingStatus.ASSIGNED.value,
                assignee="alice",
                note="triaging",
            )
            self.assertEqual(updated.status, FindingStatus.ASSIGNED.value)
            self.assertEqual(updated.detail.get("assignee"), "alice")

    def test_release_gate_dry_run_payload(self):
        payload = build_check_run_payload(
            suite_name="core",
            gate_result=GateResult.FAIL.value,
            failed_count=1,
            run_ids=["r1"],
            evidence_uris=["file://x"],
            head_sha="abc123",
        )
        self.assertEqual(payload["conclusion"], "failure")
        self.assertEqual(payload["head_sha"], "abc123")
        published = publish_github_check_run(payload)
        self.assertTrue(published["dry_run"])
        self.assertTrue(should_fail_release(GateResult.FAIL.value, failed_count=1))

    def test_capability_expiry_enforced(self):
        engine = DurableEvaluationEngine()
        cap = issue_capability(
            organization_id="o",
            run_id="r",
            allowed_tools=["read_public_doc"],
            ttl_seconds=-1,
        )
        with self.assertRaises(PermissionError):
            cap.revalidate()

    def test_api_release_gate_and_finding_patch(self):
        from fastapi.testclient import TestClient
        from app.api.main import app

        client = TestClient(app)
        headers = {"X-User-Sub": "carol"}
        org = client.post("/v1/organizations", json={"name": "ApiBeta"}, headers=headers).json()
        project = client.post(
            f"/v1/organizations/{org['id']}/projects",
            json={"name": "p"},
            headers=headers,
        ).json()
        agent = client.post(
            f"/v1/organizations/{org['id']}/projects/{project['id']}/agents",
            json={"name": "a", "allowed_tools": ["read_public_doc"]},
            headers=headers,
        ).json()
        auth_cfg = client.get("/v1/auth/config").json()
        self.assertTrue(auth_cfg["allow_dev_auth"])
        gate = client.post(
            f"/v1/organizations/{org['id']}/release-gates",
            json={
                "suite_name": "core",
                "project_id": project["id"],
                "agent_id": agent["id"],
                "scenario_keys": ["unauthorized_tool_invocation"],
                "behave_securely": False,
                "provider": "github",
                "publish": True,
            },
            headers=headers,
        )
        self.assertEqual(gate.status_code, 200, gate.text)
        body = gate.json()
        self.assertEqual(body["suite_gate_result"], "fail")
        self.assertTrue(body["fail_release"])
        self.assertTrue(body["publish_result"]["dry_run"])

        findings = client.get(
            f"/v1/organizations/{org['id']}/projects/{project['id']}/findings",
            headers=headers,
        ).json()["findings"]
        self.assertTrue(findings)
        patched = client.patch(
            f"/v1/organizations/{org['id']}/findings/{findings[0]['id']}",
            json={"status": "suppressed", "note": "known fp"},
            headers=headers,
        )
        self.assertEqual(patched.status_code, 200, patched.text)
        self.assertEqual(patched.json()["status"], "suppressed")

        export = client.get(
            f"/v1/organizations/{org['id']}/runs/{body['run_ids'][0]}/export",
            headers=headers,
        )
        self.assertEqual(export.status_code, 200, export.text)
        self.assertIn("sarif", export.json()["bundle"])
        self.assertTrue(export.json()["signature"].startswith("hmac-sha256:"))


if __name__ == "__main__":
    unittest.main()
