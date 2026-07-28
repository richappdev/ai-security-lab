"""90-day Private Beta contract, isolation, evidence, and workflow tests."""

from __future__ import annotations

import base64
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select

os.environ["ALLOW_DEV_AUTH"] = "true"
os.environ["ALLOW_LEGACY_SYNC_RUNS"] = "true"
os.environ.pop("TEMPORAL_ADDRESS", None)

from agents.adapters.synthetic import simulate
from app.api.main import app
from app.auth import reset_engine_for_tests
from evidence import build_export_bundle, build_manifest, verify_signature
from evidence.redaction import REDACTED, redact_events
from evidence.retention import purge_expired_evidence
from evidence.verify_cli import verify_bundle
from persistence import (
    Base,
    Evidence,
    FindingTransition,
    IntegrationInstallation,
    ApprovalException,
    PolicyRevision,
    Run,
    WorkerCapability,
    init_db,
    session_scope,
)
from persistence.repositories import (
    create_agent,
    create_organization,
    create_project,
    create_suite,
    issue_worker_capability,
    resolve_principal,
    validate_worker_capability,
)
from policies import evaluate_release_policy
from scenarios import list_scenario_keys, run_scenario_evaluation
from scenarios.suites import execute_persisted_suite
from workers.launcher import DockerWorkerLauncher, WorkerLaunchRequest
from workers.durable import DurableEvaluationEngine


class NinetyDayPrivateBetaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(
            f"sqlite+pysqlite:///{(Path(self.tmp.name) / 'beta.db').as_posix()}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.drop_all(self.engine)
        init_db(self.engine)
        reset_engine_for_tests(self.engine)
        os.environ["EVIDENCE_LOCAL_ROOT"] = str(Path(self.tmp.name) / "evidence")
        os.environ["EVIDENCE_SIGNING_KEY"] = "test-legacy-key"
        os.environ.pop("EVIDENCE_ED25519_PRIVATE_KEY", None)
        os.environ.pop("EVIDENCE_SIGNING_ALGORITHM", None)
        os.environ.pop("EVIDENCE_SEEDED_SECRETS", None)
        self.client = TestClient(app)
        self.headers = {"X-User-Sub": "alice"}

    def tearDown(self) -> None:
        self.engine.dispose()
        self.tmp.cleanup()

    def _bootstrap_api(self, suffix: str = "") -> dict:
        org = self.client.post(
            "/v1/organizations",
            json={"name": f"Beta{suffix}"},
            headers=self.headers,
        ).json()
        project = self.client.post(
            f"/v1/organizations/{org['id']}/projects",
            json={"name": "product"},
            headers=self.headers,
        ).json()
        agent = self.client.post(
            f"/v1/organizations/{org['id']}/projects/{project['id']}/agents",
            json={"name": "agent", "allowed_tools": ["read_public_doc"]},
            headers=self.headers,
        ).json()
        suite = self.client.post(
            f"/v1/organizations/{org['id']}/projects/{project['id']}/suites",
            json={
                "name": "core",
                "scenario_keys": ["unauthorized_tool_invocation"],
            },
            headers=self.headers,
        ).json()
        return {"org": org, "project": project, "agent": agent, "suite": suite}

    def _start_event_run(self, state: dict, *, key: str = "run-1"):
        return self.client.post(
            f"/v1/organizations/{state['org']['id']}/runs",
            headers={**self.headers, "Idempotency-Key": key},
            json={
                "execution_mode": "event_api",
                "suite_revision_id": state["suite"]["suite_revision_id"],
                "agent_version_id": state["agent"]["agent_version_id"],
                "scenario_key": "unauthorized_tool_invocation",
                "deadline_seconds": 600,
            },
        )

    def test_event_api_fail_complete_and_idempotent_batch(self):
        state = self._bootstrap_api("Event")
        started = self._start_event_run(state)
        self.assertEqual(started.status_code, 202, started.text)
        run = started.json()
        events = simulate(
            "unauthorized_tool_invocation",
            allowed_tools=["read_public_doc"],
            behave_securely=False,
        )
        payload = {
            "events": [
                {**event, "schema_version": "1", "seq": index}
                for index, event in enumerate(events, start=1)
            ]
        }
        endpoint = (
            f"/v1/organizations/{state['org']['id']}/runs/{run['run_id']}/events:batch"
        )
        capability_headers = {
            "X-Run-Capability": run["capability"],
            "Idempotency-Key": "batch-1",
        }
        accepted = self.client.post(endpoint, headers=capability_headers, json=payload)
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(accepted.json()["accepted"], len(events))
        replay = self.client.post(endpoint, headers=capability_headers, json=payload)
        self.assertTrue(replay.json()["idempotent_replay"])
        completed = self.client.post(
            f"/v1/organizations/{state['org']['id']}/runs/{run['run_id']}/complete",
            headers={"X-Run-Capability": run["capability"]},
        )
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertEqual(completed.json()["gate_result"], "fail")
        detail = self.client.get(
            f"/v1/organizations/{state['org']['id']}/runs/{run['run_id']}",
            headers=self.headers,
        ).json()
        self.assertEqual(detail["execution_mode"], "event_api")
        self.assertEqual(detail["status"], "completed")
        self.assertTrue(detail["evidence"]["expires_at"])

    def test_event_sequence_and_cross_run_capability_are_rejected(self):
        state = self._bootstrap_api("Isolation")
        first = self._start_event_run(state, key="first").json()
        second = self._start_event_run(state, key="second").json()
        event = {
            "schema_version": "1",
            "seq": 2,
            "type": "model.request",
            "payload": {},
        }
        wrong_seq = self.client.post(
            f"/v1/organizations/{state['org']['id']}/runs/{first['run_id']}/events:batch",
            headers={
                "X-Run-Capability": first["capability"],
                "Idempotency-Key": "bad-seq",
            },
            json={"events": [event]},
        )
        self.assertEqual(wrong_seq.status_code, 409)
        cross_run = self.client.post(
            f"/v1/organizations/{state['org']['id']}/runs/{second['run_id']}/events:batch",
            headers={
                "X-Run-Capability": first["capability"],
                "Idempotency-Key": "cross-run",
            },
            json={"events": [{**event, "seq": 1}]},
        )
        self.assertEqual(cross_run.status_code, 403)
        tampered = first["capability"][:-1] + (
            "A" if first["capability"][-1] != "A" else "B"
        )
        bad_signature = self.client.post(
            f"/v1/organizations/{state['org']['id']}/runs/{first['run_id']}/events:batch",
            headers={
                "X-Run-Capability": tampered,
                "Idempotency-Key": "tampered",
            },
            json={"events": [{**event, "seq": 1}]},
        )
        self.assertEqual(bad_signature.status_code, 403)

    def test_expired_capability_is_enforced(self):
        with session_scope(engine=self.engine) as session:
            org = create_organization(session, "Expired", "alice")
            session.flush()
            principal = resolve_principal(session, "alice", org.id)
            project = create_project(session, principal, "p")
            session.flush()
            agent = create_agent(session, principal, project.id, "a")
            session.flush()
            from persistence.repositories import create_run

            run = create_run(
                session,
                principal,
                project_id=project.id,
                agent_id=agent.id,
                scenario_key="direct_prompt_injection",
                scenario_version="1.0.0",
            )
            session.flush()
            cap, token = issue_worker_capability(
                session,
                principal,
                project_id=project.id,
                run_id=run.id,
                operations=["events:append"],
                ttl_seconds=-1,
            )
            session.flush()
            with self.assertRaises(TimeoutError):
                validate_worker_capability(
                    session,
                    token=token,
                    organization_id=org.id,
                    run_id=run.id,
                    operation="events:append",
                )

    def test_project_scoped_role_can_grant_operator_access(self):
        state = self._bootstrap_api("ProjectRole")
        added = self.client.post(
            f"/v1/organizations/{state['org']['id']}/memberships",
            headers=self.headers,
            json={"user_sub": "bob", "role": "viewer"},
        )
        self.assertEqual(added.status_code, 200)
        project_role = self.client.post(
            f"/v1/organizations/{state['org']['id']}/projects/{state['project']['id']}/memberships",
            headers=self.headers,
            json={"user_sub": "bob", "role": "operator"},
        )
        self.assertEqual(project_role.status_code, 200)
        created = self.client.post(
            f"/v1/organizations/{state['org']['id']}/projects/{state['project']['id']}/agents",
            headers={"X-User-Sub": "bob"},
            json={"name": "project-scoped-agent"},
        )
        self.assertEqual(created.status_code, 200, created.text)

    def test_redaction_removes_fields_patterns_and_seeded_secrets(self):
        os.environ["EVIDENCE_SEEDED_SECRETS"] = "seed-secret-value"
        result = redact_events(
            [
                {
                    "type": "tool.call",
                    "payload": {
                        "authorization": "Bearer abcdefghijklmnop",
                        "nested": {"api_key": "seed-secret-value"},
                        "message": "token is seed-secret-value",
                    },
                }
            ]
        )
        encoded = repr(result)
        self.assertNotIn("seed-secret-value", encoded)
        self.assertIn(REDACTED, encoded)

    def test_ed25519_signature_and_pdf_export(self):
        private = Ed25519PrivateKey.generate()
        raw = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        os.environ["EVIDENCE_ED25519_PRIVATE_KEY"] = base64.b64encode(raw).decode()
        manifest, _ = build_manifest(
            organization_id="o",
            project_id="p",
            run_id="r",
            scenario_key="direct_prompt_injection",
            scenario_version="1",
            agent_version="1",
            gate_result=__import__("domain").GateResult.PASS,
            events=[],
            findings=[],
        )
        unsigned = {**manifest, "signature": None}
        self.assertTrue(
            verify_signature(
                unsigned,
                manifest["signature"],
                public_key=manifest["signing"]["public_key"],
            )
        )
        bundle = build_export_bundle(
            manifest=manifest,
            events=[],
            findings=[],
            gate_result="pass",
            scenario_key="direct_prompt_injection",
            run_id="r",
        )
        self.assertTrue(base64.b64decode(bundle["pdf_base64"]).startswith(b"%PDF-"))
        self.assertIn("<!doctype html>", bundle["html"])
        self.assertTrue(all(verify_bundle(bundle).values()))

    def test_persisted_suite_policy_and_structured_transition(self):
        state = self._bootstrap_api("Suite")
        suite = self.client.post(
            f"/v1/organizations/{state['org']['id']}/suite-runs",
            headers=self.headers,
            json={
                "suite_revision_id": state["suite"]["suite_revision_id"],
                "agent_version_id": state["agent"]["agent_version_id"],
                "behave_securely": False,
                "durable": False,
            },
        )
        self.assertEqual(suite.status_code, 200, suite.text)
        self.assertEqual(suite.json()["suite_gate_result"], "fail")
        self.assertEqual(suite.json()["score"], 0)
        findings = self.client.get(
            f"/v1/organizations/{state['org']['id']}/projects/{state['project']['id']}/findings",
            headers=self.headers,
        ).json()["findings"]
        patched = self.client.patch(
            f"/v1/organizations/{state['org']['id']}/findings/{findings[0]['id']}",
            headers=self.headers,
            json={"status": "assigned", "assignee": "alice", "note": "triage"},
        )
        self.assertEqual(patched.status_code, 200)
        with session_scope(engine=self.engine) as session:
            transitions = list(session.scalars(select(FindingTransition)))
            self.assertEqual(len(transitions), 1)
            self.assertEqual(transitions[0].to_status, "assigned")
        decision = evaluate_release_policy(
            {
                "max_failed": 0,
                "required_scenarios": ["unauthorized_tool_invocation"],
                "block_severities": ["high"],
                "require_complete_evidence": True,
            },
            scenario_keys=["unauthorized_tool_invocation"],
            results=suite.json()["results"],
            evidence_complete=True,
        )
        self.assertFalse(decision.allowed)

    def test_retention_purge_and_worker_boundary(self):
        state = self._bootstrap_api("Retention")
        result = self.client.post(
            f"/v1/organizations/{state['org']['id']}/runs",
            headers=self.headers,
            json={
                "project_id": state["project"]["id"],
                "agent_id": state["agent"]["id"],
                "scenario_key": "unauthorized_tool_invocation",
                "behave_securely": True,
                "durable": False,
            },
        ).json()
        with session_scope(engine=self.engine) as session:
            evidence = session.scalar(select(Evidence).where(Evidence.run_id == result["run_id"]))
            evidence.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with session_scope(engine=self.engine) as session:
            purged = purge_expired_evidence(session)
            self.assertEqual(purged["evidence_purged"], 1)
        launcher = DockerWorkerLauncher()
        dry_run = launcher.launch(
            WorkerLaunchRequest(
                run_id="run-1",
                image="agent-evaluator:beta",
                capability="super-secret",
            ),
            dry_run=True,
        )
        command = " ".join(dry_run.command)
        self.assertIn("--read-only", command)
        self.assertIn("--network none", command)
        self.assertIn("--cap-drop ALL", command)
        self.assertNotIn("super-secret", command)

    def test_all_scenarios_are_at_least_95_percent_reproducible(self):
        for scenario_key in list_scenario_keys():
            signatures = []
            for _ in range(20):
                outcome = run_scenario_evaluation(
                    scenario_key,
                    simulate(
                        scenario_key,
                        allowed_tools=["read_public_doc"],
                        behave_securely=True,
                    ),
                )
                signatures.append(
                    (
                        outcome.gate_result.value,
                        tuple(
                            (result.assertion_id, result.passed)
                            for result in outcome.assertion_results
                        ),
                    )
                )
            identical_rate = max(
                signatures.count(signature) for signature in set(signatures)
            ) / len(signatures)
            self.assertGreaterEqual(identical_rate, 0.95, scenario_key)

    def test_cancellation_p95_is_below_ten_seconds(self):
        state = self._bootstrap_api("CancelLatency")
        latencies = []
        for index in range(10):
            run = self._start_event_run(state, key=f"cancel-{index}").json()
            started = time.perf_counter()
            cancelled = self.client.post(
                f"/v1/organizations/{state['org']['id']}/runs/{run['run_id']}/cancel",
                headers={"X-Run-Capability": run["capability"]},
            )
            latencies.append(time.perf_counter() - started)
            self.assertEqual(cancelled.json()["status"], "cancelled")
        p95 = sorted(latencies)[int(len(latencies) * 0.95) - 1]
        self.assertLess(p95, 10)

    def test_single_worker_failure_is_recoverable_without_evidence_duplication(self):
        engine = DurableEvaluationEngine()
        attempts = {"count": 0}

        def flaky(_capability):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise RuntimeError("injected worker loss")
            return {"sealed": True, "evidence_objects": 1}

        failed = engine.start_evaluation(
            run_id="recoverable",
            organization_id="org",
            allowed_tools=[],
            execute=flaky,
        )
        self.assertEqual(failed.status, "failed")
        self.assertEqual(engine.recover(failed.workflow_id).status, "queued_recovery")
        recovered = engine.start_evaluation(
            run_id="recoverable",
            organization_id="org",
            allowed_tools=[],
            execute=flaky,
        )
        self.assertEqual(recovered.status, "completed")
        self.assertEqual(recovered.result["evidence_objects"], 1)

    def test_expiring_exception_and_encrypted_integration(self):
        state = self._bootstrap_api("Governance")
        policy = self.client.post(
            f"/v1/organizations/{state['org']['id']}/projects/{state['project']['id']}/policies",
            headers=self.headers,
            json={"name": "release", "rules": {"max_failed": 0}},
        ).json()
        exception = self.client.post(
            f"/v1/organizations/{state['org']['id']}/exceptions",
            headers=self.headers,
            json={
                "project_id": state["project"]["id"],
                "policy_revision_id": policy["policy_revision_id"],
                "scope": {"suite_revision_id": state["suite"]["suite_revision_id"]},
                "reason": "time-bounded design partner exception",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            },
        )
        self.assertEqual(exception.status_code, 200, exception.text)
        installation = self.client.post(
            f"/v1/organizations/{state['org']['id']}/integrations",
            headers=self.headers,
            json={
                "provider": "github",
                "project_id": state["project"]["id"],
                "config": {"owner": "acme", "repo": "agent", "token": "ghp-secret-value"},
            },
        )
        self.assertEqual(installation.status_code, 200, installation.text)
        with session_scope(engine=self.engine) as session:
            stored = session.scalar(select(IntegrationInstallation))
            self.assertNotIn("ghp-secret-value", stored.encrypted_config)
            row = session.scalar(select(ApprovalException))
            row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        listed = self.client.get(
            f"/v1/organizations/{state['org']['id']}/projects/{state['project']['id']}/exceptions",
            headers=self.headers,
        )
        self.assertEqual(listed.json()["exceptions"], [])

    def test_beta_exit_flow_fail_remediate_rerun_pass_and_export(self):
        state = self._bootstrap_api("ExitGate")
        failed = self.client.post(
            f"/v1/organizations/{state['org']['id']}/suite-runs",
            headers=self.headers,
            json={
                "suite_revision_id": state["suite"]["suite_revision_id"],
                "agent_version_id": state["agent"]["agent_version_id"],
                "behave_securely": False,
                "durable": False,
            },
        ).json()
        self.assertEqual(failed["suite_gate_result"], "fail")
        findings = self.client.get(
            f"/v1/organizations/{state['org']['id']}/projects/{state['project']['id']}/findings",
            headers=self.headers,
        ).json()["findings"]
        self.client.patch(
            f"/v1/organizations/{state['org']['id']}/findings/{findings[0]['id']}",
            headers=self.headers,
            json={"status": "remediated", "note": "agent tool policy corrected"},
        )
        passed = self.client.post(
            f"/v1/organizations/{state['org']['id']}/suite-runs",
            headers=self.headers,
            json={
                "suite_revision_id": state["suite"]["suite_revision_id"],
                "agent_version_id": state["agent"]["agent_version_id"],
                "behave_securely": True,
                "durable": False,
            },
        ).json()
        self.assertEqual(passed["suite_gate_result"], "pass")
        exported = self.client.get(
            f"/v1/organizations/{state['org']['id']}/runs/{passed['run_ids'][0]}/export",
            headers=self.headers,
        )
        self.assertEqual(exported.status_code, 200, exported.text)
        self.assertIn("sarif", exported.json()["bundle"])
        policy = self.client.post(
            f"/v1/organizations/{state['org']['id']}/projects/{state['project']['id']}/policies",
            headers=self.headers,
            json={
                "name": "exit-gate",
                "rules": {
                    "max_failed": 0,
                    "required_scenarios": ["unauthorized_tool_invocation"],
                    "require_complete_evidence": True,
                },
            },
        ).json()
        gate = self.client.post(
            f"/v1/organizations/{state['org']['id']}/release-gates",
            headers=self.headers,
            json={
                "suite_name": "core",
                "suite_revision_id": state["suite"]["suite_revision_id"],
                "agent_version_id": state["agent"]["agent_version_id"],
                "policy_revision_id": policy["policy_revision_id"],
                "behave_securely": True,
                "provider": "none",
                "publish": False,
            },
        )
        self.assertEqual(gate.status_code, 200, gate.text)
        self.assertFalse(gate.json()["fail_release"])


if __name__ == "__main__":
    unittest.main()
