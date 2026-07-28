"""Post-implementation beta certification tests."""

from __future__ import annotations

import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

os.environ["ALLOW_DEV_AUTH"] = "true"
os.environ["ALLOW_LEGACY_SYNC_RUNS"] = "true"
os.environ.pop("TEMPORAL_ADDRESS", None)

from app.api.main import app
from app.auth import reset_engine_for_tests
from certification.beta_exit import BetaExitClient
from certification.readiness import evaluate_configuration
from certification.scorecard import evaluate_scorecard
from persistence import Base, init_db
from observability.runtime import validate_beta_configuration
from workers.temporal_client import temporal_connection_settings


def _raw_private_key() -> str:
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


class BetaCertificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(
            f"sqlite+pysqlite:///{(Path(self.tmp.name) / 'certification.db').as_posix()}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.drop_all(self.engine)
        init_db(self.engine)
        reset_engine_for_tests(self.engine)
        os.environ["EVIDENCE_LOCAL_ROOT"] = str(Path(self.tmp.name) / "evidence")
        os.environ["EVIDENCE_SIGNING_KEY"] = "certification-local-key"
        os.environ.pop("EVIDENCE_ED25519_PRIVATE_KEY", None)
        os.environ.pop("CAPABILITY_ED25519_PRIVATE_KEY", None)
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.engine.dispose()
        self.tmp.cleanup()

    def test_beta_configuration_is_fail_closed(self):
        report = evaluate_configuration(
            {
                "DEPLOYMENT_ENV": "beta",
                "ALLOW_DEV_AUTH": "true",
                "ALLOW_LEGACY_SYNC_RUNS": "true",
                "DATABASE_URL": "sqlite:///unsafe.db",
            }
        )
        self.assertFalse(report.passed)
        failed = {check.name for check in report.checks if not check.passed}
        self.assertIn("development-auth-disabled", failed)
        self.assertIn("legacy-runs-disabled", failed)
        self.assertIn("postgresql-required", failed)
        self.assertIn("temporal-address", failed)

    def test_partner_configuration_passes_static_gate(self):
        configuration = {
            "DEPLOYMENT_ENV": "beta",
            "ALLOW_DEV_AUTH": "false",
            "ALLOW_LEGACY_SYNC_RUNS": "false",
            "DATABASE_URL": "postgresql+psycopg://app:secret@db.internal/aisec",
            "OIDC_ISSUER": "https://identity.example.com",
            "OIDC_AUDIENCE": "aisec-api",
            "TEMPORAL_ADDRESS": "tenant.tmprl.cloud:7233",
            "TEMPORAL_TLS": "true",
            "TEMPORAL_API_KEY": "temporal-api-key",
            "MINIO_ENDPOINT": "https://objects.example.com",
            "MINIO_BUCKET": "partner-evidence",
            "MINIO_ACCESS_KEY": "partner-access",
            "MINIO_SECRET_KEY": "partner-secret",
            "EVIDENCE_ED25519_PRIVATE_KEY": _raw_private_key(),
            "CAPABILITY_ED25519_PRIVATE_KEY": _raw_private_key(),
            "EVIDENCE_SIGNING_KEY_ID": "evidence-2026-01",
            "CAPABILITY_SIGNING_KEY_ID": "capability-2026-01",
            "INTEGRATION_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
            "OPERATIONS_TOKEN": "o" * 32,
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example.com",
            "CI_INTEGRATION_PROVIDER": "github",
        }
        report = evaluate_configuration(configuration)
        self.assertTrue(report.passed, report.as_dict())
        settings = temporal_connection_settings(configuration)
        self.assertEqual(settings["api_key"], "temporal-api-key")
        self.assertTrue(settings["tls"])

    def test_application_startup_rejects_legacy_beta_execution(self):
        with patch.dict(
            os.environ,
            {
                "DEPLOYMENT_ENV": "beta",
                "ALLOW_DEV_AUTH": "false",
                "ALLOW_LEGACY_SYNC_RUNS": "true",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "ALLOW_LEGACY_SYNC_RUNS"):
                validate_beta_configuration()

    def test_executable_beta_exit_flow(self):
        report = BetaExitClient(
            self.client,
            auth_headers={"X-User-Sub": "certification-owner"},
        ).run()
        self.assertTrue(report.passed)
        self.assertEqual(report.failed_gate_result, "fail")
        self.assertEqual(report.passed_gate_result, "pass")
        self.assertNotEqual(
            report.failed_agent_version_id,
            report.remediated_agent_version_id,
        )
        self.assertTrue(all(report.evidence_verification.values()))
        self.assertTrue(report.cross_tenant_denial_verified)
        self.assertTrue(report.redaction_verified)
        self.assertLess(report.cancellation_seconds, 10)
        self.assertIsNone(report.ci_failure_published)

    def test_partner_scorecard_enforces_rollout_gates(self):
        passing = evaluate_scorecard(
            {
                "scenario_reproducibility_rate": 0.95,
                "evidence_completeness_rate": 1,
                "cross_tenant_denial_rate": 1,
                "cancellation_p95_seconds": 9.9,
                "worker_failure_recovery_succeeded": True,
                "seeded_secret_leaks": 0,
                "fail_remediate_pass_completed": True,
            }
        )
        self.assertTrue(passing["passed"])
        failing = evaluate_scorecard(
            {
                "scenario_reproducibility_rate": 0.94,
                "evidence_completeness_rate": 1,
                "cross_tenant_denial_rate": 1,
                "cancellation_p95_seconds": 10,
                "worker_failure_recovery_succeeded": True,
                "seeded_secret_leaks": 0,
                "fail_remediate_pass_completed": True,
            }
        )
        self.assertFalse(failing["passed"])


if __name__ == "__main__":
    unittest.main()
