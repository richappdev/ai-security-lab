"""Fail-closed configuration and live dependency certification for beta."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlparse

import httpx
from cryptography.fernet import Fernet


TENANT_TABLES = (
    "memberships",
    "project_memberships",
    "projects",
    "agents",
    "agent_versions",
    "scenarios",
    "suites",
    "suite_revisions",
    "suite_runs",
    "runs",
    "run_events",
    "findings",
    "finding_transitions",
    "evidence",
    "policies",
    "policy_revisions",
    "approval_exceptions",
    "worker_capabilities",
    "integration_installations",
    "authz_audit",
)


@dataclass(frozen=True)
class CheckResult:
    name: str
    category: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class CertificationReport:
    generated_at: str
    profile: str
    checks: list[CheckResult]

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(check.passed for check in self.checks)

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "profile": self.profile,
            "passed": self.passed,
            "summary": {
                "passed": sum(check.passed for check in self.checks),
                "failed": sum(not check.passed for check in self.checks),
                "total": len(self.checks),
            },
            "checks": [asdict(check) for check in self.checks],
        }


def _result(name: str, category: str, passed: bool, detail: str) -> CheckResult:
    return CheckResult(name=name, category=category, passed=passed, detail=detail)


def _is_true(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_https(value: str | None) -> bool:
    return bool(value and urlparse(value).scheme.lower() == "https")


def _valid_raw_ed25519(value: str | None) -> bool:
    if not value:
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def _valid_fernet(value: str | None) -> bool:
    if not value:
        return False
    try:
        Fernet(value.encode("ascii"))
        return True
    except (ValueError, TypeError):
        return False


def evaluate_configuration(
    environment: Mapping[str, str] | None = None,
    *,
    profile: str = "beta",
) -> CertificationReport:
    """Evaluate safety-critical deployment settings without making network calls."""
    env = dict(os.environ if environment is None else environment)
    checks: list[CheckResult] = []
    strict = profile in {"beta", "production"}

    deployment = env.get("DEPLOYMENT_ENV", "local").lower()
    expected = {profile} if profile == "production" else {"beta", "production"}
    checks.append(
        _result(
            "deployment-profile",
            "configuration",
            not strict or deployment in expected,
            f"DEPLOYMENT_ENV={deployment}",
        )
    )
    checks.append(
        _result(
            "development-auth-disabled",
            "identity",
            not strict or not _is_true(env.get("ALLOW_DEV_AUTH")),
            "development header authentication must be disabled",
        )
    )
    checks.append(
        _result(
            "legacy-runs-disabled",
            "workflow",
            not strict or not _is_true(env.get("ALLOW_LEGACY_SYNC_RUNS")),
            "commercial runs must not use the local workflow fallback",
        )
    )

    database_url = env.get("DATABASE_URL", "")
    checks.append(
        _result(
            "postgresql-required",
            "database",
            not strict or database_url.startswith(("postgresql://", "postgresql+psycopg://")),
            "DATABASE_URL must use PostgreSQL",
        )
    )

    oidc_issuer = env.get("OIDC_ISSUER")
    checks.extend(
        [
            _result(
                "oidc-issuer",
                "identity",
                not strict or _is_https(oidc_issuer),
                "OIDC issuer must be configured over HTTPS",
            ),
            _result(
                "oidc-audience",
                "identity",
                not strict or bool(env.get("OIDC_AUDIENCE")),
                "OIDC audience must be explicit",
            ),
        ]
    )

    temporal_address = env.get("TEMPORAL_ADDRESS", "")
    temporal_auth = bool(env.get("TEMPORAL_API_KEY")) or bool(
        env.get("TEMPORAL_CLIENT_CERT") and env.get("TEMPORAL_CLIENT_KEY")
    )
    checks.extend(
        [
            _result(
                "temporal-address",
                "workflow",
                not strict or bool(temporal_address),
                "Temporal Cloud address must be configured",
            ),
            _result(
                "temporal-tls",
                "workflow",
                not strict or _is_true(env.get("TEMPORAL_TLS")),
                "Temporal connections must use TLS",
            ),
            _result(
                "temporal-authentication",
                "workflow",
                not strict or temporal_auth,
                "Temporal Cloud requires an API key or client certificate pair",
            ),
        ]
    )

    storage_endpoint = env.get("MINIO_ENDPOINT")
    storage_credentials_safe = (
        bool(env.get("MINIO_ACCESS_KEY"))
        and bool(env.get("MINIO_SECRET_KEY"))
        and env.get("MINIO_ACCESS_KEY") != "minioadmin"
        and env.get("MINIO_SECRET_KEY") != "minioadmin"
    )
    checks.extend(
        [
            _result(
                "object-storage-endpoint",
                "evidence",
                not strict or _is_https(storage_endpoint),
                "S3-compatible endpoint must be configured over HTTPS",
            ),
            _result(
                "object-storage-credentials",
                "evidence",
                not strict or storage_credentials_safe,
                "object storage credentials must be explicit and non-default",
            ),
            _result(
                "object-storage-bucket",
                "evidence",
                not strict or bool(env.get("MINIO_BUCKET")),
                "evidence bucket must be explicit",
            ),
        ]
    )

    evidence_key = env.get("EVIDENCE_ED25519_PRIVATE_KEY")
    capability_key = env.get("CAPABILITY_ED25519_PRIVATE_KEY")
    checks.extend(
        [
            _result(
                "evidence-ed25519-key",
                "signing",
                not strict or _valid_raw_ed25519(evidence_key),
                "evidence key must be a base64-encoded raw 32-byte Ed25519 key",
            ),
            _result(
                "capability-ed25519-key",
                "signing",
                not strict or _valid_raw_ed25519(capability_key),
                "capability key must be a base64-encoded raw 32-byte Ed25519 key",
            ),
            _result(
                "separate-signing-keys",
                "signing",
                not strict or bool(evidence_key and capability_key and evidence_key != capability_key),
                "evidence and capability signing keys must be distinct",
            ),
            _result(
                "signing-key-ids",
                "signing",
                not strict
                or bool(
                    env.get("EVIDENCE_SIGNING_KEY_ID")
                    and env.get("CAPABILITY_SIGNING_KEY_ID")
                ),
                "rotatable signing key IDs must be explicit",
            ),
        ]
    )

    checks.extend(
        [
            _result(
                "integration-encryption-key",
                "integrations",
                not strict or _valid_fernet(env.get("INTEGRATION_ENCRYPTION_KEY")),
                "integration encryption key must be a valid Fernet key",
            ),
            _result(
                "operations-token",
                "operations",
                not strict or len(env.get("OPERATIONS_TOKEN", "")) >= 32,
                "operations token must contain at least 32 characters",
            ),
            _result(
                "telemetry-export",
                "operations",
                not strict or bool(env.get("OTEL_EXPORTER_OTLP_ENDPOINT")),
                "OTLP export endpoint must be configured",
            ),
            _result(
                "ci-installation-mode",
                "integrations",
                not strict
                or env.get("CI_INTEGRATION_PROVIDER", "").lower() in {"github", "gitlab"},
                "CI_INTEGRATION_PROVIDER must be github or gitlab",
            ),
        ]
    )
    return CertificationReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        profile=profile,
        checks=checks,
    )


def _safe_error(exc: Exception, env: Mapping[str, str]) -> str:
    message = str(exc)
    for name, value in env.items():
        if value and any(marker in name.upper() for marker in ("TOKEN", "KEY", "SECRET", "PASSWORD")):
            message = message.replace(value, "[REDACTED]")
    return re.sub(r"(://[^:/\s]+:)[^@\s]+@", r"\1[REDACTED]@", message)[:500]


def _probe_database(env: Mapping[str, str]) -> list[CheckResult]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from sqlalchemy import create_engine, text

    engine = create_engine(env["DATABASE_URL"], pool_pre_ping=True, hide_parameters=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            head = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
            rows = connection.execute(
                text(
                    """
                    SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                           bool_or(p.polqual IS NOT NULL) AS has_using,
                           bool_or(p.polwithcheck IS NOT NULL) AS has_with_check
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    LEFT JOIN pg_policy p ON p.polrelid = c.oid
                    WHERE n.nspname = current_schema()
                      AND c.relname = ANY(:tables)
                    GROUP BY c.relname, c.relrowsecurity, c.relforcerowsecurity
                    """
                ),
                {"tables": list(TENANT_TABLES)},
            ).mappings()
            by_table = {row["relname"]: row for row in rows}
        missing = sorted(set(TENANT_TABLES) - set(by_table))
        unsafe = sorted(
            name
            for name, row in by_table.items()
            if not (
                row["relrowsecurity"]
                and row["relforcerowsecurity"]
                and row["has_using"]
                and row["has_with_check"]
            )
        )
        return [
            _result("database-connectivity", "database", True, "PostgreSQL query succeeded"),
            _result(
                "alembic-head",
                "database",
                bool(head and version == head),
                f"database revision={version}; repository head={head}",
            ),
            _result(
                "rls-policy-coverage",
                "database",
                not missing and not unsafe,
                f"missing={missing or 'none'}; unsafe={unsafe or 'none'}",
            ),
        ]
    finally:
        engine.dispose()


def _probe_oidc(env: Mapping[str, str]) -> list[CheckResult]:
    issuer = env["OIDC_ISSUER"].rstrip("/")
    with httpx.Client(timeout=15.0) as client:
        metadata_response = client.get(f"{issuer}/.well-known/openid-configuration")
        metadata_response.raise_for_status()
        metadata = metadata_response.json()
        jwks_response = client.get(metadata["jwks_uri"])
        jwks_response.raise_for_status()
        jwks = jwks_response.json()
    return [
        _result(
            "oidc-discovery-live",
            "identity",
            metadata.get("issuer", "").rstrip("/") == issuer,
            "discovery issuer matches configuration",
        ),
        _result(
            "oidc-jwks-live",
            "identity",
            bool(jwks.get("keys")),
            "JWKS contains at least one signing key",
        ),
    ]


def _probe_storage(env: Mapping[str, str]) -> list[CheckResult]:
    from evidence.store import EvidenceStore

    store = EvidenceStore()
    client = store._client()
    client.head_bucket(Bucket=store.bucket)
    versioning = client.get_bucket_versioning(Bucket=store.bucket).get("Status")
    try:
        encryption = client.get_bucket_encryption(Bucket=store.bucket)
        encrypted = bool(
            encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules")
        )
    except Exception:
        encrypted = False
    return [
        _result("object-storage-live", "evidence", True, "evidence bucket is reachable"),
        _result(
            "object-versioning",
            "evidence",
            versioning == "Enabled",
            f"bucket versioning status={versioning or 'disabled'}",
        ),
        _result(
            "object-encryption",
            "evidence",
            encrypted,
            "bucket default server-side encryption is configured",
        ),
    ]


async def _probe_temporal(env: Mapping[str, str]) -> list[CheckResult]:
    from workers.temporal_client import connect_temporal

    client = await connect_temporal(env)
    healthy = await client.service_client.check_health()
    return [
        _result(
            "temporal-cloud-live",
            "workflow",
            bool(healthy),
            "Temporal service health check succeeded",
        )
    ]


def _probe_api(env: Mapping[str, str], base_url: str) -> list[CheckResult]:
    headers: dict[str, str] = {}
    if env.get("OPERATIONS_TOKEN"):
        headers["X-Operations-Token"] = env["OPERATIONS_TOKEN"]
    with httpx.Client(base_url=base_url.rstrip("/"), timeout=15.0) as client:
        health = client.get("/health")
        health.raise_for_status()
        openapi = client.get("/openapi.json")
        openapi.raise_for_status()
        metrics = client.get("/v1/operations/metrics", headers=headers)
        metrics.raise_for_status()
    paths = openapi.json().get("paths", {})
    required = {
        "/v1/organizations/{organization_id}/runs",
        "/v1/organizations/{organization_id}/runs/{run_id}/events:batch",
        "/v1/organizations/{organization_id}/runs/{run_id}/complete",
        "/v1/organizations/{organization_id}/runs/{run_id}/export",
    }
    return [
        _result("control-plane-health", "api", health.json().get("status") == "ok", "health endpoint"),
        _result(
            "event-api-contract",
            "api",
            required.issubset(paths),
            f"required routes present={required.issubset(paths)}",
        ),
        _result("operations-metrics", "operations", metrics.is_success, "metrics endpoint"),
    ]


def run_live_certification(
    environment: Mapping[str, str] | None = None,
    *,
    profile: str = "beta",
    base_url: str | None = None,
) -> CertificationReport:
    env = dict(os.environ if environment is None else environment)
    static_report = evaluate_configuration(env, profile=profile)
    checks = list(static_report.checks)
    probes = (
        ("database-live", lambda: _probe_database(env)),
        ("oidc-live", lambda: _probe_oidc(env)),
        ("object-storage-live", lambda: _probe_storage(env)),
        ("temporal-live", lambda: asyncio.run(_probe_temporal(env))),
    )
    if base_url:
        probes += (("control-plane-live", lambda: _probe_api(env, base_url)),)
    for name, probe in probes:
        try:
            checks.extend(probe())
        except Exception as exc:  # noqa: BLE001 - report dependency failures as gate failures.
            checks.append(_result(name, "live", False, _safe_error(exc, env)))
    return CertificationReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        profile=profile,
        checks=checks,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("local", "beta", "production"), default="beta")
    parser.add_argument("--live", action="store_true", help="probe configured managed dependencies")
    parser.add_argument("--base-url", help="control-plane URL to include in live checks")
    parser.add_argument("--output", help="optional JSON report path")
    args = parser.parse_args()
    report = (
        run_live_certification(profile=args.profile, base_url=args.base_url)
        if args.live
        else evaluate_configuration(profile=args.profile)
    )
    encoded = json.dumps(report.as_dict(), indent=2, sort_keys=True)
    print(encoded)
    if args.output:
        from pathlib import Path

        Path(args.output).write_text(encoded + "\n", encoding="utf-8")
    if not report.passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
