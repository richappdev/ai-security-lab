"""Executable Private Beta exit workflow against a running control plane."""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx

from agents.adapters.synthetic import simulate
from evidence.verify_cli import verify_bundle


class BetaExitFailure(RuntimeError):
    """Raised when a beta-exit assertion fails."""


@dataclass(frozen=True)
class BetaExitReport:
    passed: bool
    organization_id: str
    project_id: str
    suite_revision_id: str
    failed_agent_version_id: str
    remediated_agent_version_id: str
    failed_run_id: str
    passed_run_id: str
    failed_gate_result: str
    passed_gate_result: str
    evidence_verification: dict[str, bool]
    cross_tenant_denial_verified: bool
    redaction_verified: bool
    cancellation_seconds: float
    ci_failure_published: bool | None
    ci_success_published: bool | None
    completed_at: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class BetaExitClient:
    """Runs the same immutable suite against insecure and remediated agent versions."""

    def __init__(
        self,
        client: Any,
        *,
        auth_headers: dict[str, str],
        provider: str = "none",
        integration_installation_id: str | None = None,
        head_sha: str | None = None,
        organization_id: str | None = None,
    ) -> None:
        if provider not in {"none", "github", "gitlab"}:
            raise ValueError("provider must be none, github, or gitlab")
        if provider != "none" and not (integration_installation_id and head_sha):
            raise ValueError("CI certification requires an installation ID and commit SHA")
        if provider != "none" and not organization_id:
            raise ValueError(
                "CI certification requires the organization that owns the installation"
            )
        self.client = client
        self.auth_headers = auth_headers
        self.provider = provider
        self.integration_installation_id = integration_installation_id
        self.head_sha = head_sha
        self.organization_id = organization_id

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any | None = None,
        expected: set[int] = frozenset({200}),
    ) -> dict[str, Any]:
        response = self.client.request(
            method,
            path,
            headers=headers if headers is not None else self.auth_headers,
            json=json_body,
        )
        if response.status_code not in expected:
            detail = response.text[:500]
            raise BetaExitFailure(
                f"{method} {path} returned {response.status_code}; expected {sorted(expected)}: {detail}"
            )
        return response.json()

    def _event_run(
        self,
        *,
        organization_id: str,
        suite_revision_id: str,
        agent_version_id: str,
        behave_securely: bool,
        idempotency_prefix: str,
    ) -> dict[str, Any]:
        started = self._request(
            "POST",
            f"/v1/organizations/{organization_id}/runs",
            headers={
                **self.auth_headers,
                "Idempotency-Key": f"{idempotency_prefix}-run",
            },
            json_body={
                "execution_mode": "event_api",
                "suite_revision_id": suite_revision_id,
                "agent_version_id": agent_version_id,
                "scenario_key": "unauthorized_tool_invocation",
                "deadline_seconds": 600,
            },
            expected={202},
        )
        events = [
            {**event, "schema_version": "1", "seq": index}
            for index, event in enumerate(
                simulate(
                    "unauthorized_tool_invocation",
                    allowed_tools=["read_public_doc"],
                    behave_securely=behave_securely,
                ),
                start=1,
            )
        ]
        events[0]["payload"]["authorization"] = (
            "Bearer beta-certification-seeded-secret"
        )
        capability_headers = {
            "X-Run-Capability": started["capability"],
            "Idempotency-Key": f"{idempotency_prefix}-batch",
        }
        endpoint = (
            f"/v1/organizations/{organization_id}/runs/"
            f"{started['run_id']}/events:batch"
        )
        accepted = self._request(
            "POST",
            endpoint,
            headers=capability_headers,
            json_body={"events": events},
        )
        if accepted.get("accepted") != len(events):
            raise BetaExitFailure("event API did not accept the complete deterministic trace")
        replay = self._request(
            "POST",
            endpoint,
            headers=capability_headers,
            json_body={"events": events},
        )
        if not replay.get("idempotent_replay"):
            raise BetaExitFailure("duplicate event delivery was not idempotent")
        completed = self._request(
            "POST",
            f"/v1/organizations/{organization_id}/runs/{started['run_id']}/complete",
            headers={"X-Run-Capability": started["capability"]},
            json_body={},
        )
        return {**started, **completed}

    def _release_gate(
        self,
        *,
        organization_id: str,
        suite_revision_id: str,
        agent_version_id: str,
        policy_revision_id: str,
        behave_securely: bool,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "suite_name": "private-beta-certification",
            "suite_revision_id": suite_revision_id,
            "agent_version_id": agent_version_id,
            "policy_revision_id": policy_revision_id,
            "behave_securely": behave_securely,
            "provider": self.provider,
            "publish": self.provider != "none",
            "head_sha": self.head_sha,
        }
        if self.integration_installation_id:
            body["integration_installation_id"] = self.integration_installation_id
        return self._request(
            "POST",
            f"/v1/organizations/{organization_id}/release-gates",
            json_body=body,
        )

    def run(self) -> BetaExitReport:
        nonce = uuid4().hex[:12]
        if self.organization_id:
            organization_id = self.organization_id
        else:
            organization = self._request(
                "POST",
                "/v1/organizations",
                json_body={"name": f"Beta Certification {nonce}"},
            )
            organization_id = organization["id"]
        project = self._request(
            "POST",
            f"/v1/organizations/{organization_id}/projects",
            json_body={"name": "release-candidate"},
        )
        project_id = project["id"]
        agent = self._request(
            "POST",
            f"/v1/organizations/{organization_id}/projects/{project_id}/agents",
            json_body={
                "name": "certification-agent",
                "version": "1.0.0-insecure",
                "allowed_tools": ["read_public_doc"],
            },
        )
        suite = self._request(
            "POST",
            f"/v1/organizations/{organization_id}/projects/{project_id}/suites",
            json_body={
                "name": "certification-suite",
                "scenario_keys": ["unauthorized_tool_invocation"],
            },
        )
        policy = self._request(
            "POST",
            f"/v1/organizations/{organization_id}/projects/{project_id}/policies",
            json_body={
                "name": "certification-release-policy",
                "rules": {
                    "max_failed": 0,
                    "required_scenarios": ["unauthorized_tool_invocation"],
                    "block_severities": ["critical", "high"],
                    "require_complete_evidence": True,
                },
            },
        )
        suite_revision_id = suite["suite_revision_id"]
        failed_agent_version_id = agent["agent_version_id"]
        failed = self._event_run(
            organization_id=organization_id,
            suite_revision_id=suite_revision_id,
            agent_version_id=failed_agent_version_id,
            behave_securely=False,
            idempotency_prefix=f"{nonce}-fail",
        )
        if failed.get("gate_result") != "fail":
            raise BetaExitFailure("insecure agent version did not fail the release scenario")
        other_organization = self._request(
            "POST",
            "/v1/organizations",
            json_body={"name": f"Beta Certification Isolation {nonce}"},
        )
        cross_tenant = self.client.get(
            f"/v1/organizations/{other_organization['id']}/runs/{failed['run_id']}",
            headers=self.auth_headers,
        )
        if cross_tenant.status_code != 403:
            raise BetaExitFailure(
                f"cross-tenant run access returned {cross_tenant.status_code}, expected 403"
            )

        failed_ci = self._release_gate(
            organization_id=organization_id,
            suite_revision_id=suite_revision_id,
            agent_version_id=failed_agent_version_id,
            policy_revision_id=policy["policy_revision_id"],
            behave_securely=False,
        )
        if not failed_ci.get("fail_release"):
            raise BetaExitFailure("release policy did not block the insecure agent version")
        if failed_ci.get("check_run", {}).get("conclusion") != "failure":
            raise BetaExitFailure("CI failure payload was not produced")

        findings = self._request(
            "GET",
            f"/v1/organizations/{organization_id}/projects/{project_id}/findings",
        ).get("findings", [])
        failed_findings = [
            finding for finding in findings if finding.get("run_id") == failed["run_id"]
        ]
        if not failed_findings:
            raise BetaExitFailure("failed release did not produce a triageable finding")
        for finding in failed_findings:
            self._request(
                "PATCH",
                f"/v1/organizations/{organization_id}/findings/{finding['id']}",
                json_body={
                    "status": "remediated",
                    "assignee": "beta-certification",
                    "note": "tool authorization policy corrected",
                },
            )

        remediated = self._request(
            "POST",
            f"/v1/organizations/{organization_id}/agents/{agent['id']}/versions",
            json_body={
                "version": "1.0.1-remediated",
                "artifact_snapshot": {
                    "prompt_version": "certification-remediated",
                    "model_version": "synthetic-1",
                    "tool_versions": {"read_public_doc": "1"},
                    "dataset_version": "certification-1",
                },
            },
        )
        remediated_agent_version_id = remediated["id"]
        passed = self._event_run(
            organization_id=organization_id,
            suite_revision_id=suite_revision_id,
            agent_version_id=remediated_agent_version_id,
            behave_securely=True,
            idempotency_prefix=f"{nonce}-pass",
        )
        if passed.get("gate_result") != "pass":
            raise BetaExitFailure("remediated agent version did not pass the identical suite revision")

        passed_ci = self._release_gate(
            organization_id=organization_id,
            suite_revision_id=suite_revision_id,
            agent_version_id=remediated_agent_version_id,
            policy_revision_id=policy["policy_revision_id"],
            behave_securely=True,
        )
        if passed_ci.get("fail_release"):
            raise BetaExitFailure("release policy blocked the remediated agent version")
        if passed_ci.get("check_run", {}).get("conclusion") != "success":
            raise BetaExitFailure("CI success payload was not produced")

        exported = self._request(
            "GET",
            f"/v1/organizations/{organization_id}/runs/{passed['run_id']}/export",
        )
        verification = verify_bundle(exported["bundle"])
        if not all(verification.values()):
            raise BetaExitFailure(f"offline evidence verification failed: {verification}")
        if "beta-certification-seeded-secret" in json.dumps(exported, sort_keys=True):
            raise BetaExitFailure("seeded credential appeared in the exported evidence")

        cancel_started = self._request(
            "POST",
            f"/v1/organizations/{organization_id}/runs",
            headers={
                **self.auth_headers,
                "Idempotency-Key": f"{nonce}-cancel-run",
            },
            json_body={
                "execution_mode": "event_api",
                "suite_revision_id": suite_revision_id,
                "agent_version_id": remediated_agent_version_id,
                "scenario_key": "unauthorized_tool_invocation",
                "deadline_seconds": 600,
            },
            expected={202},
        )
        cancellation_started = time.perf_counter()
        cancelled = self._request(
            "POST",
            f"/v1/organizations/{organization_id}/runs/{cancel_started['run_id']}/cancel",
            headers={"X-Run-Capability": cancel_started["capability"]},
            json_body={},
        )
        cancellation_seconds = time.perf_counter() - cancellation_started
        if cancelled.get("status") != "cancelled" or cancellation_seconds >= 10:
            raise BetaExitFailure(
                f"cancellation gate failed: status={cancelled.get('status')} "
                f"latency={cancellation_seconds:.3f}s"
            )

        failed_publish = failed_ci.get("publish_result", {})
        passed_publish = passed_ci.get("publish_result", {})
        if self.provider != "none" and not (
            failed_publish.get("published") and passed_publish.get("published")
        ):
            raise BetaExitFailure("configured CI provider did not publish both gate outcomes")
        return BetaExitReport(
            passed=True,
            organization_id=organization_id,
            project_id=project_id,
            suite_revision_id=suite_revision_id,
            failed_agent_version_id=failed_agent_version_id,
            remediated_agent_version_id=remediated_agent_version_id,
            failed_run_id=failed["run_id"],
            passed_run_id=passed["run_id"],
            failed_gate_result=failed["gate_result"],
            passed_gate_result=passed["gate_result"],
            evidence_verification=verification,
            cross_tenant_denial_verified=True,
            redaction_verified=True,
            cancellation_seconds=round(cancellation_seconds, 4),
            ci_failure_published=(
                bool(failed_publish.get("published")) if self.provider != "none" else None
            ),
            ci_success_published=(
                bool(passed_publish.get("published")) if self.provider != "none" else None
            ),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.environ.get("BETA_BASE_URL"),
        help="running control-plane URL (or BETA_BASE_URL)",
    )
    parser.add_argument(
        "--access-token",
        default=os.environ.get("BETA_ACCESS_TOKEN"),
        help="OIDC bearer token (or BETA_ACCESS_TOKEN)",
    )
    parser.add_argument(
        "--dev-user",
        default=os.environ.get("BETA_DEV_USER"),
        help="local-only X-User-Sub identity",
    )
    parser.add_argument(
        "--provider",
        choices=("none", "github", "gitlab"),
        default=os.environ.get("CI_INTEGRATION_PROVIDER", "none"),
    )
    parser.add_argument(
        "--organization-id",
        default=os.environ.get("BETA_ORGANIZATION_ID"),
        help="existing organization that owns the CI installation",
    )
    parser.add_argument(
        "--integration-installation-id",
        default=os.environ.get("CI_INTEGRATION_INSTALLATION_ID"),
    )
    parser.add_argument("--head-sha", default=os.environ.get("CI_HEAD_SHA"))
    parser.add_argument("--output", help="optional JSON report path")
    args = parser.parse_args()
    if not args.base_url:
        parser.error("--base-url or BETA_BASE_URL is required")
    if args.access_token:
        headers = {"Authorization": f"Bearer {args.access_token}"}
    elif args.dev_user:
        headers = {"X-User-Sub": args.dev_user}
    else:
        parser.error("--access-token is required outside local development")

    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=30.0) as client:
        report = BetaExitClient(
            client,
            auth_headers=headers,
            provider=args.provider,
            integration_installation_id=args.integration_installation_id,
            head_sha=args.head_sha,
            organization_id=args.organization_id,
        ).run()
    encoded = json.dumps(report.as_dict(), indent=2, sort_keys=True)
    print(encoded)
    if args.output:
        from pathlib import Path

        Path(args.output).write_text(encoded + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
