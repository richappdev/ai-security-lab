"""Persisted immutable suite execution and regression comparison."""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from domain import GateResult
from persistence import Finding, Run, SuiteRun, new_id, utcnow
from persistence.repositories import (
    Principal,
    get_agent_version,
    get_suite_revision,
    require_role,
)
from scenarios.runner import execute_evaluation


def _fingerprint(scenario_key: str, assertion_id: str) -> str:
    return hashlib.sha256(f"{scenario_key}:{assertion_id}".encode()).hexdigest()


def execute_persisted_suite(
    session: Session,
    principal: Principal,
    *,
    suite_revision_id: str,
    agent_version_id: str,
    policy_revision_id: str | None = None,
    behave_securely: bool = True,
    durable: bool | None = None,
) -> dict[str, Any]:
    require_role(principal, write=True)
    revision = get_suite_revision(session, principal, suite_revision_id)
    agent_version = get_agent_version(session, principal, agent_version_id)
    if revision.project_id != agent_version.project_id:
        raise ValueError("suite revision and agent version belong to different projects")
    suite_run = SuiteRun(
        id=new_id(),
        organization_id=principal.organization_id,
        project_id=revision.project_id,
        suite_revision_id=revision.id,
        agent_version_id=agent_version.id,
        policy_revision_id=policy_revision_id,
        status="running",
    )
    session.add(suite_run)
    session.flush()

    previous = session.scalar(
        select(SuiteRun)
        .where(
            SuiteRun.organization_id == principal.organization_id,
            SuiteRun.suite_revision_id == revision.id,
            SuiteRun.status == "completed",
            SuiteRun.gate_result == GateResult.PASS.value,
            SuiteRun.id != suite_run.id,
        )
        .order_by(SuiteRun.completed_at.desc())
    )
    previous_fingerprints: set[str] = set()
    if previous:
        previous_run_ids = list(
            session.scalars(select(Run.id).where(Run.suite_run_id == previous.id))
        )
        if previous_run_ids:
            previous_fingerprints = {
                value
                for value in session.scalars(
                    select(Finding.fingerprint).where(Finding.run_id.in_(previous_run_ids))
                )
                if value
            }

    results = []
    current_fingerprints: set[str] = set()
    for scenario in revision.scenario_snapshot:
        scenario_key = str(scenario["scenario_key"])
        result = execute_evaluation(
            session,
            principal,
            project_id=revision.project_id,
            agent_id=agent_version.agent_id,
            scenario_key=scenario_key,
            behave_securely=behave_securely,
            suite_id=revision.suite_id,
            durable=durable,
        )
        run = session.get(Run, result["run_id"])
        run.suite_revision_id = revision.id
        run.suite_run_id = suite_run.id
        run.agent_version_id = agent_version.id
        run.artifact_snapshot = {
            "suite_revision_id": revision.id,
            "suite_revision": revision.revision,
            "agent_version_id": agent_version.id,
            "agent_version": agent_version.version,
            "scenario": scenario,
            "policy_revision_id": policy_revision_id,
        }
        for finding in session.scalars(select(Finding).where(Finding.run_id == run.id)):
            finding.fingerprint = _fingerprint(scenario_key, finding.assertion_id)
            current_fingerprints.add(finding.fingerprint)
            finding.regression_state = (
                "regressed"
                if previous and finding.fingerprint not in previous_fingerprints
                else "existing"
                if finding.fingerprint in previous_fingerprints
                else "new"
            )
        results.append(result)

    failed = [result for result in results if result.get("gate_result") == GateResult.FAIL.value]
    passed_count = len(results) - len(failed)
    suite_run.status = "completed"
    suite_run.gate_result = GateResult.FAIL.value if failed else GateResult.PASS.value
    suite_run.score = round(100 * passed_count / len(results)) if results else 0
    historical = list(
        session.scalars(
            select(SuiteRun).where(
                SuiteRun.organization_id == principal.organization_id,
                SuiteRun.suite_revision_id == revision.id,
                SuiteRun.agent_version_id == agent_version.id,
                SuiteRun.status == "completed",
                SuiteRun.id != suite_run.id,
            )
        )
    )
    signatures = [
        f"{row.gate_result}:{row.score}" for row in historical
    ] + [f"{suite_run.gate_result}:{suite_run.score}"]
    modal_count = max(Counter(signatures).values())
    suite_run.comparison = {
        "baseline_suite_run_id": previous.id if previous else None,
        "new_or_regressed": sorted(current_fingerprints - previous_fingerprints),
        "resolved": sorted(previous_fingerprints - current_fingerprints),
        "unchanged": sorted(previous_fingerprints & current_fingerprints),
        "reproducibility": {
            "sample_size": len(signatures),
            "identical_result_rate": round(modal_count / len(signatures), 4),
        },
    }
    suite_run.completed_at = utcnow()
    return {
        "suite_run_id": suite_run.id,
        "suite_revision_id": revision.id,
        "agent_version_id": agent_version.id,
        "suite_gate_result": suite_run.gate_result,
        "score": suite_run.score,
        "comparison": suite_run.comparison,
        "failed_count": len(failed),
        "run_ids": [result["run_id"] for result in results],
        "results": results,
    }
