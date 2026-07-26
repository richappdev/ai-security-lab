"""Execute and persist scenario evaluations."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from agents.adapters.synthetic import simulate
from domain import GateResult, RunStatus
from evidence import build_manifest
from evidence.store import EvidenceStore
from persistence.repositories import (
    Principal,
    create_run,
    get_agent,
    persist_run_result,
)
from scenarios import load_scenario, run_scenario_evaluation


def execute_evaluation(
    session: Session,
    principal: Principal,
    *,
    project_id: str,
    agent_id: str,
    scenario_key: str,
    behave_securely: bool = True,
    idempotency_key: str | None = None,
    store_blob: bool = True,
    suite_id: str | None = None,
) -> dict[str, Any]:
    agent = get_agent(session, principal, agent_id)
    definition = load_scenario(scenario_key)
    scenario_version = str(definition.get("version", "1.0.0"))
    run = create_run(
        session,
        principal,
        project_id=project_id,
        agent_id=agent_id,
        scenario_key=scenario_key,
        scenario_version=scenario_version,
        suite_id=suite_id,
        idempotency_key=idempotency_key,
    )
    if run.status == RunStatus.COMPLETED.value and run.gate_result is not None:
        return {
            "run_id": run.id,
            "gate_result": run.gate_result,
            "idempotent_replay": True,
        }

    run.status = RunStatus.RUNNING.value
    session.flush()

    events = simulate(
        scenario_key,
        allowed_tools=list(agent.allowed_tools or []),
        behave_securely=behave_securely,
    )
    outcome = run_scenario_evaluation(scenario_key, events)

    object_uri = None
    if store_blob:
        object_uri = EvidenceStore().put_json(
            organization_id=run.organization_id,
            project_id=run.project_id,
            run_id=run.id,
            name="events.json",
            payload={"events": events, "findings": outcome.findings},
        )

    manifest, content_hash = build_manifest(
        organization_id=run.organization_id,
        project_id=run.project_id,
        run_id=run.id,
        scenario_key=outcome.scenario_key,
        scenario_version=outcome.scenario_version,
        agent_version=agent.version,
        gate_result=outcome.gate_result,
        events=events,
        findings=outcome.findings,
        object_uri=object_uri,
    )
    evidence = persist_run_result(
        session,
        run=run,
        events=events,
        findings=outcome.findings,
        gate_result=outcome.gate_result,
        evidence_manifest=manifest,
        content_sha256=content_hash,
        object_uri=object_uri,
    )
    return {
        "run_id": run.id,
        "gate_result": outcome.gate_result.value,
        "findings": outcome.findings,
        "evidence_id": evidence.id,
        "content_sha256": content_hash,
        "object_uri": object_uri,
        "mitigation_guidance": outcome.mitigation_guidance,
        "assertion_results": [
            {"id": r.assertion_id, "passed": r.passed} for r in outcome.assertion_results
        ],
    }


def execute_suite(
    session: Session,
    principal: Principal,
    *,
    project_id: str,
    agent_id: str,
    scenario_keys: list[str],
    behave_securely: bool = True,
) -> dict[str, Any]:
    results = []
    for key in scenario_keys:
        results.append(
            execute_evaluation(
                session,
                principal,
                project_id=project_id,
                agent_id=agent_id,
                scenario_key=key,
                behave_securely=behave_securely,
            )
        )
    failed = [r for r in results if r["gate_result"] == GateResult.FAIL.value]
    return {
        "suite_gate_result": GateResult.FAIL.value if failed else GateResult.PASS.value,
        "results": results,
        "failed_count": len(failed),
    }
