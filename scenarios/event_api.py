"""Framework-neutral event ingestion and deterministic run finalization."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from domain import EventType, ExecutionMode, RunStatus
from evidence import (
    build_export_bundle,
    build_manifest,
    canonical_json,
    sha256_bytes,
    sign_payload,
)
from evidence.redaction import UnredactedSecretError, redact_events
from evidence.store import EvidenceStore
from observability.runtime import record_metric
from persistence import AgentVersion, PolicyRevision, Run, RunEvent, new_id, utcnow
from persistence.repositories import (
    AuthorizationError,
    Principal,
    create_run,
    find_run_by_idempotency,
    get_agent_version,
    get_run,
    get_suite_revision,
    issue_worker_capability,
    persist_run_result,
    validate_worker_capability,
)
from scenarios import load_scenario, run_scenario_evaluation
from workers.workflows import start_evaluation_workflow

EVENT_TYPES = {event.value for event in EventType}


class EventSequenceConflict(ValueError):
    pass


class EventSchemaError(ValueError):
    pass


async def start_event_run(
    session: Session,
    principal: Principal,
    *,
    suite_revision_id: str,
    agent_version_id: str,
    policy_revision_id: str | None,
    scenario_key: str | None,
    deadline_seconds: int,
    idempotency_key: str | None,
) -> dict[str, Any]:
    suite_revision = get_suite_revision(session, principal, suite_revision_id)
    agent_version = get_agent_version(session, principal, agent_version_id)
    if suite_revision.project_id != agent_version.project_id:
        raise AuthorizationError("suite and agent version belong to different projects")
    policy_revision = session.get(PolicyRevision, policy_revision_id) if policy_revision_id else None
    if policy_revision_id and policy_revision is None:
        raise AuthorizationError("policy revision not found in project")
    if policy_revision is not None and (
        policy_revision.organization_id != principal.organization_id
        or policy_revision.project_id != agent_version.project_id
    ):
        raise AuthorizationError("policy revision not found in project")
    scenarios = list(suite_revision.scenario_snapshot or [])
    allowed_keys = [str(row.get("scenario_key")) for row in scenarios]
    selected = scenario_key or (allowed_keys[0] if allowed_keys else None)
    if not selected or selected not in allowed_keys:
        raise EventSchemaError("scenario_key must be present in the suite revision")
    definition = load_scenario(selected)
    if idempotency_key:
        existing = find_run_by_idempotency(
            session, principal.organization_id, idempotency_key
        )
        if existing is not None:
            if (
                existing.execution_mode != ExecutionMode.EVENT_API.value
                or existing.suite_revision_id != suite_revision.id
                or existing.agent_version_id != agent_version.id
                or existing.scenario_key != selected
                or (existing.artifact_snapshot or {}).get("policy_revision_id")
                != policy_revision_id
            ):
                raise EventSequenceConflict(
                    "idempotency key was already used for a different run request"
                )
            return {
                "run_id": existing.id,
                "workflow_id": existing.workflow_id,
                "status": existing.status,
                "idempotent_replay": True,
            }
    run = create_run(
        session,
        principal,
        project_id=agent_version.project_id,
        agent_id=agent_version.agent_id,
        scenario_key=selected,
        scenario_version=str(definition.get("version", "1.0.0")),
        suite_id=suite_revision.suite_id,
        idempotency_key=idempotency_key,
        deadline_at=datetime.now(timezone.utc) + timedelta(seconds=deadline_seconds),
    )
    if run.workflow_id:
        return {
            "run_id": run.id,
            "workflow_id": run.workflow_id,
            "status": run.status,
            "idempotent_replay": True,
        }
    run.suite_revision_id = suite_revision.id
    run.agent_version_id = agent_version.id
    run.execution_mode = ExecutionMode.EVENT_API.value
    run.artifact_snapshot = {
        "suite_revision_id": suite_revision.id,
        "suite_revision": suite_revision.revision,
        "scenario_snapshot": scenarios,
        "agent_version_id": agent_version.id,
        "agent_version": agent_version.version,
        "agent_artifacts": agent_version.artifact_snapshot,
        "policy_revision_id": policy_revision_id,
        "policy_revision": policy_revision.revision if policy_revision else None,
        "prompt_version": (agent_version.artifact_snapshot or {}).get(
            "prompt_version", "unspecified"
        ),
        "model_version": (agent_version.artifact_snapshot or {}).get(
            "model_version", "unspecified"
        ),
        "tool_versions": (agent_version.artifact_snapshot or {}).get("tool_versions", {}),
        "dataset_version": (agent_version.artifact_snapshot or {}).get(
            "dataset_version", "unspecified"
        ),
    }
    session.flush()
    workflow = await start_evaluation_workflow(run.id, deadline_seconds)
    run.workflow_id = workflow.workflow_id
    run.status = RunStatus.RUNNING.value
    capability, token = issue_worker_capability(
        session,
        principal,
        project_id=run.project_id,
        run_id=run.id,
        operations=["events:append", "run:complete", "run:cancel"],
        ttl_seconds=deadline_seconds,
        limits={
            "request_ceiling": 1000,
            "cost_ceiling": 100,
            "time_ceiling_seconds": deadline_seconds,
        },
    )
    record_metric("runs.started")
    return {
        "run_id": run.id,
        "workflow_id": workflow.workflow_id,
        "workflow_backend": workflow.backend,
        "status": run.status,
        "capability": token,
        "capability_expires_at": capability.expires_at.isoformat(),
    }


def append_event_batch(
    session: Session,
    *,
    organization_id: str,
    run_id: str,
    token: str,
    events: list[dict[str, Any]],
    batch_idempotency_key: str,
) -> dict[str, Any]:
    capability = validate_worker_capability(
        session,
        token=token,
        organization_id=organization_id,
        run_id=run_id,
        operation="events:append",
    )
    target = session.scalar(
        select(Run).where(
            Run.id == run_id,
            Run.organization_id == organization_id,
        )
    )
    if target is None:
        raise AuthorizationError("run not found in organization")
    if target.status not in {RunStatus.RUNNING.value, RunStatus.QUEUED.value}:
        raise EventSequenceConflict("run is no longer accepting events")
    if not events:
        raise EventSchemaError("event batch cannot be empty")
    request_ceiling = int(
        ((capability.claims or {}).get("limits") or {}).get("request_ceiling", 1000)
    )
    if target.last_event_seq + len(events) > request_ceiling:
        raise EventSchemaError("capability request ceiling exceeded")
    existing = session.scalar(
        select(RunEvent).where(
            RunEvent.run_id == run_id,
            RunEvent.idempotency_key == batch_idempotency_key,
        )
    )
    if existing:
        return {
            "run_id": run_id,
            "accepted": 0,
            "last_seq": target.last_event_seq,
            "idempotent_replay": True,
        }
    expected_seq = target.last_event_seq + 1
    normalized: list[dict[str, Any]] = []
    for offset, event in enumerate(events):
        if str(event.get("schema_version")) != "1":
            raise EventSchemaError("schema_version must be '1'")
        if event.get("type") not in EVENT_TYPES:
            raise EventSchemaError(f"unsupported event type: {event.get('type')}")
        if not isinstance(event.get("payload"), dict):
            raise EventSchemaError("event payload must be an object")
        seq = int(event.get("seq", expected_seq + offset))
        if seq != expected_seq + offset:
            raise EventSequenceConflict(
                f"expected sequence {expected_seq + offset}, received {seq}"
            )
        normalized.append({**event, "seq": seq})
    cost_ceiling = float(
        ((capability.claims or {}).get("limits") or {}).get("cost_ceiling", 100)
    )
    existing_cost = sum(
        float((row.payload.get("payload") or {}).get("units", 0))
        for row in session.scalars(
            select(RunEvent).where(
                RunEvent.run_id == run_id,
                RunEvent.event_type == EventType.COST_TICK.value,
            )
        )
    )
    incoming_cost = sum(
        float((event.get("payload") or {}).get("units", 0))
        for event in normalized
        if event.get("type") == EventType.COST_TICK.value
    )
    if existing_cost + incoming_cost > cost_ceiling:
        raise EventSchemaError("capability cost ceiling exceeded")
    try:
        redacted = redact_events(normalized)
    except UnredactedSecretError as exc:
        record_metric("redaction.rejected")
        raise EventSchemaError(str(exc)) from exc
    for index, event in enumerate(redacted):
        session.add(
            RunEvent(
                id=new_id(),
                organization_id=organization_id,
                project_id=target.project_id,
                run_id=run_id,
                seq=event["seq"],
                event_type=event["type"],
                payload=event,
                idempotency_key=batch_idempotency_key if index == 0 else None,
            )
        )
    target.last_event_seq = expected_seq + len(redacted) - 1
    try:
        session.flush()
    except IntegrityError as exc:
        raise EventSequenceConflict("event sequence or idempotency conflict") from exc
    record_metric("events.accepted", len(redacted))
    return {"run_id": run_id, "accepted": len(redacted), "last_seq": target.last_event_seq}


def complete_event_run(
    session: Session,
    *,
    organization_id: str,
    run_id: str,
    token: str,
) -> dict[str, Any]:
    validate_worker_capability(
        session,
        token=token,
        organization_id=organization_id,
        run_id=run_id,
        operation="run:complete",
    )
    run = session.scalar(
        select(Run).where(Run.id == run_id, Run.organization_id == organization_id)
    )
    if run is None:
        raise AuthorizationError("run not found in organization")
    if run.status == RunStatus.COMPLETED.value:
        return {"run_id": run.id, "status": run.status, "gate_result": run.gate_result}
    if run.status != RunStatus.RUNNING.value:
        raise EventSequenceConflict("run cannot be completed from its current state")
    run.ingest_completed_at = utcnow()
    run.status = RunStatus.EVALUATING.value
    events = [
        row.payload
        for row in session.scalars(
            select(RunEvent).where(RunEvent.run_id == run.id).order_by(RunEvent.seq)
        )
    ]
    if not events:
        raise EventSchemaError("run has no events")
    outcome = run_scenario_evaluation(run.scenario_key, events)
    version = session.get(AgentVersion, run.agent_version_id) if run.agent_version_id else None
    run.status = RunStatus.SEALING.value
    manifest, content_hash = build_manifest(
        organization_id=run.organization_id,
        project_id=run.project_id,
        run_id=run.id,
        scenario_key=outcome.scenario_key,
        scenario_version=outcome.scenario_version,
        agent_version=version.version if version else "unknown",
        gate_result=outcome.gate_result,
        events=events,
        findings=outcome.findings,
        sign=True,
    )
    bundle = build_export_bundle(
        manifest=manifest,
        events=events,
        findings=outcome.findings,
        gate_result=outcome.gate_result.value,
        scenario_key=outcome.scenario_key,
        run_id=run.id,
    )
    object_uri = EvidenceStore().put_json(
        organization_id=run.organization_id,
        project_id=run.project_id,
        run_id=run.id,
        name="evidence-bundle.json",
        payload=bundle,
    )
    manifest["objects"] = [
        {
            "name": "evidence-bundle.json",
            "uri": object_uri,
            "content_type": "application/json",
        }
    ]
    manifest["signature"] = None
    manifest["signature"] = sign_payload(manifest)
    content_hash = sha256_bytes(canonical_json(manifest))
    bundle = build_export_bundle(
        manifest=manifest,
        events=events,
        findings=outcome.findings,
        gate_result=outcome.gate_result.value,
        scenario_key=outcome.scenario_key,
        run_id=run.id,
    )
    EvidenceStore().put_json(
        organization_id=run.organization_id,
        project_id=run.project_id,
        run_id=run.id,
        name="evidence-bundle.json",
        payload=bundle,
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
        persist_events=False,
    )
    record_metric("runs.completed")
    record_metric(f"gates.{run.gate_result}")
    return {
        "run_id": run.id,
        "status": run.status,
        "gate_result": run.gate_result,
        "evidence_id": evidence.id,
        "object_uri": object_uri,
        "signature": manifest.get("signature"),
    }


def cancel_event_run(
    session: Session,
    *,
    organization_id: str,
    run_id: str,
    token: str,
) -> dict[str, Any]:
    validate_worker_capability(
        session,
        token=token,
        organization_id=organization_id,
        run_id=run_id,
        operation="run:cancel",
    )
    run = session.scalar(
        select(Run).where(Run.id == run_id, Run.organization_id == organization_id)
    )
    if run is None:
        raise AuthorizationError("run not found in organization")
    if run.status in {RunStatus.COMPLETED.value, RunStatus.FAILED.value, RunStatus.CANCELLED.value}:
        return {"run_id": run.id, "status": run.status}
    run.status = RunStatus.CANCELLED.value
    run.completed_at = utcnow()
    record_metric("runs.cancelled")
    return {"run_id": run.id, "status": run.status}
