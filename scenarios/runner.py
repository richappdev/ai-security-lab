"""Execute and persist scenario evaluations (optionally via durable engine)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from agents.adapters.synthetic import simulate
from domain import GateResult, RunStatus
from evidence import build_export_bundle, build_manifest, canonical_json
from evidence.store import EvidenceStore
from persistence.repositories import (
    Principal,
    create_run,
    get_agent,
    persist_run_result,
)
from scenarios import load_scenario, run_scenario_evaluation
from workers.durable import get_durable_engine, use_durable_runs
from workers.temporal_stub import CapabilityDocument


def _store_evidence_blobs(
    *,
    organization_id: str,
    project_id: str,
    run_id: str,
    events: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    manifest: dict[str, Any],
    bundle: dict[str, Any],
) -> dict[str, str]:
    store = EvidenceStore()
    events_uri = store.put_json(
        organization_id=organization_id,
        project_id=project_id,
        run_id=run_id,
        name="events.json",
        payload={"events": events, "findings": findings},
    )
    sarif_uri = store.put_json(
        organization_id=organization_id,
        project_id=project_id,
        run_id=run_id,
        name="results.sarif.json",
        payload=bundle["sarif"],
    )
    bundle_uri = store.put_json(
        organization_id=organization_id,
        project_id=project_id,
        run_id=run_id,
        name="evidence-bundle.json",
        payload=bundle,
    )
    manifest_uri = store.put_json(
        organization_id=organization_id,
        project_id=project_id,
        run_id=run_id,
        name="manifest.json",
        payload=manifest,
    )
    return {
        "events": events_uri,
        "sarif": sarif_uri,
        "bundle": bundle_uri,
        "manifest": manifest_uri,
    }


def _run_scenario_body(
    *,
    agent,
    run,
    scenario_key: str,
    behave_securely: bool,
    store_blob: bool,
    capability: CapabilityDocument | None = None,
) -> dict[str, Any]:
    if capability is not None:
        capability.revalidate()
    events = simulate(
        scenario_key,
        allowed_tools=list(agent.allowed_tools or []),
        behave_securely=behave_securely,
    )
    if capability is not None:
        # Synthetic evaluations assert policy outcomes; expiry/ceilings still enforced.
        capability.revalidate()
        if capability.request_ceiling < len(events):
            raise PermissionError("request ceiling exceeded")

    outcome = run_scenario_evaluation(scenario_key, events)
    uris: dict[str, str] = {}
    object_uri = None
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
        object_uri=None,
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
    if store_blob:
        uris = _store_evidence_blobs(
            organization_id=run.organization_id,
            project_id=run.project_id,
            run_id=run.id,
            events=events,
            findings=outcome.findings,
            manifest=manifest,
            bundle=bundle,
        )
        object_uri = uris.get("bundle")
        manifest["objects"] = [
            {"name": name, "uri": uri, "content_type": "application/json"}
            for name, uri in uris.items()
        ]
        from evidence import sha256_bytes, sign_payload

        unsigned = dict(manifest)
        unsigned["signature"] = None
        manifest["signature"] = sign_payload(unsigned)
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

    return {
        "events": events,
        "outcome": outcome,
        "manifest": manifest,
        "content_hash": content_hash,
        "object_uri": object_uri,
        "uris": uris,
        "bundle": bundle,
    }


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
    durable: bool | None = None,
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

    use_durable = use_durable_runs() if durable is None else durable
    workflow_meta: dict[str, Any] = {}

    if use_durable:
        engine = get_durable_engine()

        def _execute(capability: CapabilityDocument) -> dict[str, Any]:
            return _run_scenario_body(
                agent=agent,
                run=run,
                scenario_key=scenario_key,
                behave_securely=behave_securely,
                store_blob=store_blob,
                capability=capability,
            )

        handle = engine.start_evaluation(
            run_id=run.id,
            organization_id=run.organization_id,
            allowed_tools=list(agent.allowed_tools or []),
            execute=_execute,
        )
        workflow_meta = {
            "workflow_id": handle.workflow_id,
            "workflow_status": handle.status,
        }
        if handle.status != "completed" or not handle.result:
            run.status = RunStatus.FAILED.value
            session.flush()
            return {
                "run_id": run.id,
                "gate_result": GateResult.FAIL.value,
                "error": (handle.result or {}).get("error", "durable run failed"),
                **workflow_meta,
            }
        body = handle.result
    else:
        body = _run_scenario_body(
            agent=agent,
            run=run,
            scenario_key=scenario_key,
            behave_securely=behave_securely,
            store_blob=store_blob,
        )

    outcome = body["outcome"]
    evidence = persist_run_result(
        session,
        run=run,
        events=body["events"],
        findings=outcome.findings,
        gate_result=outcome.gate_result,
        evidence_manifest=body["manifest"],
        content_sha256=body["content_hash"],
        object_uri=body["object_uri"],
    )
    return {
        "run_id": run.id,
        "gate_result": outcome.gate_result.value,
        "findings": outcome.findings,
        "evidence_id": evidence.id,
        "content_sha256": body["content_hash"],
        "object_uri": body["object_uri"],
        "uris": body.get("uris") or {},
        "mitigation_guidance": outcome.mitigation_guidance,
        "assertion_results": [
            {"id": r.assertion_id, "passed": r.passed} for r in outcome.assertion_results
        ],
        "manifest_signature": body["manifest"].get("signature"),
        **workflow_meta,
    }


def execute_suite(
    session: Session,
    principal: Principal,
    *,
    project_id: str,
    agent_id: str,
    scenario_keys: list[str],
    behave_securely: bool = True,
    durable: bool | None = None,
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
                durable=durable,
            )
        )
    failed = [r for r in results if r.get("gate_result") == GateResult.FAIL.value]
    evidence_uris = []
    for r in results:
        evidence_uris.extend((r.get("uris") or {}).values())
        if r.get("object_uri"):
            evidence_uris.append(r["object_uri"])
    return {
        "suite_gate_result": GateResult.FAIL.value if failed else GateResult.PASS.value,
        "results": results,
        "failed_count": len(failed),
        "run_ids": [r["run_id"] for r in results],
        "evidence_uris": sorted(set(evidence_uris)),
    }
