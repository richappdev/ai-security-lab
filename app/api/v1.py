"""Versioned control-plane API (/v1)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import AuthContext, auth_config, get_auth_context, get_db
from domain import FindingStatus, OrgRole
from evidence import build_export_bundle, verify_signature
from evidence.store import EvidenceStore
from integrations.ci_gates import (
    build_check_run_payload,
    build_gitlab_status_payload,
    publish_github_check_run,
    publish_gitlab_commit_status,
    should_fail_release,
)
from persistence import RunEvent
from persistence.repositories import (
    AuthorizationError,
    add_membership,
    create_agent,
    create_organization,
    create_project,
    create_suite,
    get_evidence_for_run,
    get_run,
    list_findings_for_run,
    list_project_findings,
    require_role,
    resolve_principal,
    update_finding_status,
)
from scenarios import list_scenario_keys
from scenarios.runner import execute_evaluation, execute_suite
from sqlalchemy import select
from workers.durable import get_durable_engine

router = APIRouter(prefix="/v1", tags=["product-v1"])


class CreateOrgRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)


class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)


class CreateAgentRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    version: str = "1.0.0"
    allowed_tools: list[str] = Field(default_factory=lambda: ["read_public_doc"])


class CreateMembershipRequest(BaseModel):
    user_sub: str
    role: str = OrgRole.VIEWER.value


class CreateSuiteRequest(BaseModel):
    name: str
    scenario_keys: list[str]


class CreateRunRequest(BaseModel):
    project_id: str
    agent_id: str
    scenario_key: str
    behave_securely: bool = True
    idempotency_key: str | None = None
    store_blob: bool = True
    durable: bool | None = None


class CreateSuiteRunRequest(BaseModel):
    project_id: str
    agent_id: str
    scenario_keys: list[str]
    behave_securely: bool = True
    durable: bool | None = None


class UpdateFindingRequest(BaseModel):
    status: str
    assignee: str | None = None
    note: str | None = None


class ReleaseGateRequest(BaseModel):
    suite_name: str = "core"
    project_id: str
    agent_id: str
    scenario_keys: list[str]
    behave_securely: bool = True
    head_sha: str | None = None
    provider: str = Field("github", pattern="^(github|gitlab|none)$")
    max_failed: int = 0
    publish: bool = True


@router.get("/auth/config")
def api_auth_config() -> dict[str, Any]:
    return auth_config()


def _principal(db: Session, auth: AuthContext, organization_id: str):
    try:
        return resolve_principal(db, auth.user_sub, organization_id)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/organizations")
def api_create_org(
    body: CreateOrgRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    org = create_organization(db, body.name, auth.user_sub)
    db.flush()
    return {"id": org.id, "name": org.name, "status": org.status}


@router.post("/organizations/{organization_id}/memberships")
def api_add_membership(
    organization_id: str,
    body: CreateMembershipRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        require_role(principal, admin=True)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    m = add_membership(db, organization_id, body.user_sub, body.role)
    return {"id": m.id, "user_sub": m.user_sub, "role": m.role}


@router.post("/organizations/{organization_id}/projects")
def api_create_project(
    organization_id: str,
    body: CreateProjectRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        project = create_project(db, principal, body.name)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    db.flush()
    return {"id": project.id, "name": project.name, "organization_id": project.organization_id}


@router.post("/organizations/{organization_id}/projects/{project_id}/agents")
def api_create_agent(
    organization_id: str,
    project_id: str,
    body: CreateAgentRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        agent = create_agent(
            db,
            principal,
            project_id,
            body.name,
            allowed_tools=body.allowed_tools,
            version=body.version,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    db.flush()
    return {
        "id": agent.id,
        "name": agent.name,
        "version": agent.version,
        "allowed_tools": agent.allowed_tools,
    }


@router.post("/organizations/{organization_id}/projects/{project_id}/suites")
def api_create_suite(
    organization_id: str,
    project_id: str,
    body: CreateSuiteRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        suite = create_suite(db, principal, project_id, body.name, body.scenario_keys)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    db.flush()
    return {"id": suite.id, "name": suite.name, "scenario_keys": suite.scenario_keys}


@router.get("/scenarios")
def api_list_scenarios() -> dict[str, Any]:
    return {"scenarios": list_scenario_keys()}


@router.post("/organizations/{organization_id}/runs")
def api_create_run(
    organization_id: str,
    body: CreateRunRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    key = body.idempotency_key or idempotency_key
    try:
        result = execute_evaluation(
            db,
            principal,
            project_id=body.project_id,
            agent_id=body.agent_id,
            scenario_key=body.scenario_key,
            behave_securely=body.behave_securely,
            idempotency_key=key,
            store_blob=body.store_blob,
            durable=body.durable,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return result


@router.post("/organizations/{organization_id}/suite-runs")
def api_suite_run(
    organization_id: str,
    body: CreateSuiteRunRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        return execute_suite(
            db,
            principal,
            project_id=body.project_id,
            agent_id=body.agent_id,
            scenario_keys=body.scenario_keys,
            behave_securely=body.behave_securely,
            durable=body.durable,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/organizations/{organization_id}/release-gates")
def api_release_gate(
    organization_id: str,
    body: ReleaseGateRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        suite = execute_suite(
            db,
            principal,
            project_id=body.project_id,
            agent_id=body.agent_id,
            scenario_keys=body.scenario_keys,
            behave_securely=body.behave_securely,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    fail_release = should_fail_release(
        suite["suite_gate_result"],
        max_failed=body.max_failed,
        failed_count=suite["failed_count"],
    )
    check_payload = build_check_run_payload(
        suite_name=body.suite_name,
        gate_result=suite["suite_gate_result"],
        failed_count=suite["failed_count"],
        run_ids=suite.get("run_ids") or [],
        evidence_uris=suite.get("evidence_uris") or [],
        head_sha=body.head_sha,
    )
    publish_result: dict[str, Any] = {"published": False, "skipped": True}
    if body.publish and body.provider == "github":
        publish_result = publish_github_check_run(check_payload)
    elif body.publish and body.provider == "gitlab":
        gl_payload = build_gitlab_status_payload(
            suite_name=body.suite_name,
            gate_result=suite["suite_gate_result"],
        )
        publish_result = publish_gitlab_commit_status(gl_payload, sha=body.head_sha)

    return {
        **suite,
        "fail_release": fail_release,
        "check_run": check_payload,
        "publish_result": publish_result,
    }


@router.get("/organizations/{organization_id}/runs/{run_id}")
def api_get_run(
    organization_id: str,
    run_id: str,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        run = get_run(db, principal, run_id)
        findings = list_findings_for_run(db, principal, run_id)
        evidence = get_evidence_for_run(db, principal, run_id)
        events = list(
            db.scalars(
                select(RunEvent)
                .where(
                    RunEvent.run_id == run_id,
                    RunEvent.organization_id == organization_id,
                )
                .order_by(RunEvent.seq)
            )
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return {
        "id": run.id,
        "status": run.status,
        "gate_result": run.gate_result,
        "scenario_key": run.scenario_key,
        "scenario_version": run.scenario_version,
        "events": [{"seq": e.seq, "type": e.event_type, "payload": e.payload} for e in events],
        "findings": [
            {
                "id": f.id,
                "assertion_id": f.assertion_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "detail": f.detail,
            }
            for f in findings
        ],
        "evidence": None
        if evidence is None
        else {
            "id": evidence.id,
            "status": evidence.status,
            "result": evidence.result,
            "content_sha256": evidence.content_sha256,
            "object_uri": evidence.object_uri,
            "manifest": evidence.manifest,
            "signature_valid": verify_signature(
                {**evidence.manifest, "signature": None} if evidence.manifest else {},
                (evidence.manifest or {}).get("signature"),
            )
            if evidence.manifest
            else False,
        },
    }


@router.get("/organizations/{organization_id}/runs/{run_id}/export")
def api_export_evidence(
    organization_id: str,
    run_id: str,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        run = get_run(db, principal, run_id)
        evidence = get_evidence_for_run(db, principal, run_id)
        findings = list_findings_for_run(db, principal, run_id)
        events = [
            e.payload
            for e in db.scalars(
                select(RunEvent)
                .where(
                    RunEvent.run_id == run_id,
                    RunEvent.organization_id == organization_id,
                )
                .order_by(RunEvent.seq)
            )
        ]
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if evidence is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    finding_payloads = [
        {
            "assertion_id": f.assertion_id,
            "title": f.title,
            "severity": f.severity,
            "detail": f.detail,
        }
        for f in findings
    ]
    bundle = build_export_bundle(
        manifest=evidence.manifest or {},
        events=events,
        findings=finding_payloads,
        gate_result=run.gate_result or "fail",
        scenario_key=run.scenario_key,
        run_id=run.id,
    )
    # Persist refreshed export bundle
    uri = EvidenceStore().put_json(
        organization_id=run.organization_id,
        project_id=run.project_id,
        run_id=run.id,
        name="evidence-bundle.json",
        payload=bundle,
    )
    return {"bundle": bundle, "object_uri": uri, "signature": bundle.get("signature")}


@router.get("/organizations/{organization_id}/projects/{project_id}/findings")
def api_list_findings(
    organization_id: str,
    project_id: str,
    status: str | None = None,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        rows = list_project_findings(db, principal, project_id, status=status)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return {
        "findings": [
            {
                "id": f.id,
                "run_id": f.run_id,
                "assertion_id": f.assertion_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "detail": f.detail,
            }
            for f in rows
        ]
    }


@router.patch("/organizations/{organization_id}/findings/{finding_id}")
def api_update_finding(
    organization_id: str,
    finding_id: str,
    body: UpdateFindingRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    if body.status not in {s.value for s in FindingStatus}:
        raise HTTPException(status_code=400, detail="invalid status")
    try:
        finding = update_finding_status(
            db,
            principal,
            finding_id,
            status=body.status,
            assignee=body.assignee,
            note=body.note,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "id": finding.id,
        "status": finding.status,
        "detail": finding.detail,
    }


@router.get("/workflows/{workflow_id}")
def api_describe_workflow(workflow_id: str) -> dict[str, Any]:
    try:
        return get_durable_engine().describe(workflow_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="workflow not found") from exc
