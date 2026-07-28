"""Versioned control-plane API (/v1)."""

from __future__ import annotations

from datetime import datetime
import os
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import AuthContext, auth_config, get_auth_context, get_db
from domain import FindingStatus, GateResult, OrgRole
from evidence import build_export_bundle, verify_signature
from evidence.store import EvidenceStore
from integrations.ci_gates import (
    build_check_run_payload,
    build_gitlab_status_payload,
    publish_github_check_run,
    publish_gitlab_commit_status,
    should_fail_release,
)
from integrations.installations import create_installation, installation_config
from policies import evaluate_release_policy
from persistence import (
    AgentVersion,
    ApprovalException,
    PolicyRevision,
    Run,
    RunEvent,
    SuiteRevision,
)
from persistence.repositories import (
    AuthorizationError,
    audit_authz,
    add_membership,
    add_project_membership,
    create_agent,
    create_agent_version,
    create_approval_exception,
    create_organization,
    create_policy_revision,
    create_project,
    create_suite,
    create_suite_revision,
    active_exceptions,
    get_evidence_for_run,
    get_run,
    get_suite_revision,
    list_findings_for_run,
    list_project_findings,
    require_role,
    resolve_principal,
    update_finding_status,
)
from scenarios import list_scenario_keys
from scenarios.event_api import (
    EventSchemaError,
    EventSequenceConflict,
    append_event_batch,
    cancel_event_run,
    complete_event_run,
    start_event_run,
)
from scenarios.runner import execute_evaluation, execute_suite
from scenarios.suites import execute_persisted_suite
from sqlalchemy import select
from workers.durable import get_durable_engine
from workers.workflows import signal_evaluation_workflow

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
    role: str = Field(OrgRole.VIEWER.value, pattern="^(owner|operator|viewer)$")


class CreateSuiteRequest(BaseModel):
    name: str
    scenario_keys: list[str]


class CreateRunRequest(BaseModel):
    project_id: str | None = None
    agent_id: str | None = None
    scenario_key: str | None = None
    suite_revision_id: str | None = None
    agent_version_id: str | None = None
    policy_revision_id: str | None = None
    deadline_seconds: int = Field(600, ge=10, le=86400)
    execution_mode: str = Field("synthetic_local", pattern="^(synthetic_local|event_api)$")
    behave_securely: bool = True
    idempotency_key: str | None = None
    store_blob: bool = True
    durable: bool | None = None


class CreateSuiteRunRequest(BaseModel):
    project_id: str | None = None
    agent_id: str | None = None
    scenario_keys: list[str] = Field(default_factory=list)
    suite_revision_id: str | None = None
    agent_version_id: str | None = None
    policy_revision_id: str | None = None
    behave_securely: bool = True
    durable: bool | None = None


class UpdateFindingRequest(BaseModel):
    status: str
    assignee: str | None = None
    note: str | None = None


class ReleaseGateRequest(BaseModel):
    suite_name: str = "core"
    project_id: str | None = None
    agent_id: str | None = None
    scenario_keys: list[str] = Field(default_factory=list)
    suite_revision_id: str | None = None
    agent_version_id: str | None = None
    behave_securely: bool = True
    head_sha: str | None = None
    provider: str = Field("github", pattern="^(github|gitlab|none)$")
    max_failed: int = 0
    publish: bool = True
    policy_revision_id: str | None = None
    integration_installation_id: str | None = None


class CreateAgentVersionRequest(BaseModel):
    version: str = Field(..., min_length=1, max_length=64)
    artifact_snapshot: dict[str, Any] = Field(default_factory=dict)


class CreateSuiteRevisionRequest(BaseModel):
    scenarios: list[dict[str, Any]] = Field(..., min_length=1)


class EventBatchRequest(BaseModel):
    events: list[dict[str, Any]] = Field(..., min_length=1, max_length=1000)


class CreatePolicyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    policy_id: str | None = None
    rules: dict[str, Any] = Field(default_factory=dict)


class CreateExceptionRequest(BaseModel):
    project_id: str
    policy_revision_id: str
    finding_id: str | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(..., min_length=3, max_length=2000)
    expires_at: datetime


class CreateIntegrationRequest(BaseModel):
    provider: str = Field(..., pattern="^(github|gitlab)$")
    project_id: str | None = None
    config: dict[str, Any]


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


@router.post("/organizations/{organization_id}/projects/{project_id}/memberships")
def api_add_project_membership(
    organization_id: str,
    project_id: str,
    body: CreateMembershipRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        row = add_project_membership(
            db,
            principal,
            project_id,
            user_sub=body.user_sub,
            role=body.role,
        )
        db.flush()
        return {
            "id": row.id,
            "project_id": row.project_id,
            "user_sub": row.user_sub,
            "role": row.role,
        }
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


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
    version_row = db.scalar(
        select(AgentVersion)
        .where(AgentVersion.agent_id == agent.id)
        .order_by(AgentVersion.created_at.desc())
    )
    return {
        "id": agent.id,
        "name": agent.name,
        "version": agent.version,
        "allowed_tools": agent.allowed_tools,
        "agent_version_id": version_row.id if version_row else None,
    }


@router.post("/organizations/{organization_id}/agents/{agent_id}/versions")
def api_create_agent_version(
    organization_id: str,
    agent_id: str,
    body: CreateAgentVersionRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        row = create_agent_version(
            db,
            principal,
            agent_id,
            version=body.version,
            artifact_snapshot=body.artifact_snapshot,
        )
        db.flush()
        return {
            "id": row.id,
            "agent_id": row.agent_id,
            "version": row.version,
            "artifact_snapshot": row.artifact_snapshot,
        }
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


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
    revision = db.scalar(
        select(SuiteRevision)
        .where(SuiteRevision.suite_id == suite.id)
        .order_by(SuiteRevision.revision.desc())
    )
    return {
        "id": suite.id,
        "name": suite.name,
        "scenario_keys": suite.scenario_keys,
        "suite_revision_id": revision.id if revision else None,
        "revision": revision.revision if revision else None,
    }


@router.post("/organizations/{organization_id}/suites/{suite_id}/revisions")
def api_create_suite_revision(
    organization_id: str,
    suite_id: str,
    body: CreateSuiteRevisionRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        row = create_suite_revision(db, principal, suite_id, body.scenarios)
        db.flush()
        return {
            "id": row.id,
            "suite_id": row.suite_id,
            "revision": row.revision,
            "scenarios": row.scenario_snapshot,
        }
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/scenarios")
def api_list_scenarios() -> dict[str, Any]:
    return {"scenarios": list_scenario_keys()}


@router.post("/organizations/{organization_id}/runs")
async def api_create_run(
    organization_id: str,
    body: CreateRunRequest,
    response: Response,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    key = body.idempotency_key or idempotency_key
    try:
        if body.execution_mode == "event_api":
            if not body.suite_revision_id or not body.agent_version_id:
                raise HTTPException(
                    status_code=422,
                    detail="suite_revision_id and agent_version_id are required for event_api",
                )
            result = await start_event_run(
                db,
                principal,
                suite_revision_id=body.suite_revision_id,
                agent_version_id=body.agent_version_id,
                policy_revision_id=body.policy_revision_id,
                scenario_key=body.scenario_key,
                deadline_seconds=body.deadline_seconds,
                idempotency_key=key,
            )
            response.status_code = 202
            return result
        if not body.project_id or not body.agent_id or not body.scenario_key:
            raise HTTPException(
                status_code=422,
                detail="project_id, agent_id, and scenario_key are required for synthetic_local",
            )
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
    except EventSchemaError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except EventSequenceConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return result


def _capability_token(authorization: str | None, x_run_capability: str | None) -> str:
    if x_run_capability:
        return x_run_capability
    if authorization and authorization.lower().startswith("capability "):
        return authorization.split(" ", 1)[1].strip()
    raise HTTPException(status_code=401, detail="missing run capability")


async def _signal_or_record(
    run: Run | None,
    signal: str,
    payload: int | None = None,
) -> bool:
    if run is None:
        return False
    try:
        await signal_evaluation_workflow(run.workflow_id, signal, payload)
        return True
    except Exception as exc:  # Temporal outage must not roll back durable DB state.
        snapshot = dict(run.artifact_snapshot or {})
        pending = list(snapshot.get("pending_workflow_signals") or [])
        pending.append({"signal": signal, "payload": payload, "error": str(exc)})
        snapshot["pending_workflow_signals"] = pending
        run.artifact_snapshot = snapshot
        return False


@router.post("/organizations/{organization_id}/runs/{run_id}/events:batch")
async def api_append_events(
    organization_id: str,
    run_id: str,
    body: EventBatchRequest,
    authorization: str | None = Header(default=None),
    x_run_capability: str | None = Header(default=None, alias="X-Run-Capability"),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    token = _capability_token(authorization, x_run_capability)
    if not idempotency_key:
        raise HTTPException(status_code=422, detail="Idempotency-Key is required")
    try:
        result = append_event_batch(
            db,
            organization_id=organization_id,
            run_id=run_id,
            token=token,
            events=body.events,
            batch_idempotency_key=idempotency_key,
        )
        run = db.scalar(select(Run).where(Run.id == run_id))
        result["workflow_signalled"] = await _signal_or_record(
            run, "events_received", result["accepted"]
        )
        return result
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TimeoutError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except EventSchemaError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except EventSequenceConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/organizations/{organization_id}/runs/{run_id}/complete")
async def api_complete_event_run(
    organization_id: str,
    run_id: str,
    authorization: str | None = Header(default=None),
    x_run_capability: str | None = Header(default=None, alias="X-Run-Capability"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    token = _capability_token(authorization, x_run_capability)
    try:
        result = complete_event_run(
            db, organization_id=organization_id, run_id=run_id, token=token
        )
        run = db.scalar(select(Run).where(Run.id == run_id))
        result["workflow_signalled"] = await _signal_or_record(run, "complete")
        return result
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TimeoutError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except EventSchemaError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except EventSequenceConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/organizations/{organization_id}/runs/{run_id}/cancel")
async def api_cancel_event_run(
    organization_id: str,
    run_id: str,
    authorization: str | None = Header(default=None),
    x_run_capability: str | None = Header(default=None, alias="X-Run-Capability"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    token = _capability_token(authorization, x_run_capability)
    try:
        result = cancel_event_run(
            db, organization_id=organization_id, run_id=run_id, token=token
        )
        run = db.scalar(select(Run).where(Run.id == run_id))
        result["workflow_signalled"] = await _signal_or_record(run, "cancel")
        return result
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TimeoutError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc


@router.post("/organizations/{organization_id}/suite-runs")
def api_suite_run(
    organization_id: str,
    body: CreateSuiteRunRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        if body.suite_revision_id or body.agent_version_id:
            if not body.suite_revision_id or not body.agent_version_id:
                raise HTTPException(
                    status_code=422,
                    detail="suite_revision_id and agent_version_id must be provided together",
                )
            return execute_persisted_suite(
                db,
                principal,
                suite_revision_id=body.suite_revision_id,
                agent_version_id=body.agent_version_id,
                policy_revision_id=body.policy_revision_id,
                behave_securely=body.behave_securely,
                durable=body.durable,
            )
        if not body.project_id or not body.agent_id or not body.scenario_keys:
            raise HTTPException(
                status_code=422,
                detail="project_id, agent_id, and scenario_keys are required for legacy suite runs",
            )
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
        if body.suite_revision_id or body.agent_version_id:
            if not body.suite_revision_id or not body.agent_version_id:
                raise HTTPException(
                    status_code=422,
                    detail="suite_revision_id and agent_version_id must be provided together",
                )
            revision = get_suite_revision(db, principal, body.suite_revision_id)
            project_id = revision.project_id
            scenario_keys = [
                str(item["scenario_key"]) for item in revision.scenario_snapshot
            ]
            suite = execute_persisted_suite(
                db,
                principal,
                suite_revision_id=body.suite_revision_id,
                agent_version_id=body.agent_version_id,
                policy_revision_id=body.policy_revision_id,
                behave_securely=body.behave_securely,
            )
        else:
            if not body.project_id or not body.agent_id or not body.scenario_keys:
                raise HTTPException(
                    status_code=422,
                    detail="project_id, agent_id, and scenario_keys are required for legacy gates",
                )
            project_id = body.project_id
            scenario_keys = body.scenario_keys
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
    policy_decision = None
    if body.policy_revision_id:
        revision = db.get(PolicyRevision, body.policy_revision_id)
        if (
            revision is None
            or revision.organization_id != organization_id
            or revision.project_id != project_id
        ):
            raise HTTPException(status_code=403, detail="policy revision not found in organization")
        exceptions = active_exceptions(db, principal, project_id)
        def _exception_matches(row: ApprovalException) -> bool:
            scope = row.scope or {}
            if row.finding_id is not None:
                return False
            expected = {
                "suite_revision_id": body.suite_revision_id,
                "agent_version_id": body.agent_version_id,
            }
            return all(
                not scope.get(key) or scope.get(key) == value
                for key, value in expected.items()
            )
        policy_decision = evaluate_release_policy(
            revision.rules,
            scenario_keys=scenario_keys,
            results=suite["results"],
            evidence_complete=all(bool(result.get("evidence_id")) for result in suite["results"]),
            has_active_exception=any(
                row.policy_revision_id == revision.id and _exception_matches(row)
                for row in exceptions
            ),
        )
        fail_release = not policy_decision.allowed
    effective_gate_result = GateResult.FAIL.value if fail_release else GateResult.PASS.value
    check_payload = build_check_run_payload(
        suite_name=body.suite_name,
        gate_result=effective_gate_result,
        failed_count=suite["failed_count"],
        run_ids=suite.get("run_ids") or [],
        evidence_uris=suite.get("evidence_uris") or [],
        head_sha=body.head_sha,
    )
    publish_result: dict[str, Any] = {"published": False, "skipped": True}
    installation = None
    installation_values: dict[str, Any] = {}
    if (
        os.environ.get("DEPLOYMENT_ENV", "local").lower() in {"beta", "production"}
        and body.publish
        and body.provider != "none"
        and not body.integration_installation_id
    ):
        raise HTTPException(
            status_code=422,
            detail="organization-scoped integration installation is required",
        )
    if body.integration_installation_id:
        try:
            installation, installation_values = installation_config(
                db, principal, body.integration_installation_id
            )
        except AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        if installation.provider != body.provider:
            raise HTTPException(
                status_code=422,
                detail="integration installation provider does not match request provider",
            )
        if installation.project_id and installation.project_id != project_id:
            raise HTTPException(
                status_code=403,
                detail="integration installation is scoped to a different project",
            )
    if body.publish and body.provider == "github":
        publish_result = publish_github_check_run(
            check_payload,
            owner=installation_values.get("owner"),
            repo=installation_values.get("repo"),
            token=installation_values.get("token"),
        )
    elif body.publish and body.provider == "gitlab":
        gl_payload = build_gitlab_status_payload(
            suite_name=body.suite_name,
            gate_result=effective_gate_result,
        )
        publish_result = publish_gitlab_commit_status(
            gl_payload,
            sha=body.head_sha,
            project_id=installation_values.get("project_id"),
            token=installation_values.get("token"),
            base_url=installation_values.get("base_url"),
        )
    audit_authz(
        db,
        principal=principal,
        action="release_gate.publish",
        resource_type="project",
        resource_id=project_id,
        allowed=not fail_release,
        detail={
            "provider": body.provider,
            "published": bool(publish_result.get("published")),
            "policy_revision_id": body.policy_revision_id,
        },
    )

    return {
        **suite,
        "fail_release": fail_release,
        "check_run": check_payload,
        "publish_result": publish_result,
        "policy_decision": None
        if policy_decision is None
        else {
            "allowed": policy_decision.allowed,
            "reasons": policy_decision.reasons,
            "metrics": policy_decision.metrics,
        },
    }


@router.post("/organizations/{organization_id}/integrations")
def api_create_integration(
    organization_id: str,
    body: CreateIntegrationRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        row = create_installation(
            db,
            principal,
            provider=body.provider,
            config=body.config,
            project_id=body.project_id,
        )
        db.flush()
        return {
            "id": row.id,
            "provider": row.provider,
            "project_id": row.project_id,
            "status": row.status,
        }
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/organizations/{organization_id}/projects/{project_id}/policies")
def api_create_policy_revision(
    organization_id: str,
    project_id: str,
    body: CreatePolicyRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        policy, revision = create_policy_revision(
            db,
            principal,
            project_id,
            name=body.name,
            rules=body.rules,
            policy_id=body.policy_id,
        )
        db.flush()
        return {
            "policy_id": policy.id,
            "policy_revision_id": revision.id,
            "revision": revision.revision,
            "rules": revision.rules,
        }
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/organizations/{organization_id}/exceptions")
def api_create_exception(
    organization_id: str,
    body: CreateExceptionRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        row = create_approval_exception(
            db,
            principal,
            project_id=body.project_id,
            policy_revision_id=body.policy_revision_id,
            finding_id=body.finding_id,
            scope=body.scope,
            reason=body.reason,
            expires_at=body.expires_at,
        )
        db.flush()
        return {
            "id": row.id,
            "status": row.status,
            "approver_sub": row.approver_sub,
            "expires_at": row.expires_at,
        }
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/organizations/{organization_id}/projects/{project_id}/exceptions")
def api_list_exceptions(
    organization_id: str,
    project_id: str,
    auth: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    principal = _principal(db, auth, organization_id)
    try:
        rows = active_exceptions(db, principal, project_id)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return {
        "exceptions": [
            {
                "id": row.id,
                "policy_revision_id": row.policy_revision_id,
                "finding_id": row.finding_id,
                "scope": row.scope,
                "reason": row.reason,
                "approver_sub": row.approver_sub,
                "expires_at": row.expires_at,
                "status": row.status,
            }
            for row in rows
        ]
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
        audit_authz(
            db,
            principal=principal,
            action="evidence.read",
            resource_type="run",
            resource_id=run_id,
            allowed=True,
        )
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
        "workflow_id": run.workflow_id,
        "execution_mode": run.execution_mode,
        "suite_revision_id": run.suite_revision_id,
        "suite_run_id": run.suite_run_id,
        "agent_version_id": run.agent_version_id,
        "artifact_snapshot": run.artifact_snapshot,
        "last_event_seq": run.last_event_seq,
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
                "fingerprint": f.fingerprint,
                "regression_state": f.regression_state,
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
            "signing_algorithm": evidence.signing_algorithm,
            "signing_key_id": evidence.signing_key_id,
            "expires_at": evidence.expires_at,
            "object_uri": evidence.object_uri,
            "manifest": evidence.manifest,
            "signature_valid": verify_signature(
                {**evidence.manifest, "signature": None} if evidence.manifest else {},
                (evidence.manifest or {}).get("signature"),
                public_key=(evidence.manifest.get("signing") or {}).get("public_key"),
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
        audit_authz(
            db,
            principal=principal,
            action="evidence.export",
            resource_type="run",
            resource_id=run_id,
            allowed=True,
        )
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
    if evidence.status in {"expired", "purged"} or evidence.purged_at is not None:
        raise HTTPException(status_code=410, detail="evidence is no longer retained")
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
                "fingerprint": f.fingerprint,
                "regression_state": f.regression_state,
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
