"""Versioned control-plane API (/v1)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import AuthContext, get_auth_context, get_db
from domain import OrgRole
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
    require_role,
    resolve_principal,
)
from scenarios import list_scenario_keys
from scenarios.runner import execute_evaluation, execute_suite

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


class CreateSuiteRunRequest(BaseModel):
    project_id: str
    agent_id: str
    scenario_keys: list[str]
    behave_securely: bool = True


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
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


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
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return {
        "id": run.id,
        "status": run.status,
        "gate_result": run.gate_result,
        "scenario_key": run.scenario_key,
        "scenario_version": run.scenario_version,
        "findings": [
            {
                "id": f.id,
                "assertion_id": f.assertion_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
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
        },
    }
