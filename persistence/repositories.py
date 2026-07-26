"""Tenant-aware repositories and authorization helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from domain import GateResult, OrgRole, RunStatus
from persistence import (
    Agent,
    AuthzAudit,
    Evidence,
    Finding,
    Membership,
    Organization,
    Project,
    Run,
    RunEvent,
    Suite,
    new_id,
    utcnow,
)


class AuthorizationError(PermissionError):
    """Raised when a caller cannot access a tenant resource."""


@dataclass
class Principal:
    user_sub: str
    organization_id: str
    role: str

    def can_write(self) -> bool:
        return self.role in {OrgRole.OWNER.value, OrgRole.OPERATOR.value}

    def can_admin(self) -> bool:
        return self.role == OrgRole.OWNER.value


def audit_authz(
    session: Session,
    *,
    principal: Principal | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    allowed: bool,
    detail: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuthzAudit(
            id=new_id(),
            organization_id=principal.organization_id if principal else None,
            user_sub=principal.user_sub if principal else "anonymous",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            allowed=allowed,
            detail=detail or {},
            created_at=utcnow(),
        )
    )


def require_role(principal: Principal, *, write: bool = False, admin: bool = False) -> None:
    if admin and not principal.can_admin():
        raise AuthorizationError("owner role required")
    if write and not principal.can_write():
        raise AuthorizationError("operator or owner role required")


def create_organization(session: Session, name: str, owner_sub: str) -> Organization:
    org = Organization(id=new_id(), name=name)
    session.add(org)
    session.flush()
    session.add(
        Membership(
            id=new_id(),
            organization_id=org.id,
            user_sub=owner_sub,
            role=OrgRole.OWNER.value,
        )
    )
    return org


def add_membership(
    session: Session,
    organization_id: str,
    user_sub: str,
    role: str = OrgRole.VIEWER.value,
) -> Membership:
    m = Membership(
        id=new_id(),
        organization_id=organization_id,
        user_sub=user_sub,
        role=role,
    )
    session.add(m)
    return m


def resolve_principal(session: Session, user_sub: str, organization_id: str) -> Principal:
    row = session.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_sub == user_sub,
        )
    )
    if row is None:
        raise AuthorizationError("not a member of organization")
    return Principal(user_sub=user_sub, organization_id=organization_id, role=row.role)


def create_project(session: Session, principal: Principal, name: str) -> Project:
    require_role(principal, write=True)
    project = Project(
        id=new_id(),
        organization_id=principal.organization_id,
        name=name,
    )
    session.add(project)
    audit_authz(
        session,
        principal=principal,
        action="project.create",
        resource_type="project",
        resource_id=project.id,
        allowed=True,
    )
    return project


def get_project(session: Session, principal: Principal, project_id: str) -> Project:
    project = session.get(Project, project_id)
    if project is None or project.organization_id != principal.organization_id:
        audit_authz(
            session,
            principal=principal,
            action="project.read",
            resource_type="project",
            resource_id=project_id,
            allowed=False,
        )
        raise AuthorizationError("project not found in organization")
    return project


def create_agent(
    session: Session,
    principal: Principal,
    project_id: str,
    name: str,
    allowed_tools: list[str] | None = None,
    version: str = "1.0.0",
) -> Agent:
    project = get_project(session, principal, project_id)
    require_role(principal, write=True)
    agent = Agent(
        id=new_id(),
        organization_id=project.organization_id,
        project_id=project.id,
        name=name,
        version=version,
        allowed_tools=list(allowed_tools or []),
    )
    session.add(agent)
    return agent


def get_agent(session: Session, principal: Principal, agent_id: str) -> Agent:
    agent = session.get(Agent, agent_id)
    if agent is None or agent.organization_id != principal.organization_id:
        audit_authz(
            session,
            principal=principal,
            action="agent.read",
            resource_type="agent",
            resource_id=agent_id,
            allowed=False,
        )
        raise AuthorizationError("agent not found in organization")
    return agent


def create_suite(
    session: Session,
    principal: Principal,
    project_id: str,
    name: str,
    scenario_keys: list[str],
) -> Suite:
    project = get_project(session, principal, project_id)
    require_role(principal, write=True)
    suite = Suite(
        id=new_id(),
        organization_id=project.organization_id,
        project_id=project.id,
        name=name,
        scenario_keys=list(scenario_keys),
    )
    session.add(suite)
    return suite


def find_run_by_idempotency(
    session: Session, organization_id: str, idempotency_key: str
) -> Run | None:
    return session.scalar(
        select(Run).where(
            Run.organization_id == organization_id,
            Run.idempotency_key == idempotency_key,
        )
    )


def create_run(
    session: Session,
    principal: Principal,
    *,
    project_id: str,
    agent_id: str,
    scenario_key: str,
    scenario_version: str,
    suite_id: str | None = None,
    idempotency_key: str | None = None,
    deadline_at: datetime | None = None,
) -> Run:
    require_role(principal, write=True)
    get_project(session, principal, project_id)
    get_agent(session, principal, agent_id)
    if idempotency_key:
        existing = find_run_by_idempotency(session, principal.organization_id, idempotency_key)
        if existing is not None:
            return existing
    run = Run(
        id=new_id(),
        organization_id=principal.organization_id,
        project_id=project_id,
        agent_id=agent_id,
        suite_id=suite_id,
        scenario_key=scenario_key,
        scenario_version=scenario_version,
        status=RunStatus.QUEUED.value,
        idempotency_key=idempotency_key,
        deadline_at=deadline_at,
    )
    session.add(run)
    audit_authz(
        session,
        principal=principal,
        action="run.create",
        resource_type="run",
        resource_id=run.id,
        allowed=True,
    )
    return run


def get_run(session: Session, principal: Principal, run_id: str) -> Run:
    run = session.get(Run, run_id)
    if run is None or run.organization_id != principal.organization_id:
        audit_authz(
            session,
            principal=principal,
            action="run.read",
            resource_type="run",
            resource_id=run_id,
            allowed=False,
        )
        raise AuthorizationError("run not found in organization")
    return run


def list_findings_for_run(session: Session, principal: Principal, run_id: str) -> list[Finding]:
    get_run(session, principal, run_id)
    return list(
        session.scalars(
            select(Finding).where(
                Finding.run_id == run_id,
                Finding.organization_id == principal.organization_id,
            )
        )
    )


def get_evidence_for_run(session: Session, principal: Principal, run_id: str) -> Evidence | None:
    get_run(session, principal, run_id)
    return session.scalar(
        select(Evidence).where(
            Evidence.run_id == run_id,
            Evidence.organization_id == principal.organization_id,
        )
    )


def get_finding(session: Session, principal: Principal, finding_id: str) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None or finding.organization_id != principal.organization_id:
        audit_authz(
            session,
            principal=principal,
            action="finding.read",
            resource_type="finding",
            resource_id=finding_id,
            allowed=False,
        )
        raise AuthorizationError("finding not found in organization")
    return finding


def update_finding_status(
    session: Session,
    principal: Principal,
    finding_id: str,
    *,
    status: str,
    assignee: str | None = None,
    note: str | None = None,
) -> Finding:
    from domain import FindingStatus

    allowed = {s.value for s in FindingStatus}
    if status not in allowed:
        raise ValueError(f"invalid finding status: {status}")
    require_role(principal, write=True)
    finding = get_finding(session, principal, finding_id)
    finding.status = status
    detail = dict(finding.detail or {})
    if assignee is not None:
        detail["assignee"] = assignee
    if note is not None:
        detail["note"] = note
    detail["updated_by"] = principal.user_sub
    finding.detail = detail
    audit_authz(
        session,
        principal=principal,
        action="finding.update",
        resource_type="finding",
        resource_id=finding.id,
        allowed=True,
        detail={"status": status},
    )
    return finding


def list_project_findings(
    session: Session,
    principal: Principal,
    project_id: str,
    *,
    status: str | None = None,
) -> list[Finding]:
    get_project(session, principal, project_id)
    stmt = select(Finding).where(
        Finding.project_id == project_id,
        Finding.organization_id == principal.organization_id,
    )
    if status:
        stmt = stmt.where(Finding.status == status)
    return list(session.scalars(stmt))


def persist_run_result(
    session: Session,
    *,
    run: Run,
    events: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    gate_result: GateResult,
    evidence_manifest: dict[str, Any],
    content_sha256: str,
    object_uri: str | None = None,
) -> Evidence:
    run.status = RunStatus.COMPLETED.value
    run.gate_result = gate_result.value
    run.completed_at = utcnow()
    for idx, event in enumerate(events, start=1):
        session.add(
            RunEvent(
                id=new_id(),
                organization_id=run.organization_id,
                project_id=run.project_id,
                run_id=run.id,
                seq=idx,
                event_type=event.get("type", "unknown"),
                payload=event,
            )
        )
    for finding in findings:
        session.add(
            Finding(
                id=new_id(),
                organization_id=run.organization_id,
                project_id=run.project_id,
                run_id=run.id,
                assertion_id=finding["assertion_id"],
                title=finding["title"],
                severity=finding.get("severity", "high"),
                detail=finding.get("detail", {}),
            )
        )
    evidence = Evidence(
        id=new_id(),
        organization_id=run.organization_id,
        project_id=run.project_id,
        run_id=run.id,
        status="sealed",
        result=gate_result.value,
        manifest=evidence_manifest,
        object_uri=object_uri,
        content_sha256=content_sha256,
    )
    session.add(evidence)
    return evidence
