"""Tenant-aware repositories and authorization helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from domain import GateResult, OrgRole, RunStatus
from persistence import (
    Agent,
    AgentVersion,
    ApprovalException,
    AuthzAudit,
    Evidence,
    Finding,
    FindingTransition,
    Membership,
    Organization,
    Policy,
    PolicyRevision,
    Project,
    ProjectMembership,
    Run,
    RunEvent,
    Suite,
    SuiteRevision,
    WorkerCapability,
    new_id,
    utcnow,
)
from workers.capability_tokens import (
    CapabilityTokenError,
    issue_capability_token,
    verify_capability_token,
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


def project_role(
    session: Session,
    principal: Principal,
    project_id: str,
) -> str:
    override = session.scalar(
        select(ProjectMembership).where(
            ProjectMembership.organization_id == principal.organization_id,
            ProjectMembership.project_id == project_id,
            ProjectMembership.user_sub == principal.user_sub,
        )
    )
    return override.role if override else principal.role


def require_project_role(
    session: Session,
    principal: Principal,
    project_id: str,
    *,
    write: bool = False,
    admin: bool = False,
) -> None:
    scoped = Principal(
        user_sub=principal.user_sub,
        organization_id=principal.organization_id,
        role=project_role(session, principal, project_id),
    )
    require_role(scoped, write=write, admin=admin)


def create_organization(session: Session, name: str, owner_sub: str) -> Organization:
    org = Organization(id=new_id(), name=name)
    session.add(org)
    session.flush()
    if str(session.get_bind().url).startswith("postgresql"):
        session.execute(
            text("SELECT set_config('app.organization_id', :oid, true)"),
            {"oid": org.id},
        )
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
        session.add(
            AuthzAudit(
                id=new_id(),
                organization_id=organization_id,
                user_sub=user_sub,
                action="membership.resolve",
                resource_type="organization",
                resource_id=organization_id,
                allowed=False,
                detail={"reason": "not a member"},
            )
        )
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
    require_project_role(session, principal, project_id, write=True)
    agent = Agent(
        id=new_id(),
        organization_id=project.organization_id,
        project_id=project.id,
        name=name,
        version=version,
        allowed_tools=list(allowed_tools or []),
    )
    session.add(agent)
    session.flush()
    session.add(
        AgentVersion(
            id=new_id(),
            organization_id=project.organization_id,
            project_id=project.id,
            agent_id=agent.id,
            version=version,
            artifact_snapshot={"allowed_tools": list(allowed_tools or [])},
        )
    )
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
    require_project_role(session, principal, project_id, write=True)
    suite = Suite(
        id=new_id(),
        organization_id=project.organization_id,
        project_id=project.id,
        name=name,
        scenario_keys=list(scenario_keys),
    )
    session.add(suite)
    session.flush()
    session.add(
        SuiteRevision(
            id=new_id(),
            organization_id=project.organization_id,
            project_id=project.id,
            suite_id=suite.id,
            revision=1,
            scenario_snapshot=[
                {"scenario_key": key, "scenario_version": "1.0.0"} for key in scenario_keys
            ],
        )
    )
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
    get_project(session, principal, project_id)
    require_project_role(session, principal, project_id, write=True)
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
    finding = get_finding(session, principal, finding_id)
    require_project_role(session, principal, finding.project_id, write=True)
    previous_status = finding.status
    finding.status = status
    detail = dict(finding.detail or {})
    if assignee is not None:
        detail["assignee"] = assignee
    if note is not None:
        detail["note"] = note
    detail["updated_by"] = principal.user_sub
    finding.detail = detail
    session.add(
        FindingTransition(
            id=new_id(),
            organization_id=finding.organization_id,
            project_id=finding.project_id,
            finding_id=finding.id,
            from_status=previous_status,
            to_status=status,
            actor_sub=principal.user_sub,
            assignee=assignee,
            note=note,
        )
    )
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
    persist_events: bool = True,
) -> Evidence:
    run.status = RunStatus.COMPLETED.value
    run.gate_result = gate_result.value
    run.completed_at = utcnow()
    if persist_events:
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
        signing_algorithm=(evidence_manifest.get("signing") or {}).get(
            "algorithm", "hmac-sha256"
        ),
        signing_key_id=(evidence_manifest.get("signing") or {}).get("key_id"),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    session.add(evidence)
    return evidence


def get_agent_version(
    session: Session,
    principal: Principal,
    agent_version_id: str,
) -> AgentVersion:
    row = session.get(AgentVersion, agent_version_id)
    if row is None or row.organization_id != principal.organization_id:
        audit_authz(
            session,
            principal=principal,
            action="agent_version.read",
            resource_type="agent_version",
            resource_id=agent_version_id,
            allowed=False,
        )
        raise AuthorizationError("agent version not found in organization")
    return row


def get_suite_revision(
    session: Session,
    principal: Principal,
    suite_revision_id: str,
) -> SuiteRevision:
    row = session.get(SuiteRevision, suite_revision_id)
    if row is None or row.organization_id != principal.organization_id:
        audit_authz(
            session,
            principal=principal,
            action="suite_revision.read",
            resource_type="suite_revision",
            resource_id=suite_revision_id,
            allowed=False,
        )
        raise AuthorizationError("suite revision not found in organization")
    return row


def create_agent_version(
    session: Session,
    principal: Principal,
    agent_id: str,
    *,
    version: str,
    artifact_snapshot: dict[str, Any],
) -> AgentVersion:
    agent = get_agent(session, principal, agent_id)
    require_project_role(session, principal, agent.project_id, write=True)
    row = AgentVersion(
        id=new_id(),
        organization_id=principal.organization_id,
        project_id=agent.project_id,
        agent_id=agent.id,
        version=version,
        artifact_snapshot=artifact_snapshot,
    )
    session.add(row)
    return row


def create_suite_revision(
    session: Session,
    principal: Principal,
    suite_id: str,
    scenario_snapshot: list[dict[str, Any]],
) -> SuiteRevision:
    suite = session.get(Suite, suite_id)
    if suite is None or suite.organization_id != principal.organization_id:
        raise AuthorizationError("suite not found in organization")
    require_project_role(session, principal, suite.project_id, write=True)
    latest = session.scalar(
        select(SuiteRevision)
        .where(SuiteRevision.suite_id == suite_id)
        .order_by(SuiteRevision.revision.desc())
    )
    row = SuiteRevision(
        id=new_id(),
        organization_id=suite.organization_id,
        project_id=suite.project_id,
        suite_id=suite.id,
        revision=(latest.revision + 1) if latest else 1,
        scenario_snapshot=scenario_snapshot,
    )
    session.add(row)
    return row


def add_project_membership(
    session: Session,
    principal: Principal,
    project_id: str,
    *,
    user_sub: str,
    role: str,
) -> ProjectMembership:
    require_role(principal, admin=True)
    project = get_project(session, principal, project_id)
    row = ProjectMembership(
        id=new_id(),
        organization_id=project.organization_id,
        project_id=project.id,
        user_sub=user_sub,
        role=role,
    )
    session.add(row)
    return row


def create_policy_revision(
    session: Session,
    principal: Principal,
    project_id: str,
    *,
    name: str,
    rules: dict[str, Any],
    policy_id: str | None = None,
) -> tuple[Policy, PolicyRevision]:
    get_project(session, principal, project_id)
    require_project_role(session, principal, project_id, write=True)
    policy = session.get(Policy, policy_id) if policy_id else None
    if policy is None:
        policy = Policy(
            id=new_id(),
            organization_id=principal.organization_id,
            project_id=project_id,
            name=name,
        )
        session.add(policy)
        session.flush()
        revision_number = 1
    else:
        if (
            policy.organization_id != principal.organization_id
            or policy.project_id != project_id
        ):
            raise AuthorizationError("policy not found in organization")
        latest = session.scalar(
            select(PolicyRevision)
            .where(PolicyRevision.policy_id == policy.id)
            .order_by(PolicyRevision.revision.desc())
        )
        revision_number = (latest.revision + 1) if latest else 1
    revision = PolicyRevision(
        id=new_id(),
        organization_id=principal.organization_id,
        project_id=project_id,
        policy_id=policy.id,
        revision=revision_number,
        rules=rules,
    )
    session.add(revision)
    audit_authz(
        session,
        principal=principal,
        action="policy.revise",
        resource_type="policy",
        resource_id=policy.id,
        allowed=True,
        detail={"revision": revision_number},
    )
    return policy, revision


def create_approval_exception(
    session: Session,
    principal: Principal,
    *,
    project_id: str,
    policy_revision_id: str,
    finding_id: str | None,
    scope: dict[str, Any],
    reason: str,
    expires_at: datetime,
) -> ApprovalException:
    get_project(session, principal, project_id)
    require_project_role(session, principal, project_id, admin=True)
    policy_revision = session.get(PolicyRevision, policy_revision_id)
    if (
        policy_revision is None
        or policy_revision.organization_id != principal.organization_id
        or policy_revision.project_id != project_id
    ):
        raise AuthorizationError("policy revision not found in project")
    if finding_id:
        finding = get_finding(session, principal, finding_id)
        if finding.project_id != project_id:
            raise AuthorizationError("finding not found in project")
    if expires_at <= datetime.now(timezone.utc):
        raise ValueError("exception expiry must be in the future")
    row = ApprovalException(
        id=new_id(),
        organization_id=principal.organization_id,
        project_id=project_id,
        policy_revision_id=policy_revision_id,
        finding_id=finding_id,
        scope=scope,
        reason=reason,
        approver_sub=principal.user_sub,
        expires_at=expires_at,
    )
    session.add(row)
    audit_authz(
        session,
        principal=principal,
        action="exception.approve",
        resource_type="approval_exception",
        resource_id=row.id,
        allowed=True,
        detail={"expires_at": expires_at.isoformat(), "reason": reason},
    )
    return row


def active_exceptions(
    session: Session,
    principal: Principal,
    project_id: str,
) -> list[ApprovalException]:
    now = datetime.now(timezone.utc)
    rows = list(
        session.scalars(
            select(ApprovalException).where(
                ApprovalException.organization_id == principal.organization_id,
                ApprovalException.project_id == project_id,
                ApprovalException.status == "active",
            )
        )
    )
    for row in rows:
        expires_at = row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            row.status = "expired"
    return [row for row in rows if row.status == "active"]


def issue_worker_capability(
    session: Session,
    principal: Principal,
    *,
    project_id: str,
    run_id: str,
    operations: list[str],
    ttl_seconds: int = 600,
    limits: dict[str, Any] | None = None,
) -> tuple[WorkerCapability, str]:
    run = get_run(session, principal, run_id)
    if run.project_id != project_id:
        raise AuthorizationError("run not found in project")
    require_project_role(session, principal, project_id, write=True)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    claims = {
        "iss": "ai-security-control-plane",
        "aud": "ai-security-evaluation-worker",
        "jti": new_id(),
        "organization_id": principal.organization_id,
        "project_id": project_id,
        "run_id": run_id,
        "operations": operations,
        "limits": limits or {},
        "network_policy": "deny_public",
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = issue_capability_token(claims)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = WorkerCapability(
        id=new_id(),
        organization_id=principal.organization_id,
        project_id=project_id,
        run_id=run_id,
        token_digest=digest,
        claims=claims,
        expires_at=expires_at,
    )
    session.add(row)
    audit_authz(
        session,
        principal=principal,
        action="capability.issue",
        resource_type="run",
        resource_id=run_id,
        allowed=True,
        detail={"expires_at": expires_at.isoformat(), "operations": operations},
    )
    return row, token


def validate_worker_capability(
    session: Session,
    *,
    token: str,
    organization_id: str,
    run_id: str,
    operation: str,
) -> WorkerCapability:
    try:
        signed_claims = verify_capability_token(token)
    except CapabilityTokenError as exc:
        raise AuthorizationError(str(exc)) from exc
    if (
        signed_claims.get("organization_id") != organization_id
        or signed_claims.get("run_id") != run_id
    ):
        raise AuthorizationError("capability does not grant access to this run")
    if operation not in signed_claims.get("operations", []):
        raise AuthorizationError("capability operation not permitted")
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = session.scalar(
        select(WorkerCapability).where(WorkerCapability.token_digest == digest)
    )
    if row is None or row.organization_id != organization_id or row.run_id != run_id:
        raise AuthorizationError("capability does not grant access to this run")
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if row.revoked_at is not None or expires_at <= datetime.now(timezone.utc):
        raise TimeoutError("capability expired")
    if operation not in (row.claims or {}).get("operations", []):
        raise AuthorizationError("capability operation not permitted")
    if signed_claims != row.claims:
        raise AuthorizationError("capability claims do not match durable record")
    return row
