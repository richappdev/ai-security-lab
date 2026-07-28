"""Private beta domain, immutable revisions, event ingestion, and RLS.

Revision ID: 0002_private_beta
Revises: 0001_product_core
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_private_beta"
down_revision = "0001_product_core"
branch_labels = None
depends_on = None


def _tenant_columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False, index=True),
        sa.Column("project_id", sa.String(36), nullable=False, index=True),
    ]


def upgrade() -> None:
    op.create_table(
        "project_memberships",
        *_tenant_columns(),
        sa.Column("user_sub", sa.String(200), nullable=False, index=True),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.UniqueConstraint("project_id", "user_sub", name="uq_project_membership"),
    )
    op.create_table(
        "agent_versions",
        *_tenant_columns(),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("artifact_snapshot", sa.JSON(), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("agent_id", "version", name="uq_agent_version"),
    )
    op.create_table(
        "suite_revisions",
        *_tenant_columns(),
        sa.Column("suite_id", sa.String(36), sa.ForeignKey("suites.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("scenario_snapshot", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("suite_id", "revision", name="uq_suite_revision"),
    )
    op.create_table(
        "policies",
        *_tenant_columns(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
    )
    op.create_table(
        "policy_revisions",
        *_tenant_columns(),
        sa.Column("policy_id", sa.String(36), sa.ForeignKey("policies.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("rules", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("policy_id", "revision", name="uq_policy_revision"),
    )
    op.create_table(
        "suite_runs",
        *_tenant_columns(),
        sa.Column("suite_revision_id", sa.String(36), sa.ForeignKey("suite_revisions.id"), nullable=False),
        sa.Column("agent_version_id", sa.String(36), sa.ForeignKey("agent_versions.id"), nullable=False),
        sa.Column("policy_revision_id", sa.String(36), sa.ForeignKey("policy_revisions.id")),
        sa.Column("workflow_id", sa.String(200)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("gate_result", sa.String(16)),
        sa.Column("score", sa.Integer()),
        sa.Column("comparison", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "approval_exceptions",
        *_tenant_columns(),
        sa.Column("policy_revision_id", sa.String(36), sa.ForeignKey("policy_revisions.id"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id")),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("approver_sub", sa.String(200), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "worker_capabilities",
        *_tenant_columns(),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("token_digest", sa.String(128), nullable=False, unique=True),
        sa.Column("claims", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "integration_installations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False, index=True),
        sa.Column("project_id", sa.String(36), index=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("encrypted_config", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "finding_transitions",
        *_tenant_columns(),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("from_status", sa.String(32), nullable=False),
        sa.Column("to_status", sa.String(32), nullable=False),
        sa.Column("actor_sub", sa.String(200), nullable=False),
        sa.Column("assignee", sa.String(200)),
        sa.Column("note", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    run_columns = [
        sa.Column("suite_revision_id", sa.String(36), nullable=True),
        sa.Column("suite_run_id", sa.String(36), nullable=True),
        sa.Column("agent_version_id", sa.String(36), nullable=True),
        sa.Column("execution_mode", sa.String(32), nullable=False, server_default="synthetic_local"),
        sa.Column("workflow_id", sa.String(200), nullable=True),
        sa.Column("artifact_snapshot", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("last_event_seq", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ingest_completed_at", sa.DateTime(timezone=True), nullable=True),
    ]
    for column in run_columns:
        op.add_column("runs", column)
    op.create_unique_constraint(
        "uq_run_idempotency", "runs", ["organization_id", "idempotency_key"]
    )
    op.add_column("run_events", sa.Column("idempotency_key", sa.String(120)))
    op.create_unique_constraint("uq_run_event_seq", "run_events", ["run_id", "seq"])
    op.create_unique_constraint(
        "uq_run_event_idempotency", "run_events", ["run_id", "idempotency_key"]
    )
    op.add_column("findings", sa.Column("fingerprint", sa.String(128)))
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.add_column(
        "findings", sa.Column("regression_state", sa.String(32), nullable=False, server_default="new")
    )
    op.add_column(
        "evidence",
        sa.Column("signing_algorithm", sa.String(32), nullable=False, server_default="ed25519"),
    )
    op.add_column("evidence", sa.Column("signing_key_id", sa.String(120)))
    op.add_column("evidence", sa.Column("expires_at", sa.DateTime(timezone=True)))
    op.add_column("evidence", sa.Column("purged_at", sa.DateTime(timezone=True)))
    op.create_index("ix_evidence_expiry", "evidence", ["expires_at", "purged_at"])

    # Existing mutable records become revision 1 without changing their IDs.
    op.execute(
        """
        INSERT INTO agent_versions
          (id, organization_id, project_id, agent_id, version, artifact_snapshot, created_at)
        SELECT id, organization_id, project_id, id, version,
               json_build_object('allowed_tools', allowed_tools), created_at
        FROM agents
        """
    )
    op.execute(
        """
        INSERT INTO suite_revisions
          (id, organization_id, project_id, suite_id, revision, scenario_snapshot, created_at)
        SELECT id, organization_id, project_id, id, 1, scenario_keys, created_at
        FROM suites
        """
    )
    op.execute("UPDATE runs SET agent_version_id = agent_id")
    op.execute("UPDATE runs SET suite_revision_id = suite_id WHERE suite_id IS NOT NULL")
    op.create_foreign_key(
        "fk_runs_agent_version", "runs", "agent_versions", ["agent_version_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_runs_suite_revision", "runs", "suite_revisions", ["suite_revision_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_runs_suite_run", "runs", "suite_runs", ["suite_run_id"], ["id"]
    )

    if op.get_bind().dialect.name == "postgresql":
        tenant_tables = [
            "memberships", "project_memberships", "projects", "agents", "agent_versions",
            "scenarios", "suites", "suite_revisions", "suite_runs", "runs", "run_events",
            "findings", "finding_transitions", "evidence", "policies", "policy_revisions",
            "approval_exceptions", "worker_capabilities", "integration_installations",
            "authz_audit",
        ]
        for table in tenant_tables:
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
            nullable_global = table == "scenarios"
            predicate = (
                "organization_id IS NULL OR "
                if nullable_global
                else ""
            ) + "organization_id = NULLIF(current_setting('app.organization_id', true), '')"
            op.execute(
                f"CREATE POLICY tenant_isolation ON {table} "
                f"USING ({predicate}) WITH CHECK ({predicate})"
            )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in (
            "memberships", "projects", "agents", "scenarios", "suites", "runs",
            "run_events", "findings", "evidence", "authz_audit",
        ):
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
    for constraint, table in (
        ("uq_run_event_idempotency", "run_events"),
        ("uq_run_event_seq", "run_events"),
        ("uq_run_idempotency", "runs"),
    ):
        op.drop_constraint(constraint, table, type_="unique")
    op.drop_index("ix_evidence_expiry", table_name="evidence")
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    for constraint in (
        "fk_runs_suite_run",
        "fk_runs_suite_revision",
        "fk_runs_agent_version",
    ):
        op.drop_constraint(constraint, "runs", type_="foreignkey")
    for column in ("purged_at", "expires_at", "signing_key_id", "signing_algorithm"):
        op.drop_column("evidence", column)
    for column in ("regression_state", "fingerprint"):
        op.drop_column("findings", column)
    op.drop_column("run_events", "idempotency_key")
    for column in (
        "ingest_completed_at", "last_event_seq", "artifact_snapshot", "workflow_id",
        "execution_mode", "agent_version_id", "suite_run_id", "suite_revision_id",
    ):
        op.drop_column("runs", column)
    for table in (
        "finding_transitions", "integration_installations", "worker_capabilities",
        "approval_exceptions", "suite_runs", "policy_revisions", "policies",
        "suite_revisions", "agent_versions", "project_memberships",
    ):
        op.drop_table(table)
