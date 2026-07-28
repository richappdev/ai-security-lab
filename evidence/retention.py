"""Evidence expiry and auditable purge operations."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from evidence.store import EvidenceStore
from persistence import AuthzAudit, Evidence, new_id, utcnow


def purge_expired_evidence(session: Session, *, limit: int = 100) -> dict[str, int]:
    now = datetime.now(timezone.utc)
    rows = list(
        session.scalars(
            select(Evidence)
            .where(
                Evidence.expires_at.is_not(None),
                Evidence.expires_at <= now,
                Evidence.purged_at.is_(None),
            )
            .limit(limit)
        )
    )
    objects_deleted = 0
    store = EvidenceStore()
    for row in rows:
        objects_deleted += store.delete_run(
            organization_id=row.organization_id,
            project_id=row.project_id,
            run_id=row.run_id,
        )
        row.status = "purged"
        row.purged_at = utcnow()
        session.add(
            AuthzAudit(
                id=new_id(),
                organization_id=row.organization_id,
                user_sub="system:retention",
                action="evidence.purge",
                resource_type="evidence",
                resource_id=row.id,
                allowed=True,
                detail={"run_id": row.run_id, "objects_deleted": objects_deleted},
            )
        )
    return {"evidence_purged": len(rows), "objects_deleted": objects_deleted}
