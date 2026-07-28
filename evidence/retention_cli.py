"""Run one bounded evidence-retention purge batch."""

from __future__ import annotations

import json

from sqlalchemy import select

from persistence import Organization, session_scope
from evidence.retention import purge_expired_evidence


def main() -> None:
    with session_scope() as session:
        organization_ids = list(session.scalars(select(Organization.id)))
    total = {"evidence_purged": 0, "objects_deleted": 0}
    for organization_id in organization_ids:
        with session_scope(organization_id=organization_id) as session:
            result = purge_expired_evidence(session)
        for key in total:
            total[key] += result[key]
    print(json.dumps(total, sort_keys=True))


if __name__ == "__main__":
    main()
