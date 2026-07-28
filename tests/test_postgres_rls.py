"""PostgreSQL-only RLS integration tests.

CI sets POSTGRES_TEST_URL after applying Alembic migrations.
"""

from __future__ import annotations

import os
import unittest

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from persistence import Project, make_engine, new_id, utcnow
from persistence.repositories import create_organization


@unittest.skipUnless(os.environ.get("POSTGRES_TEST_URL"), "PostgreSQL test URL not configured")
class PostgresRlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = make_engine(os.environ["POSTGRES_TEST_URL"])
        cls.sessions = sessionmaker(bind=cls.engine, expire_on_commit=False)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.engine.dispose()

    def _organization(self, name: str) -> str:
        with self.sessions() as session:
            organization = create_organization(session, name, f"{name}-owner")
            session.commit()
            return organization.id

    def test_using_and_with_check_isolate_reads_and_writes(self):
        org_a = self._organization("RlsA")
        org_b = self._organization("RlsB")
        with self.sessions() as session:
            session.execute(
                text("SELECT set_config('app.organization_id', :oid, true)"),
                {"oid": org_a},
            )
            session.add(
                Project(
                    id=new_id(),
                    organization_id=org_a,
                    name="visible",
                    created_at=utcnow(),
                )
            )
            session.commit()
        with self.sessions() as session:
            session.execute(
                text("SELECT set_config('app.organization_id', :oid, true)"),
                {"oid": org_b},
            )
            self.assertEqual(list(session.scalars(select(Project))), [])
            session.add(
                Project(
                    id=new_id(),
                    organization_id=org_a,
                    name="forbidden",
                    created_at=utcnow(),
                )
            )
            with self.assertRaises(DBAPIError):
                session.commit()
