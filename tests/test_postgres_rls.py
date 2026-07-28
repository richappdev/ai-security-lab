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
        cls.admin_engine = make_engine(os.environ["POSTGRES_TEST_URL"])
        role = "aisec_rls_test"
        password = "aisec-rls-test-password"
        with cls.admin_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    DO $$
                    BEGIN
                      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisec_rls_test') THEN
                        CREATE ROLE aisec_rls_test LOGIN PASSWORD 'aisec-rls-test-password'
                          NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
                      END IF;
                    END
                    $$;
                    """
                )
            )
            connection.execute(text(f"GRANT CONNECT ON DATABASE {connection.dialect.identifier_preparer.quote(connection.engine.url.database)} TO {role}"))
            connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
            connection.execute(
                text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}")
            )
            connection.execute(
                text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}")
            )
        app_url = cls.admin_engine.url.set(username=role, password=password)
        cls.engine = make_engine(app_url.render_as_string(hide_password=False))
        cls.sessions = sessionmaker(bind=cls.engine, expire_on_commit=False)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.engine.dispose()
        cls.admin_engine.dispose()

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

    def test_every_tenant_table_forces_bidirectional_rls(self):
        expected = {
            "memberships",
            "project_memberships",
            "projects",
            "agents",
            "agent_versions",
            "scenarios",
            "suites",
            "suite_revisions",
            "suite_runs",
            "runs",
            "run_events",
            "findings",
            "finding_transitions",
            "evidence",
            "policies",
            "policy_revisions",
            "approval_exceptions",
            "worker_capabilities",
            "integration_installations",
            "authz_audit",
        }
        with self.admin_engine.connect() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                           bool_or(p.polqual IS NOT NULL) AS has_using,
                           bool_or(p.polwithcheck IS NOT NULL) AS has_with_check
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    LEFT JOIN pg_policy p ON p.polrelid = c.oid
                    WHERE n.nspname = current_schema()
                      AND c.relname = ANY(:tables)
                    GROUP BY c.relname, c.relrowsecurity, c.relforcerowsecurity
                    """
                ),
                {"tables": list(expected)},
            ).mappings()
            actual = {row["relname"]: row for row in rows}
        self.assertEqual(set(actual), expected)
        for table, row in actual.items():
            with self.subTest(table=table):
                self.assertTrue(row["relrowsecurity"])
                self.assertTrue(row["relforcerowsecurity"])
                self.assertTrue(row["has_using"])
                self.assertTrue(row["has_with_check"])
