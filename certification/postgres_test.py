"""Apply migrations and run PostgreSQL-only certification tests inside Docker."""

from __future__ import annotations

import os
import sys
import unittest

from alembic import command
from alembic.config import Config


def main() -> None:
    database_url = os.environ.get("POSTGRES_TEST_URL") or os.environ.get("DATABASE_URL")
    if not database_url or not database_url.startswith(
        ("postgresql://", "postgresql+psycopg://")
    ):
        raise SystemExit("POSTGRES_TEST_URL must reference PostgreSQL")
    os.environ["DATABASE_URL"] = database_url
    os.environ["POSTGRES_TEST_URL"] = database_url

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")

    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_postgres_rls")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
