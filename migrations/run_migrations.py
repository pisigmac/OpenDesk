#!/usr/bin/env python3
"""Idempotent migration runner for Auth service.

Usage:
    cd Auth
    PYTHONPATH=src python3 migrations/run_migrations.py

Environment:
    AUTH_DATABASE_URL — target database (defaults to SQLite in /tmp)
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError, OperationalError

# Allow importing pisigma_auth when PYTHONPATH=src
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pisigma_auth.models import Base


def _split_sql(statements: str) -> list[str]:
    """Split SQL on semicolons, ignoring empty statements and line comments."""
    # Strip line comments
    cleaned = re.sub(r"--.*?\n", "\n", statements)
    parts = [p.strip() for p in cleaned.split(";")]
    return [p for p in parts if p]


def run_migrations() -> None:
    # The migration runner only needs the database URL. Bypass the full settings
    # object (which may require other env vars) and create the engine directly.
    database_url = os.environ.get("AUTH_DATABASE_URL")
    if not database_url:
        raise RuntimeError("AUTH_DATABASE_URL is required to run migrations")

    engine = create_engine(database_url)
    migrations_dir = Path(__file__).parent

    # Ensure base schema exists. Existing deployments using SQLAlchemy's create_all()
    # will already have all tables; new deployments need this before 0002 can run.
    Base.metadata.create_all(bind=engine)

    with engine.connect() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS _migrations ("
                "    name TEXT PRIMARY KEY,"
                "    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                ")"
            )
        )

        for sql_file in sorted(migrations_dir.glob("*.sql")):
            name = sql_file.name
            already_applied = conn.execute(
                text("SELECT 1 FROM _migrations WHERE name = :name"),
                {"name": name},
            ).scalar()
            if already_applied:
                print(f"Skipping already-applied migration: {name}")
                continue

            print(f"Applying migration: {name}")
            sql = sql_file.read_text(encoding="utf-8")
            for statement in _split_sql(sql):
                try:
                    conn.execute(text(statement))
                except (ProgrammingError, OperationalError) as exc:
                    msg = str(exc).lower()
                    # Idempotent guard: skip duplicate column / duplicate table errors
                    if "duplicate column name" in msg or "already exists" in msg:
                        print(f"  Skipping idempotent statement (already applied): {exc}")
                        continue
                    raise

            conn.execute(
                text("INSERT INTO _migrations (name) VALUES (:name)"),
                {"name": name},
            )
            print(f"Applied migration: {name}")

        conn.commit()


if __name__ == "__main__":
    run_migrations()
