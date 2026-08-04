"""Database access for the API."""
from __future__ import annotations

import os
import pathlib

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

DSN = os.environ.get("SIPTRACE_DSN", "postgresql://siptrace:siptrace@db:5432/siptrace")

pool = ConnectionPool(DSN, min_size=1, max_size=8, open=False, kwargs={"row_factory": dict_row})


def rows(sql: str, params: tuple | list = ()) -> list[dict]:
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def row(sql: str, params: tuple | list = ()) -> dict | None:
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def execute(sql: str, params: tuple | list = ()) -> dict | None:
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        result = cur.fetchone() if cur.description else None
        conn.commit()
        return result


MIGRATIONS = pathlib.Path(__file__).parent.parent / "db" / "migrations"


def migrate() -> list[str]:
    """Apply any db/migrations/*.sql not yet recorded, in filename order.

    db/schema.sql is the baseline and only ever runs on an empty data directory
    (Postgres only executes /docker-entrypoint-initdb.d then). Without this,
    changing the schema of a running deployment means wiping it. Migrations are
    applied inside a transaction each, and recorded so they never run twice.
    """
    applied: list[str] = []
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS schema_migration ("
                    " filename TEXT PRIMARY KEY,"
                    " applied_at TIMESTAMPTZ NOT NULL DEFAULT now())")
        conn.commit()
        cur.execute("SELECT filename FROM schema_migration")
        done = {r["filename"] for r in cur.fetchall()}

    if not MIGRATIONS.is_dir():
        # Never fail silently here: a missing directory means the image was built
        # without db/, and every later query against a migrated column would 500.
        raise RuntimeError(f"migrations directory missing: {MIGRATIONS}")

    for path in sorted(MIGRATIONS.glob("*.sql")):
        if path.name in done:
            continue
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(path.read_text())
            cur.execute("INSERT INTO schema_migration (filename) VALUES (%s)",
                        (path.name,))
            conn.commit()
        applied.append(path.name)
    return applied


def resolve_citations(refs: list[str]) -> list[str]:
    """Return the subset of 'RFC#####section' refs that do NOT exist in the corpus."""
    import re

    bad: list[str] = []
    for ref in refs:
        m = re.match(r"RFC(\d+)#(.+)$", (ref or "").strip())
        if not m:
            bad.append(ref)
            continue
        hit = row("SELECT 1 AS ok FROM rfc_section WHERE rfc_number=%s AND section=%s",
                  (int(m.group(1)), m.group(2)))
        if not hit:
            bad.append(ref)
    return bad
