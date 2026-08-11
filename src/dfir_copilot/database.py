"""SQLite persistence for cases, evidence, findings, and custody records."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    investigator TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_number TEXT NOT NULL,
    original_name TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    source_type TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    UNIQUE(case_id, evidence_number)
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    artifact_ref TEXT NOT NULL UNIQUE,
    artifact_type TEXT NOT NULL,
    event_time TEXT NOT NULL,
    source TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    mitre_id TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    finding_ref TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    mitre_id TEXT NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 70,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS custody_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    event_time TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    event_time TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS copilot_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    citations_json TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    mode TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self.connect() as connection:
            cursor = connection.execute(sql, params)
            return int(cursor.lastrowid or 0)

    def executemany(self, sql: str, rows: list[tuple[Any, ...]]) -> None:
        if not rows:
            return
        with self.connect() as connection:
            connection.executemany(sql, rows)

    def fetch_one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(sql, params).fetchone()
            return dict(row) if row else None

    def fetch_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, params).fetchall()]

    def audit(self, case_id: int | None, action: str, details: str) -> None:
        self.execute(
            "INSERT INTO audit_log(case_id, action, details, event_time) VALUES (?, ?, ?, ?)",
            (case_id, action, details, utc_now()),
        )

    @staticmethod
    def json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

