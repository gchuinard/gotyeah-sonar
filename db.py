"""Couche de persistance SQLite pour l'historique des scans de Sonar."""

from __future__ import annotations

import datetime
import json
import sqlite3
import uuid
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "data" / "scans.db"


def init_db() -> None:
    """Crée le dossier de données et la table `scans` si nécessaire."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                score INTEGER,
                grade TEXT,
                counts TEXT,
                total INTEGER,
                findings TEXT,
                created_at TEXT NOT NULL
            )
            """
        )


def save_scan(target: str, summary: dict, findings: list[dict]) -> str:
    """Persiste un scan et retourne son identifiant unique."""
    scan_id = uuid.uuid4().hex
    created_at = datetime.datetime.now().isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO scans
                (id, target, score, grade, counts, total, findings, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                target,
                summary.get("score"),
                summary.get("grade"),
                json.dumps(summary.get("counts", {})),
                summary.get("total"),
                json.dumps(findings),
                created_at,
            ),
        )
    return scan_id


def list_scans() -> list[dict]:
    """Retourne les 50 scans les plus récents (sans les findings)."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, target, score, grade, created_at
            FROM scans
            ORDER BY created_at DESC
            LIMIT 50
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan(scan_id: str) -> dict | None:
    """Retourne un scan complet (counts/findings désérialisés) ou None."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT id, target, score, grade, counts, total, findings, created_at
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "target": row["target"],
        "score": row["score"],
        "grade": row["grade"],
        "counts": json.loads(row["counts"]) if row["counts"] else {},
        "total": row["total"],
        "findings": json.loads(row["findings"]) if row["findings"] else [],
        "created_at": row["created_at"],
    }
