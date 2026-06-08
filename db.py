"""Couche de persistance SQLite pour l'historique des scans de Sonar.

Depuis l'arrivée de l'auth, chaque scan est rattaché à l'utilisateur qui l'a lancé
(`user_id`). Les tables d'auth (users/sessions/tokens) vivent dans la même base,
mais sont gérées par `auth.py`.
"""

from __future__ import annotations

import datetime
import json
import sqlite3
import uuid
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "data" / "scans.db"


def init_db() -> None:
    """Crée le dossier de données et la table `scans` ; migre les bases existantes."""
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
                created_at TEXT NOT NULL,
                user_id TEXT,
                status TEXT
            )
            """
        )
        # Migration douce : une base d'avant l'auth n'a pas la colonne user_id.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "user_id" not in cols:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id TEXT")
        # Migration douce : le scan asynchrone (MCP) introduit un statut. Les lignes
        # d'avant sont des scans terminés -> NULL est traité comme 'done' à la lecture.
        if "status" not in cols:
            conn.execute("ALTER TABLE scans ADD COLUMN status TEXT")
        # Réglages applicatifs modifiables à chaud (clé/valeur), ex. toggle admin.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )


def get_setting(key: str, default: str | None = None) -> str | None:
    """Lit un réglage applicatif (None/`default` si absent). Robuste si la table manque."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default
    except sqlite3.Error:
        return default


def set_setting(key: str, value: str) -> None:
    """Écrit (upsert) un réglage applicatif."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def save_scan(target: str, summary: dict, findings: list[dict], user_id: str | None = None) -> str:
    """Persiste un scan TERMINÉ (rattaché à `user_id` si fourni) ; retourne son id."""
    scan_id = uuid.uuid4().hex
    created_at = datetime.datetime.now().isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO scans
                (id, target, score, grade, counts, total, findings, created_at, user_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'done')
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
                user_id,
            ),
        )
    return scan_id


def create_running_scan(target: str, user_id: str | None = None) -> str:
    """Crée une ligne de scan EN COURS (statut 'running') et retourne son id.

    Sert au scan asynchrone (déclenché par le MCP) : l'id existe immédiatement pour
    que l'appelant puisse récupérer le rapport plus tard, pendant que le scan tourne
    en tâche de fond. `finalize_scan`/`fail_scan` viennent compléter la ligne ensuite.
    """
    scan_id = uuid.uuid4().hex
    created_at = datetime.datetime.now().isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO scans
                (id, target, score, grade, counts, total, findings, created_at, user_id, status)
            VALUES (?, ?, NULL, NULL, '{}', NULL, '[]', ?, ?, 'running')
            """,
            (scan_id, target, created_at, user_id),
        )
    return scan_id


def finalize_scan(scan_id: str, summary: dict, findings: list[dict]) -> None:
    """Complète une ligne 'running' avec le résultat du scan (statut -> 'done')."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE scans SET score=?, grade=?, counts=?, total=?, findings=?, "
            "target=?, status='done' WHERE id=?",
            (
                summary.get("score"),
                summary.get("grade"),
                json.dumps(summary.get("counts", {})),
                summary.get("total"),
                json.dumps(findings),
                summary.get("target") or "",
                scan_id,
            ),
        )


def fail_scan(scan_id: str, message: str) -> None:
    """Marque une ligne 'running' comme en échec (statut -> 'error').

    Le message est stocké comme un finding « passthrough » (titre/détail sans `code`)
    afin que get_report le restitue tel quel, quelle que soit la langue."""
    note = [{
        "check_id": "scan-error",
        "category": "info",
        "severity": "info",
        "title": "Scan en échec",
        "detail": message or "Scan en échec.",
    }]
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE scans SET status='error', findings=? WHERE id=?",
            (json.dumps(note), scan_id),
        )


def list_scans(user_id: str | None = None) -> list[dict]:
    """Les 50 scans les plus récents (sans les findings).

    Si `user_id` est fourni, on ne renvoie que les scans de cet utilisateur ; sinon
    (ex. admin) on renvoie tout l'historique.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if user_id is None:
            rows = conn.execute(
                "SELECT id, target, score, grade, counts, created_at, status "
                "FROM scans ORDER BY created_at DESC LIMIT 50"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, target, score, grade, counts, created_at, status "
                "FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
                (user_id,),
            ).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        d["counts"] = json.loads(d["counts"]) if d["counts"] else {}
        d["status"] = d["status"] or "done"     # legacy (NULL) = scan terminé
        out.append(d)
    return out


def get_scan(scan_id: str, user_id: str | None = None) -> dict | None:
    """Retourne un scan complet (counts/findings désérialisés) ou None.

    Si `user_id` est fourni, on applique le contrôle de propriété : un scan qui ne
    lui appartient pas est traité comme introuvable.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT id, target, score, grade, counts, total, findings, created_at, user_id, status
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
    if row is None:
        return None
    if user_id is not None and row["user_id"] != user_id:
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
        "status": row["status"] or "done",       # legacy (NULL) = scan terminé
    }


def delete_scan(scan_id: str, user_id: str | None = None) -> bool:
    """Supprime un scan de l'historique. Retourne True si une ligne a été supprimée.

    Si `user_id` est fourni, on applique le contrôle de propriété : un scan d'un autre
    propriétaire n'est PAS supprimé (pas d'IDOR). Si None (ex. admin), supprime quel que
    soit le propriétaire.
    """
    with sqlite3.connect(DB_PATH) as conn:
        if user_id is None:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        else:
            cur = conn.execute(
                "DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id)
            )
    return cur.rowcount > 0
