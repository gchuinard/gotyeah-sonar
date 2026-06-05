"""Stockage OAuth du MCP distant (clients DCR, demandes en attente, codes, jetons).

Partage le MÊME fichier SQLite que `db`/`auth` (on réutilise `auth._conn` / `_hash`
/ `_now` / `_iso`) — donc compatible avec la fixture de test `authdb`.

Principes de sécurité (alignés sur les PAT) :
  • codes & jetons stockés HASHÉS (SHA-256) au repos ; le secret en clair n'existe
    qu'à l'instant où on le rend au client ;
  • TTL courts (code 5 min) et raisonnables (access 1 h, refresh 30 j) ;
  • RÉVOCATION en cascade : révoquer un access révoque son refresh apparié (et
    inversement) ;
  • tout est rattaché à un `user_id` (subject) — l'accès restera scopé à ce
    propriétaire (pas d'IDOR) ;
  • single-use : un code d'autorisation et une demande en attente sont CONSOMMÉS
    (supprimés) à l'usage.

Le SDK `mcp` vérifie déjà l'expiration du code/refresh, le match redirect_uri et
PKCE S256 côté handler ; ici on assure le reste (consommation, rotation, et le
filtrage révoqué/expiré dans les `load_*`, car le SDK ne regarde pas la révocation).
"""
from __future__ import annotations

import json
import secrets
import time

import auth  # _conn / _hash / _now / _iso + db.DB_PATH partagés
from mcp.shared.auth import OAuthClientInformationFull

# Durées de vie (secondes)
CODE_TTL = 300              # code d'autorisation : 5 min (claude.ai l'échange aussitôt)
PENDING_TTL = 600          # demande en attente de consentement : 10 min
ACCESS_TTL = 3600          # access token : 1 h
REFRESH_TTL = 30 * 86400   # refresh token : 30 j (rotatif)


def init_store() -> None:
    """Crée les tables OAuth (idempotent). À appeler quand le MCP distant est actif."""
    with auth._conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id  TEXT PRIMARY KEY,
                metadata   TEXT NOT NULL,          -- OAuthClientInformationFull (JSON)
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oauth_pending (
                rid                   TEXT PRIMARY KEY,   -- id opaque porté dans l'URL de consentement
                client_id             TEXT NOT NULL,
                redirect_uri          TEXT NOT NULL,
                redirect_uri_explicit INTEGER NOT NULL DEFAULT 1,
                code_challenge        TEXT NOT NULL,
                scopes                TEXT NOT NULL DEFAULT '',
                state                 TEXT,
                resource              TEXT,
                expires_at            REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oauth_codes (
                code_hash             TEXT PRIMARY KEY,   -- hash du code (jamais en clair)
                client_id             TEXT NOT NULL,
                user_id               TEXT NOT NULL,      -- subject (propriétaire)
                redirect_uri          TEXT NOT NULL,
                redirect_uri_explicit INTEGER NOT NULL DEFAULT 1,
                code_challenge        TEXT NOT NULL,
                scopes                TEXT NOT NULL DEFAULT '',
                resource              TEXT,
                expires_at            REAL NOT NULL,
                created_at            TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oauth_tokens (
                token_hash   TEXT PRIMARY KEY,            -- hash du token (access OU refresh)
                kind         TEXT NOT NULL,               -- 'access' | 'refresh'
                client_id    TEXT NOT NULL,
                user_id      TEXT NOT NULL,               -- subject
                scopes       TEXT NOT NULL DEFAULT '',
                resource     TEXT,
                refresh_hash TEXT,                        -- access : hash du refresh apparié
                expires_at   REAL,                        -- NULL = sans expiration
                created_at   TEXT NOT NULL,
                revoked_at   TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_oauth_tokens_user ON oauth_tokens(user_id);
            CREATE INDEX IF NOT EXISTS ix_oauth_tokens_refresh ON oauth_tokens(refresh_hash);
            """
        )


# --------------------------------------------------------------------------- #
# Clients (Dynamic Client Registration)
# --------------------------------------------------------------------------- #
def save_client(info: OAuthClientInformationFull) -> None:
    """Persiste un client enregistré par DCR. Le SDK a déjà généré client_id/secret ;
    on stocke le bloc complet pour le restituer tel quel (le SDK compare le secret)."""
    with auth._conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO oauth_clients(client_id, metadata, created_at) VALUES (?, ?, ?)",
            (info.client_id, info.model_dump_json(), auth._iso(auth._now())),
        )


def load_client(client_id: str) -> OAuthClientInformationFull | None:
    with auth._conn() as conn:
        row = conn.execute(
            "SELECT metadata FROM oauth_clients WHERE client_id = ?", (client_id,)
        ).fetchone()
    if not row:
        return None
    return OAuthClientInformationFull.model_validate_json(row["metadata"])


# --------------------------------------------------------------------------- #
# Demandes d'autorisation en attente (entre /authorize et le consentement)
# --------------------------------------------------------------------------- #
def create_pending(
    *,
    client_id: str,
    redirect_uri: str,
    redirect_uri_explicit: bool,
    code_challenge: str,
    scopes: list[str],
    state: str | None,
    resource: str | None,
) -> str:
    """Stocke la requête d'autorisation, retourne un `rid` opaque pour l'URL de consentement."""
    rid = secrets.token_urlsafe(24)
    with auth._conn() as conn:
        conn.execute(
            """INSERT INTO oauth_pending
               (rid, client_id, redirect_uri, redirect_uri_explicit, code_challenge,
                scopes, state, resource, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (rid, client_id, redirect_uri, 1 if redirect_uri_explicit else 0,
             code_challenge, " ".join(scopes), state, resource, time.time() + PENDING_TTL),
        )
    return rid


def _pending_to_dict(row) -> dict:
    return {
        "client_id": row["client_id"],
        "redirect_uri": row["redirect_uri"],
        "redirect_uri_explicit": bool(row["redirect_uri_explicit"]),
        "code_challenge": row["code_challenge"],
        "scopes": row["scopes"].split() if row["scopes"] else [],
        "state": row["state"],
        "resource": row["resource"],
    }


def peek_pending(rid: str) -> dict | None:
    """Charge une demande en attente SANS la consommer (pour afficher le consentement)."""
    with auth._conn() as conn:
        row = conn.execute("SELECT * FROM oauth_pending WHERE rid = ?", (rid,)).fetchone()
    if not row or row["expires_at"] < time.time():
        return None
    return _pending_to_dict(row)


def take_pending(rid: str) -> dict | None:
    """Charge ET consomme (supprime) une demande en attente. None si absente/expirée."""
    with auth._conn() as conn:
        row = conn.execute("SELECT * FROM oauth_pending WHERE rid = ?", (rid,)).fetchone()
        conn.execute("DELETE FROM oauth_pending WHERE rid = ?", (rid,))
    if not row or row["expires_at"] < time.time():
        return None
    return _pending_to_dict(row)


# --------------------------------------------------------------------------- #
# Codes d'autorisation (émis APRÈS consentement, liés au propriétaire)
# --------------------------------------------------------------------------- #
def create_code(
    *,
    client_id: str,
    user_id: str,
    redirect_uri: str,
    redirect_uri_explicit: bool,
    code_challenge: str,
    scopes: list[str],
    resource: str | None,
) -> str:
    """Crée un code d'autorisation (rendu UNE fois au client) ; stocke son hash."""
    raw = secrets.token_urlsafe(32)
    with auth._conn() as conn:
        conn.execute(
            """INSERT INTO oauth_codes
               (code_hash, client_id, user_id, redirect_uri, redirect_uri_explicit,
                code_challenge, scopes, resource, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (auth._hash(raw), client_id, user_id, redirect_uri,
             1 if redirect_uri_explicit else 0, code_challenge, " ".join(scopes),
             resource, time.time() + CODE_TTL, auth._iso(auth._now())),
        )
    return raw


def peek_code(raw: str) -> dict | None:
    """Charge un code par sa valeur (NON consommant). None si absent/expiré."""
    with auth._conn() as conn:
        row = conn.execute(
            "SELECT * FROM oauth_codes WHERE code_hash = ?", (auth._hash(raw),)
        ).fetchone()
    if not row or row["expires_at"] < time.time():
        return None
    return {
        "code": raw,
        "client_id": row["client_id"],
        "user_id": row["user_id"],
        "redirect_uri": row["redirect_uri"],
        "redirect_uri_explicit": bool(row["redirect_uri_explicit"]),
        "code_challenge": row["code_challenge"],
        "scopes": row["scopes"].split() if row["scopes"] else [],
        "resource": row["resource"],
        "expires_at": row["expires_at"],
    }


def consume_code(raw: str) -> bool:
    """Supprime un code (single-use). True s'il existait."""
    with auth._conn() as conn:
        cur = conn.execute("DELETE FROM oauth_codes WHERE code_hash = ?", (auth._hash(raw),))
    return cur.rowcount > 0


# --------------------------------------------------------------------------- #
# Jetons (access + refresh) — hashés, appariés pour révocation en cascade
# --------------------------------------------------------------------------- #
def issue_token_pair(
    *, client_id: str, user_id: str, scopes: list[str], resource: str | None
) -> tuple[str, str]:
    """Émet un couple (access, refresh) lié au propriétaire. Retourne les valeurs en clair."""
    access_raw = secrets.token_urlsafe(32)
    refresh_raw = secrets.token_urlsafe(32)
    access_h, refresh_h = auth._hash(access_raw), auth._hash(refresh_raw)
    now_iso = auth._iso(auth._now())
    scope_s = " ".join(scopes)
    with auth._conn() as conn:
        conn.execute(
            """INSERT INTO oauth_tokens
               (token_hash, kind, client_id, user_id, scopes, resource, refresh_hash,
                expires_at, created_at)
               VALUES (?, 'access', ?, ?, ?, ?, ?, ?, ?)""",
            (access_h, client_id, user_id, scope_s, resource, refresh_h,
             time.time() + ACCESS_TTL, now_iso),
        )
        conn.execute(
            """INSERT INTO oauth_tokens
               (token_hash, kind, client_id, user_id, scopes, resource, refresh_hash,
                expires_at, created_at)
               VALUES (?, 'refresh', ?, ?, ?, ?, NULL, ?, ?)""",
            (refresh_h, client_id, user_id, scope_s, resource,
             time.time() + REFRESH_TTL, now_iso),
        )
    return access_raw, refresh_raw


def _load_token(raw: str, kind: str) -> dict | None:
    """Charge un token VALIDE (bon type, non révoqué, non expiré). None sinon."""
    with auth._conn() as conn:
        row = conn.execute(
            "SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = ?",
            (auth._hash(raw), kind),
        ).fetchone()
    if not row or row["revoked_at"]:
        return None
    if row["expires_at"] is not None and row["expires_at"] < time.time():
        return None
    return {
        "token": raw,
        "kind": row["kind"],
        "client_id": row["client_id"],
        "user_id": row["user_id"],
        "scopes": row["scopes"].split() if row["scopes"] else [],
        "resource": row["resource"],
        "expires_at": int(row["expires_at"]) if row["expires_at"] is not None else None,
    }


def load_access(raw: str) -> dict | None:
    return _load_token(raw, "access")


def load_refresh(raw: str) -> dict | None:
    return _load_token(raw, "refresh")


def revoke_by_raw(raw: str) -> None:
    """Révoque le token donné ET son apparié (access<->refresh). Idempotent."""
    h = auth._hash(raw)
    now_iso = auth._iso(auth._now())
    with auth._conn() as conn:
        row = conn.execute(
            "SELECT token_hash, kind, refresh_hash FROM oauth_tokens WHERE token_hash = ?",
            (h,),
        ).fetchone()
        if not row:
            return
        # révoque celui-ci
        conn.execute(
            "UPDATE oauth_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            (now_iso, h),
        )
        # révoque l'apparié
        if row["kind"] == "access" and row["refresh_hash"]:
            conn.execute(
                "UPDATE oauth_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (now_iso, row["refresh_hash"]),
            )
        else:  # refresh -> révoque les access qui le référencent
            conn.execute(
                "UPDATE oauth_tokens SET revoked_at = ? WHERE refresh_hash = ? AND revoked_at IS NULL",
                (now_iso, h),
            )
