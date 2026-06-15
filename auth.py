"""Auth passwordless par lien magique — P0.

Aucun mot de passe. Un email -> un lien à USAGE UNIQUE (TTL court) -> une SESSION
longue (cookie). Tout ce qui est secret (tokens de lien, tokens de session) est
stocké **hashé** au repos (SHA-256) ; le secret en clair ne quitte jamais la
mémoire/le mail.

Garde-fous :
  - tokens single-use (invalidés à la consommation), expirants ;
  - rate-limit par email ET par IP (fenêtre glissante) ;
  - politique d'inscription via SONAR_OPEN_REGISTRATION (ouverte vs invite-only) ;
  - un compte ne peut RIEN scanner tant qu'il n'a pas de domaine vérifié
    (la vérif DNS elle-même arrive dans un ticket suivant ; ici le gate est prêt) ;
  - porte de secours admin indépendante de l'email (SONAR_ADMIN_EMAIL + lien
    one-time imprimé dans les logs au démarrage).

La base est partagée avec `db.py` (même fichier SQLite). On référence `db.DB_PATH`
dynamiquement pour rester testable (monkeypatch).
"""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import logging
import os
import re
import secrets
import sqlite3
import uuid

import db

log = logging.getLogger("sonar.auth")


# --------------------------------------------------------------------------- #
# Config (lue dynamiquement pour rester testable)
# --------------------------------------------------------------------------- #
def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name) or default)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    v = _env(name).lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


def open_registration() -> bool:
    return _env_bool("SONAR_OPEN_REGISTRATION", False)


def admin_scan_any() -> bool:
    """L'admin peut-il scanner n'importe quel domaine SANS vérification DNS ?

    Priorité : le réglage modifiable depuis l'UI (table `app_settings`) l'emporte ; à
    défaut, l'env `SONAR_ADMIN_SCAN_ANY` fixe la valeur initiale (défaut True). N'affecte
    QUE le compte admin ; les non-admins restent toujours gatés.
    """
    override = db.get_setting("admin_scan_any")
    if override is not None:
        return override == "1"
    return _env_bool("SONAR_ADMIN_SCAN_ANY", True)


def set_admin_scan_any(enabled: bool) -> None:
    """Persiste le toggle (UI admin) ; surclasse l'env par défaut."""
    db.set_setting("admin_scan_any", "1" if enabled else "0")


def session_max_age() -> int:
    return _env_int("SONAR_SESSION_DAYS", 30) * 86400


# --------------------------------------------------------------------------- #
# Helpers bas niveau
# --------------------------------------------------------------------------- #
def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(dt: datetime.datetime) -> str:
    return dt.isoformat()


def _hash(raw: str) -> str:
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


# Validation volontairement simple (pas de RFC complète) : un local-part, un domaine
# avec au moins un point, pas d'espace, longueur bornée. Suffisant pour un homelab.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(email: str) -> bool:
    email = normalize_email(email)
    return bool(email) and len(email) <= 254 and _EMAIL_RE.match(email) is not None


def _conn() -> sqlite3.Connection:
    conn = db.connect()                 # busy_timeout + WAL persistant (cf. db.connect)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth() -> None:
    """Crée les tables d'auth si besoin (dans la même base que les scans)."""
    db.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _conn() as conn:
        # Pré-migration : l'ancienne table `verified_domains` (déploiement auth
        # initial, vide) n'a pas les colonnes du flow de vérif -> on la recrée.
        existing = conn.execute("PRAGMA table_info(verified_domains)").fetchall()
        if existing and "token" not in {r[1] for r in existing}:
            conn.execute("DROP TABLE verified_domains")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id         TEXT PRIMARY KEY,
                email      TEXT NOT NULL UNIQUE,
                is_admin   INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                lang       TEXT
            );
            CREATE TABLE IF NOT EXISTS magic_tokens (
                token_hash  TEXT PRIMARY KEY,
                email       TEXT NOT NULL,
                purpose     TEXT NOT NULL DEFAULT 'login',
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                redeemed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id    TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS personal_tokens (
                id           TEXT PRIMARY KEY,
                user_id      TEXT NOT NULL,
                name         TEXT NOT NULL DEFAULT '',
                token_hash   TEXT NOT NULL UNIQUE,
                scope        TEXT NOT NULL DEFAULT 'scans:read',
                created_at   TEXT NOT NULL,
                expires_at   TEXT,
                last_used_at TEXT,
                revoked_at   TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_pat_user ON personal_tokens(user_id);
            CREATE TABLE IF NOT EXISTS verified_domains (
                id          TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL,
                domain      TEXT NOT NULL,
                token       TEXT NOT NULL,
                verified    INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                verified_at TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_domain_user
                ON verified_domains(user_id, domain);
            CREATE TABLE IF NOT EXISTS auth_rate (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                key        TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        # Migration douce : une base d'avant l'i18n n'a pas la colonne `lang`.
        ucols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "lang" not in ucols:
            conn.execute("ALTER TABLE users ADD COLUMN lang TEXT")
    purge_expired()   # nettoyage au démarrage (sessions / liens magiques expirés)


def purge_expired() -> int:
    """Supprime les sessions et liens magiques EXPIRÉS. Sans ça ces tables grossissent sans
    fin (un anonyme peut générer des magic_tokens à volonté en inscription ouverte). Appelé
    au démarrage ; renvoie le nombre de lignes supprimées. Idempotent."""
    now = _iso(_now())
    with _conn() as conn:
        n = conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,)).rowcount
        n += conn.execute("DELETE FROM magic_tokens WHERE expires_at < ?", (now,)).rowcount
    return n


# --------------------------------------------------------------------------- #
# Utilisateurs
# --------------------------------------------------------------------------- #
def get_user_by_email(email: str):
    email = normalize_email(email)
    with _conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    return dict(row) if row else None


def get_user_by_id(uid: str):
    with _conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return dict(row) if row else None


def set_admin(uid: str, value: bool) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET is_admin=? WHERE id=?", (1 if value else 0, uid))


def update_user_email(user_id: str, new_email: str):
    """Change l'email d'un compte (usage ADMIN). Renvoie :
      - le compte mis à jour (dict) en cas de succès (ou inchangé si même email) ;
      - "not_found" si le compte n'existe pas ;
      - "invalid"   si l'email est mal formé ;
      - "conflict"  si un AUTRE compte utilise déjà cette adresse.

    Purge les liens magiques en vol pour l'ancien ET le nouvel email : un lien pendant
    sur l'ancienne adresse pourrait recréer un compte fantôme, et un lien pendant sur la
    nouvelle adresse pourrait laisser un tiers se connecter au compte renommé.
    """
    new_email = normalize_email(new_email)
    if not is_valid_email(new_email):
        return "invalid"
    user = get_user_by_id(user_id)
    if not user:
        return "not_found"
    if new_email == user["email"]:
        return user   # no-op : même adresse
    try:
        with _conn() as conn:
            conn.execute("UPDATE users SET email=? WHERE id=?", (new_email, user_id))
            conn.execute("DELETE FROM magic_tokens WHERE email IN (?, ?)",
                         (user["email"], new_email))
    except sqlite3.IntegrityError:
        return "conflict"   # contrainte UNIQUE(email) : un autre compte a déjà cette adresse
    return get_user_by_id(user_id)


def set_user_lang(uid: str, lang: str) -> None:
    """Enregistre la langue préférée de l'utilisateur (déjà validée par l'appelant)."""
    with _conn() as conn:
        conn.execute("UPDATE users SET lang=? WHERE id=?", (lang, uid))


def create_user(email: str, is_admin: bool = False):
    email = normalize_email(email)
    uid = uuid.uuid4().hex
    with _conn() as conn:
        conn.execute(
            "INSERT INTO users (id, email, is_admin, created_at) VALUES (?, ?, ?, ?)",
            (uid, email, 1 if is_admin else 0, _iso(_now())),
        )
    return get_user_by_id(uid)


def get_or_create_user(email: str, is_admin: bool = False):
    user = get_user_by_email(email)
    if user:
        if is_admin and not user["is_admin"]:
            set_admin(user["id"], True)
            user = get_user_by_id(user["id"])
        return user
    return create_user(email, is_admin=is_admin)


def count_admins() -> int:
    """Nombre de comptes admin — sert de garde-fou anti-lockout (ne pas tomber à zéro)."""
    with _conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0]


def list_users() -> list[dict]:
    """Tous les comptes + compteurs (domaines vérifiés, scans, jetons actifs) — usage ADMIN.

    Sous-requêtes corrélées plutôt que des JOIN/GROUP BY : pas de double comptage quand un
    user a à la fois des domaines et des scans. La base est petite (homelab), c'est suffisant.
    """
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT u.id, u.email, u.is_admin, u.created_at, u.lang,
                   (SELECT COUNT(*) FROM verified_domains d
                      WHERE d.user_id = u.id AND d.verified = 1)        AS verified_domains,
                   (SELECT COUNT(*) FROM scans s WHERE s.user_id = u.id) AS scans,
                   (SELECT COUNT(*) FROM personal_tokens p
                      WHERE p.user_id = u.id AND p.revoked_at IS NULL)   AS active_tokens
            FROM users u
            ORDER BY u.created_at
            """
        ).fetchall()
    return [dict(r) for r in rows]


def delete_user(user_id: str) -> bool:
    """Supprime un compte et TOUTES ses données (cascade), en une transaction.

    Couvre les scans (table `scans`, même base), domaines, jetons perso, sessions, et les
    liens magiques encore en vol pour son email. Renvoie False si le compte n'existe pas.
    Aucun garde-fou ici (dernier admin / soi-même) : c'est à l'appelant (endpoint) de poser
    la politique — cette fonction est l'outil brut.
    """
    user = get_user_by_id(user_id)
    if not user:
        return False
    with _conn() as conn:
        conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM verified_domains WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM personal_tokens WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM magic_tokens WHERE email = ?", (user["email"],))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return True


def demote_admin(user_id: str) -> bool:
    """Retire le rôle admin en UNE instruction atomique, SAUF si c'est le dernier admin.
    La sous-requête `COUNT(...) > 1` est évaluée dans l'UPDATE (sous le verrou d'écriture) →
    deux rétrogradations concurrentes ne peuvent pas tomber à zéro admin. True si retiré ;
    False si c'était le dernier admin (ou la cible n'est pas/plus admin)."""
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE users SET is_admin = 0 "
            "WHERE id = ? AND is_admin = 1 "
            "AND (SELECT COUNT(*) FROM users WHERE is_admin = 1) > 1",
            (user_id,))
        return cur.rowcount > 0


def delete_user_guarded(user_id: str) -> str:
    """Supprime un compte + ses données (cascade), en refusant le DERNIER admin de façon
    ATOMIQUE. `BEGIN IMMEDIATE` prend le verrou d'écriture AVANT le COUNT → anti-course
    (deux suppressions concurrentes de deux admins ne peuvent pas vider la table d'admins).
    Renvoie 'ok' | 'last_admin' | 'not_found'."""
    conn = _conn()
    try:
        conn.isolation_level = None        # gestion manuelle de la transaction
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT is_admin, email FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return "not_found"
        if row["is_admin"]:
            n = conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
            if n <= 1:
                conn.execute("ROLLBACK")
                return "last_admin"
        for sql in ("DELETE FROM scans WHERE user_id = ?",
                    "DELETE FROM verified_domains WHERE user_id = ?",
                    "DELETE FROM personal_tokens WHERE user_id = ?",
                    "DELETE FROM sessions WHERE user_id = ?"):
            conn.execute(sql, (user_id,))
        conn.execute("DELETE FROM magic_tokens WHERE email = ?", (row["email"],))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.execute("COMMIT")
        return "ok"
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Rate limiting (email + IP, fenêtre glissante)
# --------------------------------------------------------------------------- #
def rate_limit_ok(email: str, ip: str) -> bool:
    email = normalize_email(email)
    window = _env_int("SONAR_RATE_WINDOW_MIN", 15)
    cutoff = _iso(_now() - datetime.timedelta(minutes=window))
    now_iso = _iso(_now())
    with _conn() as conn:
        conn.execute("DELETE FROM auth_rate WHERE created_at < ?", (cutoff,))
        n_email = conn.execute(
            "SELECT COUNT(*) FROM auth_rate WHERE key=? AND created_at >= ?",
            (f"email:{email}", cutoff)).fetchone()[0]
        n_ip = conn.execute(
            "SELECT COUNT(*) FROM auth_rate WHERE key=? AND created_at >= ?",
            (f"ip:{ip}", cutoff)).fetchone()[0]
        if n_email >= _env_int("SONAR_RATE_EMAIL", 5) or n_ip >= _env_int("SONAR_RATE_IP", 20):
            return False
        conn.execute("INSERT INTO auth_rate (key, created_at) VALUES (?, ?)", (f"email:{email}", now_iso))
        conn.execute("INSERT INTO auth_rate (key, created_at) VALUES (?, ?)", (f"ip:{ip}", now_iso))
    return True


def scan_rate_ok(user_id: str) -> bool:
    """Garde-fou anti-abus des scans déclenchés par le MCP (run_scan = action publique).

    Borne le nombre de scans par compte sur une fenêtre glissante (réutilise `auth_rate`,
    clé `scan:<user_id>`). Défauts : `SONAR_SCAN_RATE`=10 scans / `SONAR_SCAN_RATE_WINDOW_MIN`=15 min.
    Enregistre la tentative et renvoie False si le quota est atteint. La purge ne touche
    QUE la clé du compte (n'interfère pas avec le rate-limit de login)."""
    window = _env_int("SONAR_SCAN_RATE_WINDOW_MIN", 15)
    limit = _env_int("SONAR_SCAN_RATE", 10)
    key = f"scan:{user_id}"
    cutoff = _iso(_now() - datetime.timedelta(minutes=window))
    now_iso = _iso(_now())
    with _conn() as conn:
        conn.execute("DELETE FROM auth_rate WHERE key=? AND created_at < ?", (key, cutoff))
        n = conn.execute(
            "SELECT COUNT(*) FROM auth_rate WHERE key=? AND created_at >= ?",
            (key, cutoff)).fetchone()[0]
        if n >= limit:
            return False
        conn.execute("INSERT INTO auth_rate (key, created_at) VALUES (?, ?)", (key, now_iso))
    return True


# --------------------------------------------------------------------------- #
# Tokens de lien magique (single-use, expirants, hashés)
# --------------------------------------------------------------------------- #
def issue_magic_token(email: str, purpose: str = "login", ttl_min: int | None = None) -> str:
    email = normalize_email(email)
    raw = secrets.token_urlsafe(32)
    ttl = ttl_min if ttl_min is not None else _env_int("SONAR_MAGIC_TTL_MIN", 15)
    now = _now()
    expires = now + datetime.timedelta(minutes=ttl)
    with _conn() as conn:
        conn.execute(
            "INSERT INTO magic_tokens (token_hash, email, purpose, created_at, expires_at, redeemed_at) "
            "VALUES (?, ?, ?, ?, ?, NULL)",
            (_hash(raw), email, purpose, _iso(now), _iso(expires)),
        )
    return raw  # seul le secret en clair est renvoyé ; la base ne stocke que le hash


def redeem_magic_token(raw: str):
    """Consomme un token (single-use) et renvoie l'email s'il est valide, sinon None."""
    token_hash = _hash(raw or "")
    now_iso = _iso(_now())
    with _conn() as conn:
        row = conn.execute(
            "SELECT email, expires_at, redeemed_at FROM magic_tokens WHERE token_hash=?",
            (token_hash,)).fetchone()
        if not row or row["redeemed_at"] is not None or row["expires_at"] <= now_iso:
            return None
        # invalidation atomique : la 1re consommation gagne.
        cur = conn.execute(
            "UPDATE magic_tokens SET redeemed_at=? WHERE token_hash=? AND redeemed_at IS NULL",
            (now_iso, token_hash))
        if cur.rowcount != 1:
            return None
        return row["email"]


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #
def create_session(user_id: str) -> str:
    raw = secrets.token_urlsafe(32)
    now = _now()
    expires = now + datetime.timedelta(days=_env_int("SONAR_SESSION_DAYS", 30))
    with _conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (_hash(raw), user_id, _iso(now), _iso(expires)),
        )
    return raw


def get_session_user(raw: str):
    if not raw:
        return None
    now_iso = _iso(_now())
    with _conn() as conn:
        row = conn.execute(
            "SELECT user_id, expires_at FROM sessions WHERE token_hash=?", (_hash(raw),)).fetchone()
        if not row or row["expires_at"] <= now_iso:
            return None
    return get_user_by_id(row["user_id"])


def destroy_session(raw: str) -> None:
    if not raw:
        return
    with _conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (_hash(raw),))


# --------------------------------------------------------------------------- #
# Jetons d'accès personnels (PAT) — accès LECTURE SEULE à l'API pour le MCP.
# Le secret brut (`sonar_pat_…`) n'est montré qu'à la création ; seul son hash
# SHA-256 est stocké (lookup par index, comme les sessions). Révocable, expiry
# optionnel, scope (un seul pour l'instant : "scans:read").
# --------------------------------------------------------------------------- #
PAT_PREFIX = "sonar_pat_"
PAT_DEFAULT_SCOPE = "scans:read"


def _pat_to_dict(row) -> dict:
    """Métadonnées publiques d'un jeton — SANS jamais le secret brut."""
    return {
        "id": row["id"],
        "name": row["name"] or "",
        "scope": row["scope"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "last_used_at": row["last_used_at"],
        "revoked": row["revoked_at"] is not None,
    }


def create_pat(user_id: str, name: str = "", scope: str = PAT_DEFAULT_SCOPE,
               ttl_days: int | None = None) -> tuple[str, dict]:
    """Crée un jeton personnel. Retourne (raw, meta) ; `raw` n'est disponible qu'ICI."""
    raw = PAT_PREFIX + secrets.token_urlsafe(32)
    pid = uuid.uuid4().hex
    now = _now()
    expires = _iso(now + datetime.timedelta(days=ttl_days)) if ttl_days else None
    with _conn() as conn:
        conn.execute(
            "INSERT INTO personal_tokens "
            "(id, user_id, name, token_hash, scope, created_at, expires_at, last_used_at, revoked_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
            (pid, user_id, (name or "").strip()[:80], _hash(raw), scope, _iso(now), expires),
        )
        row = conn.execute("SELECT * FROM personal_tokens WHERE id=?", (pid,)).fetchone()
    return raw, _pat_to_dict(row)


def list_pats(user_id: str) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM personal_tokens WHERE user_id=? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
    return [_pat_to_dict(r) for r in rows]


def revoke_pat(token_id: str, user_id: str) -> bool:
    """Révoque un jeton de cet utilisateur. Idempotent ; True si une ligne lui
    appartenant a été révoquée (un id d'un autre owner ne fait rien -> pas d'IDOR)."""
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE personal_tokens SET revoked_at=? "
            "WHERE id=? AND user_id=? AND revoked_at IS NULL",
            (_iso(_now()), token_id, user_id),
        )
        return cur.rowcount > 0


def delete_pat(token_id: str, user_id: str) -> bool:
    """Supprime DÉFINITIVEMENT un jeton DÉJÀ révoqué de cet utilisateur.

    Owner-scopé (pas d'IDOR) et restreint aux jetons révoqués : tant qu'un jeton est
    actif, on garde sa ligne (il faut le révoquer d'abord, ce qui coupe l'accès). C'est
    du simple nettoyage de la liste. Retourne True si une ligne a été supprimée."""
    with _conn() as conn:
        cur = conn.execute(
            "DELETE FROM personal_tokens "
            "WHERE id=? AND user_id=? AND revoked_at IS NOT NULL",
            (token_id, user_id),
        )
        return cur.rowcount > 0


def resolve_pat(raw: str, required_scope: str | None = None):
    """Valide un jeton brut et renvoie l'utilisateur propriétaire, sinon None.
    Refuse : mauvais préfixe, inconnu, révoqué, expiré, scope insuffisant.
    Met à jour `last_used_at` en cas de succès."""
    if not raw or not raw.startswith(PAT_PREFIX):
        return None
    now_iso = _iso(_now())
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM personal_tokens WHERE token_hash=?", (_hash(raw),)
        ).fetchone()
        if not row or row["revoked_at"] is not None:
            return None
        if row["expires_at"] is not None and row["expires_at"] <= now_iso:
            return None
        if required_scope is not None and required_scope not in (row["scope"] or "").split():
            return None  # default-deny si on ajoute des scopes plus tard
        conn.execute(
            "UPDATE personal_tokens SET last_used_at=? WHERE id=?", (now_iso, row["id"]))
    return get_user_by_id(row["user_id"])


# --------------------------------------------------------------------------- #
# Gate « peut scanner » (vérif domaine = vrai garde-fou)
# --------------------------------------------------------------------------- #
CHALLENGE_PREFIX = "_sonar-verify"
_DOMAIN_RE = re.compile(r"(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$")


def normalize_domain(host: str) -> str:
    """Minuscule, sans schéma/port/chemin ni `www.` — la forme « propriétaire »."""
    host = (host or "").strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0].strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def is_valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.fullmatch(normalize_domain(domain)))


def has_verified_domain(user_id: str) -> bool:
    with _conn() as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM verified_domains WHERE user_id=? AND verified=1",
            (user_id,)).fetchone()[0]
    return n > 0


def user_can_scan(user) -> bool:
    if not user:
        return False
    if user["is_admin"] and admin_scan_any():
        return True
    return has_verified_domain(user["id"])


def _verified_domains_of(user_id: str) -> list[str]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT domain FROM verified_domains WHERE user_id=? AND verified=1",
            (user_id,)).fetchall()
    return [r["domain"] for r in rows]


def user_can_scan_target(user, host: str) -> bool:
    """Admin (si `SONAR_ADMIN_SCAN_ANY`) : tout. Sinon : le domaine cible doit être un
    domaine vérifié de l'utilisateur, ou un sous-domaine de celui-ci."""
    if not user:
        return False
    if user["is_admin"] and admin_scan_any():
        return True
    h = normalize_domain(host)
    for d in _verified_domains_of(user["id"]):
        if h == d or h.endswith("." + d):
            return True
    return False


# --------------------------------------------------------------------------- #
# Vérification de domaine par DNS (TXT)
# --------------------------------------------------------------------------- #
def _domain_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "domain": row["domain"],
        "verified": bool(row["verified"]),
        "token": row["token"],
        "created_at": row["created_at"],
        "verified_at": row["verified_at"],
        # Enregistrement TXT à publier (apex recommandé, sous-domaine en alternative).
        "dns": {
            "apex": {"type": "TXT", "host": row["domain"], "value": f"sonar-verify={row['token']}"},
            "subdomain": {"type": "TXT", "host": f"{CHALLENGE_PREFIX}.{row['domain']}", "value": row["token"]},
        },
    }


def get_domain(domain_id: str, user_id: str):
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM verified_domains WHERE id=? AND user_id=?", (domain_id, user_id)).fetchone()
    return _domain_to_dict(row) if row else None


def get_domain_by_name(user_id: str, domain: str):
    domain = normalize_domain(domain)
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM verified_domains WHERE user_id=? AND domain=?", (user_id, domain)).fetchone()
    return _domain_to_dict(row) if row else None


def list_domains(user_id: str) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM verified_domains WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
    return [_domain_to_dict(r) for r in rows]


def add_domain(user_id: str, domain: str):
    """Crée une revendication de domaine (token de challenge). Idempotent : si le
    domaine est déjà revendiqué par cet utilisateur, on renvoie l'existant. None si
    le domaine est invalide."""
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        return None
    existing = get_domain_by_name(user_id, domain)
    if existing:
        return existing
    did = uuid.uuid4().hex
    token = secrets.token_hex(16)
    with _conn() as conn:
        conn.execute(
            "INSERT INTO verified_domains (id, user_id, domain, token, verified, created_at, verified_at) "
            "VALUES (?, ?, ?, ?, 0, ?, NULL)",
            (did, user_id, domain, token, _iso(_now())),
        )
    return get_domain(did, user_id)


def delete_domain(domain_id: str, user_id: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM verified_domains WHERE id=? AND user_id=?", (domain_id, user_id))


def update_domain(domain_id: str, user_id: str, new_domain: str):
    """Renomme un domaine d'un utilisateur (usage ADMIN).

    Un nom de domaine différent n'a PAS été prouvé : le renommage **remet le domaine
    en attente** (verified=0, nouveau token de challenge). Renvoie :
      - le domaine mis à jour (dict) en cas de succès (ou inchangé si même nom) ;
      - None si le domaine est introuvable pour cet utilisateur, ou le nouveau nom invalide ;
      - la chaîne "conflict" si l'utilisateur a déjà un domaine portant ce nom.
    """
    new_domain = normalize_domain(new_domain)
    if not is_valid_domain(new_domain):
        return None
    current = get_domain(domain_id, user_id)
    if not current:
        return None
    if new_domain == current["domain"]:
        return current   # no-op : même nom, on ne casse pas la vérification existante
    if get_domain_by_name(user_id, new_domain):
        return "conflict"
    token = secrets.token_hex(16)
    with _conn() as conn:
        conn.execute(
            "UPDATE verified_domains SET domain=?, token=?, verified=0, verified_at=NULL "
            "WHERE id=? AND user_id=?",
            (new_domain, token, domain_id, user_id),
        )
    return get_domain(domain_id, user_id)


def _mark_verified(domain_id: str) -> None:
    with _conn() as conn:
        conn.execute(
            "UPDATE verified_domains SET verified=1, verified_at=? WHERE id=?",
            (_iso(_now()), domain_id))


async def _txt_records(name: str) -> list[str]:
    """Résout les enregistrements TXT (bloquant -> thread). Liste vide si erreur."""
    import dns.resolver

    def query():
        try:
            answer = dns.resolver.resolve(name, "TXT", lifetime=8)
        except Exception:
            return []
        out = []
        for rdata in answer:
            try:
                out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
            except Exception:
                out.append(str(rdata).strip('"'))
        return out

    return await asyncio.to_thread(query)


async def verify_domain(domain_id: str, user_id: str):
    """Vérifie la propriété d'un domaine via son TXT. Renvoie (ok: bool, message: str)."""
    claim = get_domain(domain_id, user_id)
    if not claim:
        return False, "Domaine introuvable."
    if claim["verified"]:
        return True, "Domaine déjà vérifié."

    domain, token = claim["domain"], claim["token"]

    # Méthode 1 : TXT sur l'apex contenant `sonar-verify=<token>`.
    if any(f"sonar-verify={token}" in rec for rec in await _txt_records(domain)):
        _mark_verified(domain_id)
        return True, "Domaine vérifié (TXT sur l'apex)."

    # Méthode 2 : TXT sur `_sonar-verify.<domaine>` valant le token.
    if any(token in rec for rec in await _txt_records(f"{CHALLENGE_PREFIX}.{domain}")):
        _mark_verified(domain_id)
        return True, f"Domaine vérifié (TXT sur {CHALLENGE_PREFIX})."

    return False, ("Enregistrement TXT introuvable. Vérifie la valeur, puis patiente : "
                   "la propagation DNS peut prendre quelques minutes.")


# --------------------------------------------------------------------------- #
# Flows de haut niveau
# --------------------------------------------------------------------------- #
def request_login_link(email: str, ip: str):
    """Applique le rate-limit + la politique d'inscription.

    Renvoie le token brut à envoyer par email, ou None s'il ne faut pas envoyer de
    lien (rate-limité, email invalide, ou email inconnu en mode invite-only). La
    réponse renvoyée à l'utilisateur reste GÉNÉRIQUE quoi qu'il arrive (géré côté
    endpoint) pour ne pas divulguer l'existence d'un compte.
    """
    email = normalize_email(email)
    if not email or "@" not in email:
        return None
    if not rate_limit_ok(email, ip):
        return None
    user = get_user_by_email(email)
    if user is None and not open_registration():
        return None  # invite-only : pas de lien pour un email inconnu
    return issue_magic_token(email, purpose="login")


def complete_login(raw: str):
    """Consomme le token de lien et ouvre une session.

    Renvoie (session_raw, user) en cas de succès, (None, None) sinon. L'utilisateur
    est créé au passage si le token avait été émis en mode inscription ouverte.
    """
    email = redeem_magic_token(raw)
    if not email:
        return None, None
    user = get_or_create_user(email)
    session_raw = create_session(user["id"])
    return session_raw, user


def bootstrap_admin():
    """Au démarrage : garantit le compte admin (SONAR_ADMIN_EMAIL) et imprime un
    lien de login one-time dans les logs — porte de secours indépendante de l'email.
    Renvoie le token brut (utile aux tests), ou None si pas d'admin configuré.
    """
    email = normalize_email(_env("SONAR_ADMIN_EMAIL"))
    if not email:
        return None
    get_or_create_user(email, is_admin=True)
    ttl = _env_int("SONAR_ADMIN_TTL_MIN", 60)
    raw = issue_magic_token(email, purpose="admin-bootstrap", ttl_min=ttl)
    base = _env("SONAR_BASE_URL").rstrip("/")
    link = f"{base}/auth/verify?token={raw}" if base else f"/auth/verify?token={raw}"
    log.warning("================ PORTE DE SECOURS ADMIN ================")
    log.warning("Admin : %s", email)
    log.warning("Lien de login one-time (valable %s min, usage unique) :", ttl)
    log.warning("  %s", link)
    log.warning("=======================================================")
    return raw
