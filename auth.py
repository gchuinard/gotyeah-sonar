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

import datetime
import hashlib
import logging
import os
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


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(db.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth() -> None:
    """Crée les tables d'auth si besoin (dans la même base que les scans)."""
    db.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id         TEXT PRIMARY KEY,
                email      TEXT NOT NULL UNIQUE,
                is_admin   INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
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
            CREATE TABLE IF NOT EXISTS verified_domains (
                id          TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL,
                domain      TEXT NOT NULL,
                verified_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_rate (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                key        TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


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
# Gate « peut scanner » (vérif domaine = vrai garde-fou)
# --------------------------------------------------------------------------- #
def has_verified_domain(user_id: str) -> bool:
    with _conn() as conn:
        n = conn.execute("SELECT COUNT(*) FROM verified_domains WHERE user_id=?", (user_id,)).fetchone()[0]
    return n > 0


def user_can_scan(user) -> bool:
    return bool(user) and (bool(user["is_admin"]) or has_verified_domain(user["id"]))


def registrable_domain(host: str) -> str:
    """Domaine « enregistrable » naïf (2 derniers labels). Suffit pour le gate ;
    la vraie résolution (PSL) viendra avec le flow de vérification DNS."""
    host = (host or "").strip().lower().split(":")[0]
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def user_can_scan_target(user, host: str) -> bool:
    if not user:
        return False
    if user["is_admin"]:
        return True
    dom = registrable_domain(host)
    with _conn() as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM verified_domains WHERE user_id=? AND domain=?",
            (user["id"], dom)).fetchone()[0]
    return n > 0


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
