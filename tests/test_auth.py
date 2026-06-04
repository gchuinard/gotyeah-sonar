"""Auth par lien magique : unités (tokens/sessions/rate-limit/gate), mailer, endpoints."""
import asyncio
import json
import sqlite3

import httpx
import pytest

import auth
import db
import mailer


# Les fixtures `authdb` et `client` sont dans conftest.py (partagées avec test_domains).
def _count(path, where, *params):
    return sqlite3.connect(db.DB_PATH).execute(
        f"SELECT COUNT(*) FROM {path} WHERE {where}", params).fetchone()[0]


# --------------------------------------------------------------------------- #
# Unités : tokens
# --------------------------------------------------------------------------- #
def test_hash_and_normalize():
    assert auth._hash("abc") == auth._hash("abc")
    assert auth._hash("abc") != auth._hash("abd")
    assert len(auth._hash("x")) == 64
    assert auth.normalize_email("  ME@Example.COM ") == "me@example.com"


def test_token_stored_hashed_and_single_use(authdb):
    raw = auth.issue_magic_token("a@b.com")
    stored = sqlite3.connect(db.DB_PATH).execute(
        "SELECT token_hash FROM magic_tokens").fetchone()[0]
    assert stored == auth._hash(raw) and stored != raw      # jamais en clair
    assert auth.redeem_magic_token(raw) == "a@b.com"        # 1re fois : OK
    assert auth.redeem_magic_token(raw) is None             # single-use


def test_token_expired(authdb):
    raw = auth.issue_magic_token("a@b.com", ttl_min=-1)     # déjà expiré
    assert auth.redeem_magic_token(raw) is None


def test_token_unknown(authdb):
    assert auth.redeem_magic_token("pas-un-token") is None


# --------------------------------------------------------------------------- #
# Unités : sessions
# --------------------------------------------------------------------------- #
def test_sessions(authdb):
    u = auth.create_user("s@b.com")
    raw = auth.create_session(u["id"])
    got = auth.get_session_user(raw)
    assert got and got["id"] == u["id"]
    auth.destroy_session(raw)
    assert auth.get_session_user(raw) is None
    assert auth.get_session_user("bidon") is None


# --------------------------------------------------------------------------- #
# Unités : rate limiting
# --------------------------------------------------------------------------- #
def test_rate_limit_email(authdb, monkeypatch):
    monkeypatch.setenv("SONAR_RATE_EMAIL", "3")
    monkeypatch.setenv("SONAR_RATE_IP", "100")
    assert all(auth.rate_limit_ok("r@b.com", "1.2.3.4") for _ in range(3))
    assert auth.rate_limit_ok("r@b.com", "1.2.3.4") is False


def test_rate_limit_ip(authdb, monkeypatch):
    monkeypatch.setenv("SONAR_RATE_EMAIL", "100")
    monkeypatch.setenv("SONAR_RATE_IP", "2")
    assert auth.rate_limit_ok("a@b.com", "9.9.9.9")
    assert auth.rate_limit_ok("c@b.com", "9.9.9.9")
    assert auth.rate_limit_ok("d@b.com", "9.9.9.9") is False


# --------------------------------------------------------------------------- #
# Unités : politique d'inscription + gate
# --------------------------------------------------------------------------- #
def test_invite_only(authdb, monkeypatch):
    monkeypatch.setenv("SONAR_OPEN_REGISTRATION", "false")
    assert auth.request_login_link("inconnu@b.com", "1.1.1.1") is None  # pas de lien
    auth.create_user("connu@b.com")
    assert auth.request_login_link("connu@b.com", "1.1.1.2") is not None


def test_open_registration_creates_on_redeem(authdb, monkeypatch):
    monkeypatch.setenv("SONAR_OPEN_REGISTRATION", "true")
    raw = auth.request_login_link("fresh@b.com", "1.1.1.3")
    assert raw is not None
    assert auth.get_user_by_email("fresh@b.com") is None    # pas encore créé
    sess, user = auth.complete_login(raw)
    assert sess and user["email"] == "fresh@b.com"          # créé à la redemption


def test_request_invalid_email(authdb):
    assert auth.request_login_link("pasunmail", "1.1.1.1") is None
    assert auth.request_login_link("", "1.1.1.1") is None


def test_scan_gate(authdb):
    admin = auth.create_user("admin@b.com", is_admin=True)
    plain = auth.create_user("plain@b.com")
    assert auth.user_can_scan(admin) is True
    assert auth.user_can_scan(plain) is False
    assert auth.user_can_scan_target(admin, "n-importe-quoi.com") is True
    assert auth.user_can_scan_target(plain, "n-importe-quoi.com") is False


def test_admin_scan_any_default_on(authdb, monkeypatch):
    monkeypatch.delenv("SONAR_ADMIN_SCAN_ANY", raising=False)   # défaut = bypass conservé
    admin = auth.create_user("a@b.com", is_admin=True)
    assert auth.user_can_scan(admin) is True
    assert auth.user_can_scan_target(admin, "n-importe.com") is True


def test_admin_scan_any_off_gates_admin(authdb, monkeypatch):
    monkeypatch.setenv("SONAR_ADMIN_SCAN_ANY", "false")
    admin = auth.create_user("a2@b.com", is_admin=True)
    # gaté exactement comme un compte lambda
    assert auth.user_can_scan(admin) is False
    assert auth.user_can_scan_target(admin, "x.com") is False
    # après vérif DNS d'un domaine, il ne peut scanner que CE domaine (+ ses sous-domaines)
    c = auth.add_domain(admin["id"], "monsite.com")
    auth._mark_verified(c["id"])
    assert auth.user_can_scan(admin) is True
    assert auth.user_can_scan_target(admin, "app.monsite.com") is True
    assert auth.user_can_scan_target(admin, "autre.com") is False


def test_bootstrap_admin(authdb, monkeypatch):
    monkeypatch.setenv("SONAR_ADMIN_EMAIL", "boss@b.com")
    raw = auth.bootstrap_admin()
    assert raw is not None
    u = auth.get_user_by_email("boss@b.com")
    assert u and u["is_admin"] == 1
    sess, user = auth.complete_login(raw)                   # le lien one-time marche
    assert sess and user["id"] == u["id"]


def test_bootstrap_admin_absent(authdb, monkeypatch):
    monkeypatch.delenv("SONAR_ADMIN_EMAIL", raising=False)
    assert auth.bootstrap_admin() is None


# --------------------------------------------------------------------------- #
# Mailer
# --------------------------------------------------------------------------- #
async def test_mailer_log_fallback(monkeypatch):
    monkeypatch.delenv("BREVO_API_KEY", raising=False)
    assert await mailer.send_magic_link("x@y.com", "https://s/v?token=abc") is False


async def test_mailer_brevo(monkeypatch):
    monkeypatch.setenv("BREVO_API_KEY", "secret-key")
    monkeypatch.setenv("SONAR_MAIL_FROM", "from@s.com")
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        captured["key"] = request.headers.get("api-key")
        return httpx.Response(201, json={"messageId": "1"})

    real = httpx.AsyncClient

    def fake_client(*a, **k):
        k.pop("transport", None)
        return real(*a, transport=httpx.MockTransport(handler), **k)

    monkeypatch.setattr(mailer.httpx, "AsyncClient", fake_client)
    assert await mailer.send_magic_link("x@y.com", "https://s/v?token=abc") is True
    assert "brevo.com" in captured["url"]
    assert captured["key"] == "secret-key"
    assert captured["body"]["to"][0]["email"] == "x@y.com"


# --------------------------------------------------------------------------- #
# Endpoints (TestClient)
# --------------------------------------------------------------------------- #
def test_index_redirects_anon(client):
    c, _ = client
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"


def test_login_page(client):
    c, _ = client
    r = c.get("/login")
    assert r.status_code == 200 and "lien magique" in r.text.lower()


def test_request_generic_and_issues_token(client):
    c, _ = client
    r = c.post("/api/auth/request", json={"email": "new@b.com"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert _count("magic_tokens", "email = ?", "new@b.com") == 1


def test_request_invite_only_no_token_but_generic(client, monkeypatch):
    c, _ = client
    monkeypatch.setenv("SONAR_OPEN_REGISTRATION", "false")
    r = c.post("/api/auth/request", json={"email": "ghost@b.com"})
    assert r.status_code == 200 and r.json()["ok"] is True            # réponse identique
    assert _count("magic_tokens", "email = ?", "ghost@b.com") == 0    # mais aucun lien


def test_verify_opens_session(client):
    c, _ = client
    raw = auth.issue_magic_token("v@b.com")
    r = c.get(f"/auth/verify?token={raw}", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/"
    me = c.get("/api/me")
    assert me.status_code == 200 and me.json()["email"] == "v@b.com"


def test_me_401_anon(client):
    c, _ = client
    assert c.get("/api/me").status_code == 401


def test_scan_requires_auth(client):
    c, _ = client
    assert c.get("/api/scan/stream?target=example.com").status_code == 401


def test_scan_403_without_verified_domain(client):
    c, _ = client
    u = auth.create_user("plain2@b.com")
    c.cookies.set("sonar_session", auth.create_session(u["id"]))
    r = c.get("/api/scan/stream?target=example.com")
    assert r.status_code == 403 and r.json()["code"] == "no_verified_domain"


def test_scan_admin_passes_gate(client, monkeypatch):
    c, appmod = client
    admin = auth.create_user("admin2@b.com", is_admin=True)
    c.cookies.set("sonar_session", auth.create_session(admin["id"]))

    async def fake_run(target):
        yield {"event": "started", "data": {"target": target}}
        yield {"event": "done",
               "data": {"score": 100, "grade": "A+", "counts": {}, "total": 0, "target": "https://x"},
               "_findings": []}

    monkeypatch.setattr(appmod, "run_scan", fake_run)
    r = c.get("/api/scan/stream?target=example.com")
    assert r.status_code == 200
    assert "event: done" in r.text and "event: saved" in r.text


def test_sse_heartbeat_keeps_stream_alive(client, monkeypatch):
    c, appmod = client
    admin = auth.create_user("hb@b.com", is_admin=True)
    c.cookies.set("sonar_session", auth.create_session(admin["id"]))
    monkeypatch.setattr(appmod, "SSE_HEARTBEAT_SECS", 0.05)

    async def slow_run(target):
        yield {"event": "started", "data": {"target": target, "total_checks": 1, "categories": {}}}
        await asyncio.sleep(0.25)   # > heartbeat → au moins un keepalive pendant l'attente
        yield {"event": "done",
               "data": {"score": 100, "grade": "A+", "counts": {}, "total": 0, "target": "https://x"},
               "_findings": []}

    monkeypatch.setattr(appmod, "run_scan", slow_run)
    r = c.get("/api/scan/stream?target=example.com")
    assert r.status_code == 200
    assert ": keepalive" in r.text                       # le flux est resté actif
    assert "event: done" in r.text and "event: saved" in r.text   # et le scan s'est terminé


def test_logout_destroys_session(client):
    c, _ = client
    u = auth.create_user("lo@b.com")
    raw = auth.create_session(u["id"])
    c.cookies.set("sonar_session", raw)
    assert c.get("/api/me").status_code == 200
    c.post("/api/auth/logout")
    assert auth.get_session_user(raw) is None


def test_admin_scan_any_toggle_endpoint(client):
    c, _ = client
    admin = auth.create_user("boss@b.com", is_admin=True)
    c.cookies.set("sonar_session", auth.create_session(admin["id"]))
    # défaut : /api/me expose admin_scan_any=True et can_scan=True
    me = c.get("/api/me").json()
    assert me["is_admin"] is True and me["admin_scan_any"] is True and me["can_scan"] is True
    # toggle OFF → l'admin (sans domaine vérifié) est gaté
    r = c.post("/api/admin/scan-any", json={"enabled": False})
    assert r.status_code == 200 and r.json()["admin_scan_any"] is False
    me2 = c.get("/api/me").json()
    assert me2["admin_scan_any"] is False and me2["can_scan"] is False
    # toggle ON → de nouveau libre
    c.post("/api/admin/scan-any", json={"enabled": True})
    assert c.get("/api/me").json()["can_scan"] is True


def test_admin_scan_any_toggle_forbidden_for_non_admin(client):
    c, _ = client
    plain = auth.create_user("nonadmin@b.com")
    c.cookies.set("sonar_session", auth.create_session(plain["id"]))
    assert c.post("/api/admin/scan-any", json={"enabled": True}).status_code == 403
    assert "admin_scan_any" not in c.get("/api/me").json()   # non exposé aux non-admins
