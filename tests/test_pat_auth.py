"""Auth par PAT (Étape 2) : la dépendance _pat_or_session_user (concept require_pat).

Vérifie : cookie OU Bearer PAT acceptés ; PAT révoqué/expiré/mauvais scope refusé ;
DEFAULT-DENY (un PAT ne peut atteindre aucune route d'écriture/admin) ; jeton jamais
journalisé. Le branchement effectif sur les 3 lectures + l'IDOR HTTP sont à l'Étape 3.
"""
import app as appmod
import auth
import db
from starlette.requests import Request


def _req(headers=None):
    """Request Starlette minimale avec en-têtes (et cookies via l'en-tête 'cookie')."""
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "GET", "path": "/", "query_string": b"",
                    "headers": raw})


def _bearer(raw):
    return {"authorization": f"Bearer {raw}"}


# --------------------------------------------------------------------------- #
# Unités : la dépendance accepte cookie OU PAT, et refuse le reste
# --------------------------------------------------------------------------- #
def test_dep_accepts_valid_pat(authdb):
    u = auth.create_user("a@b.com")
    raw, _ = auth.create_pat(u["id"])
    got = appmod._pat_or_session_user(_req(_bearer(raw)))
    assert got and got["id"] == u["id"]


def test_dep_accepts_session_cookie(authdb):
    u = auth.create_user("a@b.com")
    sess = auth.create_session(u["id"])
    got = appmod._pat_or_session_user(_req({"cookie": f"sonar_session={sess}"}))
    assert got and got["id"] == u["id"]


def test_dep_rejects_revoked_expired_scope(authdb):
    u = auth.create_user("a@b.com")
    raw, meta = auth.create_pat(u["id"])
    # mauvais scope -> refusé (default-deny)
    assert appmod._pat_or_session_user(_req(_bearer(raw)), scope="scans:write") is None
    # révoqué -> refusé
    auth.revoke_pat(meta["id"], u["id"])
    assert appmod._pat_or_session_user(_req(_bearer(raw))) is None


def test_dep_rejects_no_or_bad_auth(authdb):
    assert appmod._pat_or_session_user(_req()) is None
    assert appmod._pat_or_session_user(_req({"authorization": "Bearer pas-un-pat"})) is None
    assert appmod._pat_or_session_user(_req({"authorization": "Basic abc"})) is None


# --------------------------------------------------------------------------- #
# DEFAULT-DENY (HTTP) : un PAT ne peut atteindre aucune route d'écriture/admin.
# Ces routes utilisent _current_user (cookie seul) -> sans cookie : 401/403.
# --------------------------------------------------------------------------- #
def test_pat_cannot_reach_write_or_admin_routes(client):
    c, _appmod = client
    u = auth.create_user("a@b.com")
    raw, meta = auth.create_pat(u["id"])
    h = _bearer(raw)  # PAT valide mais AUCUN cookie de session
    assert c.post("/api/domains", json={"domain": "x.com"}, headers=h).status_code == 401
    assert c.delete("/api/domains/whatever", headers=h).status_code == 401
    assert c.post("/api/tokens", json={}, headers=h).status_code == 401        # pas de jeton via jeton
    assert c.delete("/api/tokens/" + meta["id"], headers=h).status_code == 401
    assert c.post("/api/admin/scan-any", json={"enabled": True},
                  headers=h).status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Le secret ne fuit jamais dans les logs
# --------------------------------------------------------------------------- #
def test_pat_never_logged(authdb, caplog):
    u = auth.create_user("a@b.com")
    raw, _ = auth.create_pat(u["id"])
    with caplog.at_level("DEBUG"):
        appmod._pat_or_session_user(_req(_bearer(raw)))
        auth.resolve_pat(raw)
    assert raw not in caplog.text


# --------------------------------------------------------------------------- #
# Étape 3 — les 3 lectures acceptent le PAT ; IDOR HTTP : un PAT ne lit que les
# scans de SON propriétaire ; et le dashboard (cookie) marche toujours.
# --------------------------------------------------------------------------- #
def _save_scan_for(user, target):
    summary = {"score": 80, "grade": "B", "counts": {"low": 1}, "total": 1, "target": target}
    findings = [{"check_id": "hdr-csp", "category": "headers", "severity": "low",
                 "code": "absent", "params": {}}]
    return db.save_scan(target, summary, findings, user_id=user["id"])


def test_read_endpoints_pat_and_idor(client):
    c, _appmod = client
    a = auth.create_user("a@b.com")
    b = auth.create_user("b@b.com")
    raw_a, _ = auth.create_pat(a["id"])
    raw_b, _ = auth.create_pat(b["id"])
    sid_a = _save_scan_for(a, "https://a.example")
    ha, hb = _bearer(raw_a), _bearer(raw_b)

    # Le PAT de A lit son propre scan -> 200
    r = c.get(f"/api/scan/{sid_a}", headers=ha)
    assert r.status_code == 200 and r.json()["target"] == "https://a.example"
    # IDOR : le PAT de B ne lit PAS le scan de A -> 404
    assert c.get(f"/api/scan/{sid_a}", headers=hb).status_code == 404
    # /api/history est cloisonné par propriétaire
    assert any(s["id"] == sid_a for s in c.get("/api/history", headers=ha).json())
    assert all(s["id"] != sid_a for s in c.get("/api/history", headers=hb).json())
    # /api/domains accessible au PAT (lecture)
    assert c.get("/api/domains", headers=ha).status_code == 200
    # Sans aucune auth -> 401 (les routes restent protégées)
    assert c.get(f"/api/scan/{sid_a}").status_code == 401
    assert c.get("/api/history").status_code == 401


def test_read_endpoints_still_accept_session_cookie(client):
    """Non-régression dashboard : la session (cookie) lit toujours les 3 routes."""
    c, _appmod = client
    u = auth.create_user("a@b.com")
    sid = _save_scan_for(u, "https://a.example")
    c.cookies.set("sonar_session", auth.create_session(u["id"]))
    assert c.get("/api/domains").status_code == 200
    assert c.get("/api/history").status_code == 200
    assert c.get(f"/api/scan/{sid}").status_code == 200
