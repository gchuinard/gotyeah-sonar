"""Auth par PAT (Étape 2) : la dépendance _pat_or_session_user (concept require_pat).

Vérifie : cookie OU Bearer PAT acceptés ; PAT révoqué/expiré/mauvais scope refusé ;
DEFAULT-DENY (un PAT ne peut atteindre aucune route d'écriture/admin) ; jeton jamais
journalisé. Le branchement effectif sur les 3 lectures + l'IDOR HTTP sont à l'Étape 3.
"""
import app as appmod
import auth
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
