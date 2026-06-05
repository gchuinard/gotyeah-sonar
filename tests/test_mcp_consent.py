"""MCP distant — Ph.2 : consentement adossé à la session + flux OAuth end-to-end.

On charge l'app RÉELLE avec le MCP distant activé (SONAR_MCP_REMOTE=on) et on exerce :
  • la page de consentement (session requise, bilingue, affiche client + scope) ;
  • le threading `next` à travers le lien magique (avec garde anti open-redirect) ;
  • le parcours OAuth COMPLET en HTTP : DCR → /authorize → consentement → /token
    (PKCE S256) → un access token qui est ACCEPTÉ sur /mcp (et refusé sans lui).

Le SDK `mcp` est requis ; absent, le module est ignoré.
"""
import base64
import hashlib
import importlib
import secrets
from urllib.parse import parse_qs, urlparse

import pytest

pytest.importorskip("mcp")

from fastapi.testclient import TestClient

import auth
import db

CALLBACK = "https://claude.ai/api/mcp/auth_callback"
BASE = "https://sonar.test"


@pytest.fixture
def remote(tmp_path, monkeypatch):
    """App réelle avec MCP distant ACTIVÉ, base temporaire. Restaure l'état éteint après."""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "sonar.db")
    monkeypatch.setenv("SONAR_MCP_REMOTE", "on")
    monkeypatch.setenv("SONAR_BASE_URL", BASE)
    monkeypatch.setenv("SONAR_COOKIE_SECURE", "false")
    monkeypatch.setenv("SONAR_OPEN_REGISTRATION", "true")
    monkeypatch.delenv("SONAR_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("BREVO_API_KEY", raising=False)

    import app as appmod
    importlib.reload(appmod)  # ré-exécute le bloc _REMOTE_* avec le flag on
    assert appmod._REMOTE_PROVIDER is not None
    with TestClient(appmod.app) as c:
        yield c, appmod
    # rétablit l'état désactivé pour les tests suivants
    monkeypatch.delenv("SONAR_MCP_REMOTE", raising=False)
    importlib.reload(appmod)


def _login(c, email="owner@example.com"):
    """Crée un utilisateur + une session et pose le cookie sur le client."""
    user = auth.get_or_create_user(email)
    c.cookies.set("sonar_session", auth.create_session(user["id"]))
    return user


def _seed_pending(appmod, *, redirect=CALLBACK, state="st-1", client_name="Claude"):
    """Enregistre un client + une demande d'autorisation en attente, renvoie rid."""
    from mcp_remote import store
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyUrl

    store.save_client(OAuthClientInformationFull(
        client_id="cid-1", redirect_uris=[AnyUrl(redirect)], client_name=client_name))
    return store.create_pending(
        client_id="cid-1", redirect_uri=redirect, redirect_uri_explicit=True,
        code_challenge="chal", scopes=["scans:read"], state=state, resource=f"{BASE}/mcp")


# --------------------------------------------------------------------------- #
# Page de consentement
# --------------------------------------------------------------------------- #
def test_consent_without_session_redirects_to_login(remote):
    c, appmod = remote
    rid = _seed_pending(appmod)
    r = c.get(f"/mcp/consent?rid={rid}", follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith("/login?next=")
    assert "mcp%2Fconsent" in loc and rid in loc  # retour encodé vers le consentement


def test_consent_with_session_shows_client_and_scope(remote):
    c, appmod = remote
    _login(c, "owner@example.com")
    rid = _seed_pending(appmod, client_name="Claude")
    r = c.get(f"/mcp/consent?rid={rid}")
    assert r.status_code == 200
    body = r.text
    assert "Claude" in body                 # nom du client (DCR)
    assert "scans:read" in body             # scope lecture seule affiché
    assert "owner@example.com" in body      # qui est connecté
    assert rid in body                       # rid dans le formulaire


def test_consent_unknown_rid_is_expired_page(remote):
    c, appmod = remote
    _login(c)
    r = c.get("/mcp/consent?rid=does-not-exist")
    assert r.status_code == 400


def test_consent_approve_redirects_with_code(remote):
    c, appmod = remote
    user = _login(c)
    rid = _seed_pending(appmod, state="xyz")
    r = c.post("/mcp/consent", data={"rid": rid, "action": "approve"}, follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith(CALLBACK)
    q = parse_qs(urlparse(loc).query)
    assert q["state"] == ["xyz"] and q.get("code")
    # le code émis est bien lié au propriétaire
    info = appmod._REMOTE_PROVIDER  # provider
    import asyncio
    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyUrl
    client = OAuthClientInformationFull(client_id="cid-1", redirect_uris=[AnyUrl(CALLBACK)])
    authcode = asyncio.run(info.load_authorization_code(client, q["code"][0]))
    assert authcode is not None and authcode.subject == user["id"]


def test_consent_deny_redirects_with_error(remote):
    c, appmod = remote
    _login(c)
    rid = _seed_pending(appmod, state="zzz")
    r = c.post("/mcp/consent", data={"rid": rid, "action": "deny"}, follow_redirects=False)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["error"] == ["access_denied"] and q["state"] == ["zzz"]


def test_consent_post_without_session_redirects_login(remote):
    c, appmod = remote
    rid = _seed_pending(appmod)
    r = c.post("/mcp/consent", data={"rid": rid, "action": "approve"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/login")


# --------------------------------------------------------------------------- #
# Threading `next` à travers le lien magique (anti open-redirect)
# --------------------------------------------------------------------------- #
def test_verify_redirects_to_safe_next(remote):
    c, appmod = remote
    auth.get_or_create_user("u@example.com")
    raw = auth.request_login_link("u@example.com", "1.2.3.4")
    r = c.get(f"/auth/verify?token={raw}&next=/mcp/consent?rid=abc", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/mcp/consent?rid=abc"   # retour same-origin honoré


def test_verify_rejects_open_redirect(remote):
    c, appmod = remote
    auth.get_or_create_user("v@example.com")
    raw = auth.request_login_link("v@example.com", "1.2.3.4")
    r = c.get(f"/auth/verify?token={raw}&next=https://evil.com/x", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/"   # next hostile ignoré -> accueil


# --------------------------------------------------------------------------- #
# Parcours OAuth COMPLET en HTTP (DCR -> authorize -> consent -> token -> /mcp)
# --------------------------------------------------------------------------- #
def test_full_oauth_flow_end_to_end(remote):
    c, appmod = remote
    user = _login(c, "e2e@example.com")

    # 1) DCR : claude.ai s'enregistre — il demande offline_access (refresh token) ;
    #    notre AS doit l'accepter (ce qui avait initialement cassé la connexion réelle).
    reg = c.post("/register", json={
        "redirect_uris": [CALLBACK],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "scans:read offline_access",
    })
    assert reg.status_code in (200, 201), reg.text
    client_id = reg.json()["client_id"]

    # 2) PKCE
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

    # 3) /authorize -> redirige vers notre page de consentement (rid)
    authz = c.get("/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": CALLBACK,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "scope": "scans:read offline_access", "state": "s-e2e", "resource": f"{BASE}/mcp",
    }, follow_redirects=False)
    assert authz.status_code in (302, 307), authz.text
    rid = parse_qs(urlparse(authz.headers["location"]).query)["rid"][0]

    # 4) consentement (session présente) -> approuve -> code
    approve = c.post("/mcp/consent", data={"rid": rid, "action": "approve"}, follow_redirects=False)
    assert approve.status_code == 302
    code = parse_qs(urlparse(approve.headers["location"]).query)["code"][0]

    # 5) /token : échange code + verifier PKCE -> access token
    tok = c.post("/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": CALLBACK, "client_id": client_id, "code_verifier": verifier,
    })
    assert tok.status_code == 200, tok.text
    access = tok.json()["access_token"]
    assert access and tok.json()["token_type"].lower() == "bearer"

    # 6) /mcp : refuse sans token, accepte AVEC (auth de bout en bout validée)
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert c.post("/mcp", headers=headers, json=ping).status_code == 401
    with_tok = c.post("/mcp", headers={**headers, "Authorization": f"Bearer {access}"}, json=ping)
    assert with_tok.status_code != 401, with_tok.text   # token accepté (≠ 401)
