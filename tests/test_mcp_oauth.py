"""MCP distant — Ph.1 : serveur d'autorisation OAuth maison (store + provider).

On exerce TOUTE la machine en isolation (sans HTTP) : DCR, authorize→consentement→
code lié au propriétaire, échange code→jetons (single-use), rotation du refresh,
résolution/révocation, expiration, scope, et propagation du `subject` (anti-IDOR).

La vérif PKCE S256 et le match redirect_uri sont faits par le SDK dans le handler
/token (testés ailleurs) ; ici on vérifie surtout que le `code_challenge` est stocké
et restitué intact pour que cette vérif puisse aboutir.
"""
import time

import pytest

pytest.importorskip("mcp")

from urllib.parse import parse_qs, urlparse

from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, TokenError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

import auth
from mcp_remote import store
from mcp_remote.provider import SonarOAuthProvider

BASE = "https://sonar.test"
CALLBACK = "https://claude.ai/api/mcp/auth_callback"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"  # PKCE S256 challenge (opaque ici)


@pytest.fixture
def oauth(authdb):
    """Base d'auth + tables OAuth + un provider + un utilisateur propriétaire."""
    store.init_store()
    user = auth.get_or_create_user("owner@example.com")
    return SonarOAuthProvider(BASE), user


def _client(client_id="client-1", redirect=CALLBACK):
    return OAuthClientInformationFull(client_id=client_id, redirect_uris=[AnyUrl(redirect)])


def _params(redirect=CALLBACK, scopes=None, state="xyz"):
    return AuthorizationParams(
        state=state,
        scopes=scopes,
        code_challenge=CHALLENGE,
        redirect_uri=AnyUrl(redirect),
        redirect_uri_provided_explicitly=True,
        resource=f"{BASE}/mcp",
    )


async def _full_grant(provider, user, client=None):
    """Déroule authorize→consent→exchange et renvoie (client, OAuthToken)."""
    client = client or _client()
    await provider.register_client(client)
    consent = await provider.authorize(client, _params())
    rid = parse_qs(urlparse(consent).query)["rid"][0]
    redirect = provider.complete_consent(rid, user["id"])
    code = parse_qs(urlparse(redirect).query)["code"][0]
    authcode = await provider.load_authorization_code(client, code)
    tokens = await provider.exchange_authorization_code(client, authcode)
    return client, tokens


# --------------------------------------------------------------------------- #
# DCR
# --------------------------------------------------------------------------- #
async def test_register_and_get_client(oauth):
    provider, _ = oauth
    client = _client("abc")
    assert await provider.get_client("abc") is None
    await provider.register_client(client)
    got = await provider.get_client("abc")
    assert got is not None and str(got.redirect_uris[0]) == CALLBACK


# --------------------------------------------------------------------------- #
# authorize → consentement → code
# --------------------------------------------------------------------------- #
async def test_authorize_redirects_to_consent_no_code_yet(oauth):
    provider, _ = oauth
    client = _client()
    await provider.register_client(client)
    consent = await provider.authorize(client, _params())
    # redirige vers NOTRE page de consentement, pas (encore) vers le client
    assert consent.startswith(f"{BASE}/mcp/consent?rid=")
    assert CALLBACK not in consent


async def test_consent_mints_owner_bound_code(oauth):
    provider, user = oauth
    client = _client()
    await provider.register_client(client)
    consent = await provider.authorize(client, _params())
    rid = parse_qs(urlparse(consent).query)["rid"][0]
    redirect = provider.complete_consent(rid, user["id"])
    q = parse_qs(urlparse(redirect).query)
    assert redirect.startswith(CALLBACK)
    assert q["state"] == ["xyz"]                       # state rendu tel quel
    code = q["code"][0]
    authcode = await provider.load_authorization_code(client, code)
    assert authcode.subject == user["id"]              # code lié au propriétaire
    assert authcode.code_challenge == CHALLENGE        # PKCE préservé pour le SDK
    assert authcode.scopes == ["scans:read"]


async def test_consent_unknown_or_expired_rid_returns_none(oauth):
    provider, user = oauth
    assert provider.complete_consent("nope", user["id"]) is None


async def test_pending_is_single_use(oauth):
    provider, user = oauth
    client = _client()
    await provider.register_client(client)
    consent = await provider.authorize(client, _params())
    rid = parse_qs(urlparse(consent).query)["rid"][0]
    assert provider.complete_consent(rid, user["id"]) is not None
    assert provider.complete_consent(rid, user["id"]) is None  # consommé


async def test_authorize_rejects_unknown_scope(oauth):
    provider, _ = oauth
    client = _client()
    await provider.register_client(client)
    with pytest.raises(AuthorizeError):
        await provider.authorize(client, _params(scopes=["scans:read", "scans:write"]))


async def test_authorize_accepts_offline_access(oauth):
    """claude.ai demande `offline_access` (refresh token) : doit être toléré, pas rejeté."""
    provider, _ = oauth
    client = _client()
    await provider.register_client(client)
    consent = await provider.authorize(client, _params(scopes=["scans:read", "offline_access"]))
    assert consent.startswith(f"{BASE}/mcp/consent?rid=")


# --------------------------------------------------------------------------- #
# code → jetons (single-use)
# --------------------------------------------------------------------------- #
async def test_exchange_code_issues_tokens(oauth):
    provider, user = oauth
    client, tokens = await _full_grant(provider, user)
    assert tokens.access_token and tokens.refresh_token
    assert tokens.token_type == "Bearer"
    assert tokens.scope == "scans:read"
    at = await provider.load_access_token(tokens.access_token)
    assert at is not None and at.subject == user["id"] and "scans:read" in at.scopes


async def test_code_is_single_use(oauth):
    provider, user = oauth
    client = _client()
    await provider.register_client(client)
    consent = await provider.authorize(client, _params())
    rid = parse_qs(urlparse(consent).query)["rid"][0]
    code = parse_qs(urlparse(provider.complete_consent(rid, user["id"])).query)["code"][0]
    authcode = await provider.load_authorization_code(client, code)
    await provider.exchange_authorization_code(client, authcode)        # 1er échange OK
    assert await provider.load_authorization_code(client, code) is None  # consommé
    with pytest.raises(TokenError):
        await provider.exchange_authorization_code(client, authcode)     # rejeu refusé


async def test_code_wrong_client_not_loaded(oauth):
    provider, user = oauth
    client = _client("c-a")
    await provider.register_client(client)
    consent = await provider.authorize(client, _params())
    rid = parse_qs(urlparse(consent).query)["rid"][0]
    code = parse_qs(urlparse(provider.complete_consent(rid, user["id"])).query)["code"][0]
    other = _client("c-b")
    assert await provider.load_authorization_code(other, code) is None   # autre client => invisible


async def test_expired_code_not_loaded(oauth):
    provider, user = oauth
    client = _client()
    await provider.register_client(client)
    consent = await provider.authorize(client, _params())
    rid = parse_qs(urlparse(consent).query)["rid"][0]
    code = parse_qs(urlparse(provider.complete_consent(rid, user["id"])).query)["code"][0]
    with auth._conn() as conn:  # force l'expiration
        conn.execute("UPDATE oauth_codes SET expires_at = ?", (time.time() - 1,))
    assert await provider.load_authorization_code(client, code) is None


# --------------------------------------------------------------------------- #
# refresh rotatif
# --------------------------------------------------------------------------- #
async def test_refresh_rotation_revokes_old_pair(oauth):
    provider, user = oauth
    client, tokens = await _full_grant(provider, user)
    old_access, old_refresh = tokens.access_token, tokens.refresh_token

    rt = await provider.load_refresh_token(client, old_refresh)
    assert rt is not None and rt.subject == user["id"]
    new = await provider.exchange_refresh_token(client, rt, ["scans:read"])

    assert new.access_token != old_access and new.refresh_token != old_refresh
    # l'ancien couple est révoqué (rotation)
    assert await provider.load_access_token(old_access) is None
    assert await provider.load_refresh_token(client, old_refresh) is None
    # le nouvel access est valide et toujours lié au même propriétaire
    at = await provider.load_access_token(new.access_token)
    assert at is not None and at.subject == user["id"]


# --------------------------------------------------------------------------- #
# résolution / révocation / expiration des access tokens
# --------------------------------------------------------------------------- #
async def test_revoke_access_cascades_to_refresh(oauth):
    provider, user = oauth
    client, tokens = await _full_grant(provider, user)
    at = await provider.load_access_token(tokens.access_token)
    await provider.revoke_token(at)
    assert await provider.load_access_token(tokens.access_token) is None
    assert await provider.load_refresh_token(client, tokens.refresh_token) is None  # apparié révoqué


async def test_revoke_refresh_cascades_to_access(oauth):
    provider, user = oauth
    client, tokens = await _full_grant(provider, user)
    rt = await provider.load_refresh_token(client, tokens.refresh_token)
    await provider.revoke_token(rt)
    assert await provider.load_refresh_token(client, tokens.refresh_token) is None
    assert await provider.load_access_token(tokens.access_token) is None


async def test_expired_access_not_resolved(oauth):
    provider, user = oauth
    _, tokens = await _full_grant(provider, user)
    with auth._conn() as conn:
        conn.execute("UPDATE oauth_tokens SET expires_at = ? WHERE kind = 'access'", (time.time() - 1,))
    assert await provider.load_access_token(tokens.access_token) is None


async def test_unknown_access_token_is_none(oauth):
    provider, _ = oauth
    assert await provider.load_access_token("sonar_nope") is None


# --------------------------------------------------------------------------- #
# propagation du subject (anti-IDOR) : deux propriétaires => deux subjects
# --------------------------------------------------------------------------- #
async def test_subject_isolation_between_owners(oauth):
    provider, user_a = oauth
    user_b = auth.get_or_create_user("other@example.com")
    _, tok_a = await _full_grant(provider, user_a, _client("ca"))
    _, tok_b = await _full_grant(provider, user_b, _client("cb"))
    at_a = await provider.load_access_token(tok_a.access_token)
    at_b = await provider.load_access_token(tok_b.access_token)
    assert at_a.subject == user_a["id"] and at_b.subject == user_b["id"]
    assert at_a.subject != at_b.subject


# --------------------------------------------------------------------------- #
# Compat claude.ai : le serveur d'autorisation, une fois branché dans FastMCP,
# annonce PKCE S256 (exigence dure) + tous les endpoints attendus.
# --------------------------------------------------------------------------- #
def test_as_metadata_is_claude_compatible():
    # On teste la VRAIE config de prod (build_remote), pas une reconstruction inline.
    from starlette.testclient import TestClient

    from mcp_remote.remote import build_remote

    mcp, app, _provider = build_remote(BASE)
    with TestClient(app) as c:
        md = c.get("/.well-known/oauth-authorization-server").json()
    assert md["code_challenge_methods_supported"] == ["S256"]   # PKCE S256 obligatoire
    assert "scans:read" in md["scopes_supported"]
    assert "offline_access" in md["scopes_supported"]           # toléré pour le refresh
    for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"):
        assert md.get(key), f"endpoint manquant : {key}"
    assert set(md["grant_types_supported"]) == {"authorization_code", "refresh_token"}


# --------------------------------------------------------------------------- #
# metadata_documents : les métadonnées CORRIGÉES servies en prod (issuer sans
# slash final + mode client public "none"). Sans ça, claude.ai rejette la
# métadonnée (validation RFC 8414 stricte) et n'enregistre jamais de client.
# --------------------------------------------------------------------------- #
def test_metadata_documents_claude_interop():
    from mcp_remote.remote import metadata_documents

    as_meta, pr_meta = metadata_documents(BASE)

    # Défaut #1 : issuer / authorization_servers SANS slash final (pydantic en ajoute).
    assert as_meta["issuer"] == BASE
    assert not as_meta["issuer"].endswith("/")
    assert pr_meta["authorization_servers"] == [BASE]

    # Client PUBLIC (PKCE sans secret) : "none" doit être annoncé.
    assert "none" in as_meta["token_endpoint_auth_methods_supported"]

    # Cohérence ressource / scope (anti-régression).
    assert pr_meta["resource"] == f"{BASE}/mcp"
    assert as_meta["code_challenge_methods_supported"] == ["S256"]
