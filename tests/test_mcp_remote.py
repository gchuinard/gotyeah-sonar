"""MCP distant — Ph.0 (spike) : plomberie transport + métadonnées OAuth.

On vérifie UNIQUEMENT ce que claude.ai web attend pour amorcer la découverte :
  • la métadonnée de ressource (RFC 9728) est servie ;
  • /mcp exige une auth (401) et pointe vers cette métadonnée ;
  • monter le transport ne casse pas les routes Sonar ;
  • le coupe-circuit (SONAR_MCP_REMOTE) est bien opt-in / éteint par défaut.

Aucun token n'est encore accepté (le serveur d'autorisation maison arrive plus
tard) : ces tests ne couvrent donc PAS l'émission de jetons ni les outils.

Le SDK `mcp` est requis pour ce module ; absent, le module est ignoré.
"""
import pytest

pytest.importorskip("mcp")

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.testclient import TestClient

from mcp_remote.remote import build_remote, remote_enabled

_MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
_PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


def _combined_app(base: str = "https://sonar.test"):
    """Reproduit le câblage de app.py : routes hôtes + mount MCP en dernier +
    lifespan qui fait tourner le session manager du transport."""
    mcp, sub, _provider = build_remote(base)

    @asynccontextmanager
    async def lifespan(app):
        async with mcp.session_manager.run():
            yield

    app = FastAPI(lifespan=lifespan)

    @app.get("/login")
    async def login():
        return PlainTextResponse("login")

    app.mount("/", sub)  # monté EN DERNIER → fallback pour /mcp + /.well-known
    return app


def test_protected_resource_metadata_served():
    """RFC 9728 : /.well-known/oauth-protected-resource/mcp annonce la ressource
    et le scope scans:read."""
    with TestClient(_combined_app()) as c:
        r = c.get("/.well-known/oauth-protected-resource/mcp")
        assert r.status_code == 200
        body = r.json()
        assert body["resource"].rstrip("/") == "https://sonar.test/mcp"
        assert "scans:read" in body["scopes_supported"]
        # un serveur d'autorisation est annoncé (le nôtre, maison)
        assert body["authorization_servers"]


def test_mcp_requires_auth_and_advertises_metadata():
    """Sans token : 401 + WWW-Authenticate pointant vers la métadonnée de ressource
    (c'est le point de départ de la découverte OAuth de claude.ai)."""
    with TestClient(_combined_app()) as c:
        r = c.post("/mcp", headers=_MCP_HEADERS, json=_PING)
        assert r.status_code == 401
        www = r.headers.get("www-authenticate", "")
        assert "resource_metadata=" in www
        assert "oauth-protected-resource" in www


def test_host_routes_survive_the_mount():
    """Monter le transport en fallback ne masque pas les routes Sonar."""
    with TestClient(_combined_app()) as c:
        assert c.get("/login").status_code == 200


def test_remote_disabled_by_default(monkeypatch):
    """Surface publique → opt-in strict : seul 'on/1/true/yes' active."""
    monkeypatch.delenv("SONAR_MCP_REMOTE", raising=False)
    assert remote_enabled() is False
    monkeypatch.setenv("SONAR_MCP_REMOTE", "off")
    assert remote_enabled() is False
    monkeypatch.setenv("SONAR_MCP_REMOTE", "on")
    assert remote_enabled() is True


def test_app_module_does_not_mount_remote_when_disabled():
    """app.py importé sans SONAR_MCP_REMOTE : aucun transport monté (kill-switch)."""
    import app as appmod

    assert getattr(appmod, "_REMOTE_APP", "MISSING") is None
    with TestClient(appmod.app) as c:
        # /mcp n'existe pas → 404 (et surtout pas 401 : rien n'est monté)
        assert c.post("/mcp", headers=_MCP_HEADERS, json=_PING).status_code == 404
