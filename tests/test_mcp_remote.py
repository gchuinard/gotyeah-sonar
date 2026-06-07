"""Smoke tests du MCP distant (auth déléguée à un IdP OIDC via l'OIDCProxy de FastMCP).

Sans réseau : coupe-circuit (opt-in), dérivation de l'URL de discovery, fail-soft si la
config OIDC est incomplète, et non-montage quand le MCP distant est éteint. Le flux OAuth
complet (DCR claude.ai → login IdP → token → /mcp) est validé manuellement (cf README §MCP).
"""
from __future__ import annotations

import pytest

from mcp_remote.remote import build_remote, oidc_config_url, remote_enabled

_OIDC_ENV = (
    "SONAR_OIDC_CONFIG_URL",
    "SONAR_OIDC_ISSUER",
    "SONAR_OIDC_CLIENT_ID",
    "SONAR_OIDC_CLIENT_SECRET",
)

_MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
_PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


def test_remote_enabled_opt_in(monkeypatch):
    for on in ("on", "1", "true", "YES", "On"):
        monkeypatch.setenv("SONAR_MCP_REMOTE", on)
        assert remote_enabled() is True
    for off in ("", "off", "0", "no", "false", "nope"):
        monkeypatch.setenv("SONAR_MCP_REMOTE", off)
        assert remote_enabled() is False
    monkeypatch.delenv("SONAR_MCP_REMOTE", raising=False)
    assert remote_enabled() is False


def test_oidc_config_url_prefers_explicit(monkeypatch):
    monkeypatch.setenv(
        "SONAR_OIDC_CONFIG_URL", "https://idp.example.com/.well-known/openid-configuration"
    )
    monkeypatch.setenv("SONAR_OIDC_ISSUER", "https://autre.example.com")
    assert oidc_config_url() == "https://idp.example.com/.well-known/openid-configuration"


def test_oidc_config_url_derived_from_issuer(monkeypatch):
    monkeypatch.delenv("SONAR_OIDC_CONFIG_URL", raising=False)
    monkeypatch.setenv("SONAR_OIDC_ISSUER", "https://idp.example.com/")  # slash final toléré
    assert oidc_config_url() == "https://idp.example.com/.well-known/openid-configuration"


def test_oidc_config_url_empty_when_unset(monkeypatch):
    for k in ("SONAR_OIDC_CONFIG_URL", "SONAR_OIDC_ISSUER"):
        monkeypatch.delenv(k, raising=False)
    assert oidc_config_url() == ""


def test_build_remote_requires_full_oidc_config(monkeypatch):
    """Config OIDC incomplète → RuntimeError. app.py enveloppe l'appel (fail-soft :
    le MCP distant est simplement désactivé, le reste du site démarre)."""
    for k in _OIDC_ENV:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(RuntimeError):
        build_remote("https://sonar.example.com")


def test_app_does_not_mount_remote_when_disabled():
    """app.py importé sans SONAR_MCP_REMOTE : aucun transport monté (kill-switch) →
    /mcp n'existe pas (404, surtout pas 401)."""
    from starlette.testclient import TestClient

    import app as appmod

    assert getattr(appmod, "_REMOTE_APP", "MISSING") is None
    with TestClient(appmod.app) as c:
        assert c.post("/mcp", headers=_MCP_HEADERS, json=_PING).status_code == 404
