"""Smoke test de la couche web : l'app s'importe et expose ses routes."""
from fastapi import FastAPI


def test_app_and_routes():
    import app
    assert isinstance(app.app, FastAPI)
    paths = {r.path for r in app.app.routes}
    assert {"/", "/api/scan/stream", "/api/history"} <= paths


def test_sse_format():
    import app
    out = app._sse("finding", {"a": 1})
    assert out.startswith("event: finding\n")
    assert "data: " in out and out.endswith("\n\n")


def test_login_message_adapts_to_registration_mode(client, monkeypatch):
    """Inscription ouverte → message direct (un lien EST toujours envoyé) ; invite-only →
    message générique anti-énumération (ne révèle pas si le compte existe)."""
    c, _ = client
    # le fixture `client` active SONAR_OPEN_REGISTRATION=true
    r = c.post("/api/auth/request", json={"email": "new@b.com"})
    assert r.status_code == 200 and "vient d'être envoyé à cet email" in r.json()["message"]
    # invite-only → on retombe sur le message générique
    monkeypatch.setenv("SONAR_OPEN_REGISTRATION", "false")
    r = c.post("/api/auth/request", json={"email": "ghost@b.com"})
    assert "Si un compte existe" in r.json()["message"]


def test_help_mcp_page(client):
    """Page d'aide MCP : login requis (302) puis 200 avec l'URL d'instance injectée."""
    import auth
    c, _ = client
    r = c.get("/help/mcp", follow_redirects=False)
    assert r.status_code == 302 and "/login" in r.headers["location"]
    u = auth.create_user("a@b.com")
    c.cookies.set("sonar_session", auth.create_session(u["id"]))
    r2 = c.get("/help/mcp")
    assert r2.status_code == 200
    assert "__SONAR_HELP_BASE__" not in r2.text   # placeholder bien remplacé
    assert "/mcp" in r2.text and "sonar_mcp" in r2.text
