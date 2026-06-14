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


def _req(headers=None, peer="9.9.9.9"):
    from starlette.requests import Request
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "GET", "path": "/", "query_string": b"",
                    "headers": raw, "client": (peer, 12345)})


def test_client_ip_anti_spoof(monkeypatch):
    """#3 — on ne fait JAMAIS confiance à la 1ʳᵉ valeur XFF (falsifiable par le client)."""
    import app
    monkeypatch.delenv("SONAR_TRUSTED_PROXY_HOPS", raising=False)   # défaut 1 (NPM)
    # `1.2.3.4` est forgé par le client ; `5.6.7.8` est ajouté par NPM (le vrai peer).
    assert app._client_ip(_req({"x-forwarded-for": "1.2.3.4, 5.6.7.8"})) == "5.6.7.8"
    # 2 hops (Cloudflare + NPM) : la vraie IP est l'avant-dernière.
    monkeypatch.setenv("SONAR_TRUSTED_PROXY_HOPS", "2")
    assert app._client_ip(_req({"x-forwarded-for": "evil, vrai, cf"})) == "vrai"
    # Pas de XFF → IP du peer direct.
    monkeypatch.delenv("SONAR_TRUSTED_PROXY_HOPS", raising=False)
    assert app._client_ip(_req({})) == "9.9.9.9"
    # hops=0 (exposition directe) → XFF ignoré.
    monkeypatch.setenv("SONAR_TRUSTED_PROXY_HOPS", "0")
    assert app._client_ip(_req({"x-forwarded-for": "1.2.3.4"})) == "9.9.9.9"


def test_scan_stream_rate_limited(client, monkeypatch):
    """#4 — l'endpoint de scan web applique le rate-limit (429), comme le MCP."""
    import sqlite3
    import auth
    import db
    c, _ = client
    u = auth.create_user("a@b.com")
    d = auth.add_domain(u["id"], "ex.com")
    with sqlite3.connect(db.DB_PATH) as conn:        # vérifie le domaine sans passer par le DNS
        conn.execute("UPDATE verified_domains SET verified=1 WHERE id=?", (d["id"],))
    c.cookies.set("sonar_session", auth.create_session(u["id"]))
    monkeypatch.setattr(auth, "scan_rate_ok", lambda uid: False)
    r = c.get("/api/scan/stream?target=ex.com")
    assert r.status_code == 429 and r.json()["code"] == "rate_limited"


def test_docs_disabled(client):
    """/docs, /redoc et /openapi.json ne doivent pas être servis (fuite de surface API)."""
    c, _ = client
    assert c.get("/docs").status_code == 404
    assert c.get("/openapi.json").status_code == 404


def test_security_headers(client):
    """#5 — l'app pose ses en-têtes de sécurité (anti-clickjacking) sur ses réponses."""
    c, _ = client
    r = c.get("/login")
    assert r.headers.get("x-frame-options") == "DENY"
    assert r.headers.get("x-content-type-options") == "nosniff"
    csp = r.headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp
    assert "unpkg.com" not in csp                    # #6 — plus de CDN dans la CSP
    assert r.headers.get("referrer-policy")


def test_vue_self_hosted(client):
    """#6 — Vue est servi en local (/static), plus depuis un CDN tiers."""
    c, _ = client
    r = c.get("/static/vendor/vue.global.prod.js")
    assert r.status_code == 200 and "Vue" in r.text[:300]


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
