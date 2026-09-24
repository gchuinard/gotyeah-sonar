"""Page 404 : un navigateur reçoit la page aux couleurs de Sonar, l'API garde sa 404 JSON."""

import auth

HTML = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}


def _is_html_404(r) -> bool:
    return (
        r.status_code == 404
        and r.headers["content-type"].startswith("text/html")
        and "Page introuvable" in r.text
    )


def test_browser_gets_custom_404(client):
    c, _ = client
    r = c.get("/cette-page-n-existe-pas", headers=HTML, follow_redirects=False)
    assert _is_html_404(r)
    assert '<meta name="robots" content="noindex"' in r.text
    # Chemins absolus : la page reste stylée même servie sous /a/b/c.
    assert 'href="/static/fonts.css"' in r.text
    # Le middleware d'en-têtes de sécurité s'applique aussi à la page 404.
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_browser_gets_custom_404_on_deep_path(client):
    c, _ = client
    assert _is_html_404(c.get("/a/b/c", headers=HTML, follow_redirects=False))


def test_head_gets_404_too(client):
    c, _ = client
    r = c.head("/inconnue", headers=HTML)
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("text/html")


def test_post_keeps_json_404(client):
    c, _ = client
    r = c.post("/inconnue", headers=HTML)
    assert r.status_code == 404
    assert r.json() == {"detail": "Not Found"}


def test_api_unknown_keeps_json_404(client):
    c, _ = client
    for accept in ("application/json", "*/*", HTML["Accept"]):
        r = c.get("/api/inconnue", headers={"Accept": accept})
        assert r.status_code == 404
        assert r.json() == {"detail": "Not Found"}


def test_non_browser_clients_keep_json_404(client):
    c, _ = client
    for accept in ("application/json", "*/*"):
        r = c.get("/inconnue", headers={"Accept": accept})
        assert r.status_code == 404
        assert r.json() == {"detail": "Not Found"}


def test_excluded_prefixes_keep_json_404(client):
    c, _ = client
    for path in ("/static/absent.css", "/auth/oidc/inconnue", "/api/mcp/inconnue"):
        r = c.get(path, headers=HTML)
        assert r.status_code == 404, path
        assert r.headers["content-type"].startswith("application/json"), path


def test_route_level_json_404_unchanged(client):
    # Les 404 posées par les routes (JSONResponse) ne passent pas par le gestionnaire.
    c, _ = client
    u = auth.create_user("a@b.com")
    c.cookies.set("sonar_session", auth.create_session(u["id"]))
    r = c.get("/api/scan/absent", headers=HTML)
    assert r.status_code == 404
    assert r.json() == {"error": "not found"}


def test_other_statuses_unchanged(client):
    c, _ = client
    r = c.post("/healthz", headers=HTML)
    assert r.status_code == 405
    assert r.json() == {"detail": "Method Not Allowed"}


def test_existing_pages_and_health_intact(client):
    c, _ = client
    r = c.get("/healthz", headers=HTML)
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    r = c.get("/", headers=HTML, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"
    r = c.get("/help/mcp", headers=HTML, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"
    assert c.get("/login", headers=HTML).status_code == 200
    assert c.get("/static/fonts.css").status_code == 200
