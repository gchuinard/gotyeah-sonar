"""Sonde de santé publique `/healthz` + comportement de redirection de la racine."""


def test_healthz_ok_without_auth(client):
    # 200 + JSON, sans cookie de session : c'est la cible à donner à un monitor externe.
    c, _ = client
    r = c.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_root_redirects_to_login_when_unauthenticated(client):
    # Documente le 302 « normal » : la racine renvoie vers /login tant qu'on n'a pas de session.
    c, _ = client
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/login"
