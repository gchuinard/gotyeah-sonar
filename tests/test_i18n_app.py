"""Endpoints i18n de la couche web : UI, préférence de langue, re-render archivé."""
from __future__ import annotations

import auth
import db
from scanner.finding import Category, Finding, Severity


def test_i18n_ui_endpoint(client):
    c, _ = client
    r = c.get("/api/i18n/ui?lang=fr")
    assert r.status_code == 200
    body = r.json()
    assert body["lang"] == "fr" and "fr" in body["available"]
    assert body["ui"]["sev_label"]["critical"] == "Critique"
    assert body["ui"]["cat_label"]["zap"] == "Pentest (ZAP)"


def test_me_exposes_lang(client):
    c, _ = client
    u = auth.create_user("lang@b.com")
    c.cookies.set("sonar_session", auth.create_session(u["id"]))
    me = c.get("/api/me").json()
    assert me["lang"] == "fr" and "fr" in me["available_langs"]


def test_set_lang_invalid_400(client):
    c, _ = client
    assert c.post("/api/lang", json={"lang": "xx"}).status_code == 400


def test_set_lang_valid_sets_cookie(client):
    c, _ = client
    r = c.post("/api/lang", json={"lang": "fr"})
    assert r.status_code == 200 and r.json()["lang"] == "fr"
    assert c.cookies.get("sonar_lang") == "fr"


def test_scan_detail_renders_findings(client):
    c, _ = client
    u = auth.create_user("hist@b.com")
    c.cookies.set("sonar_session", auth.create_session(u["id"]))
    # Un scan archivé avec un finding (forme legacy → passthrough au rendu).
    summary = {"score": 92, "grade": "A", "counts": {}, "total": 1, "target": "https://x"}
    f = Finding("hdr-csp", Category.HEADERS, Severity.MEDIUM, "Titre archivé", "det", "reco").as_dict()
    sid = db.save_scan("https://x", summary, [f], user_id=u["id"])

    data = c.get(f"/api/scan/{sid}?lang=fr").json()
    assert data["lang"] == "fr"
    assert data["findings"][0]["title"] == "Titre archivé"
    assert "remediation" in data["findings"][0]
