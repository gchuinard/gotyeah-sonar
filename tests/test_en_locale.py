"""Locale anglaise : prouve « ajouter une langue = déposer des fichiers, zéro code ».

L'anglais a été ajouté en déposant `locales/ui/en.json` + `content/checks/*.en.yaml`,
sans toucher au code. On vérifie : la langue est découverte, le chrome et le contenu
maison sont rendus en anglais, la couverture EST complète (pas de repli FR silencieux),
et les endpoints acceptent `en`.
"""
from __future__ import annotations

import scenarios

import auth
from scanner.finding import Category, Finding, Severity
from scanner.i18n import loader, render


def test_en_is_discovered():
    assert "en" in loader.available_langs()


def test_ui_chrome_in_english():
    ui = render.render_ui("en")
    assert ui["sev_label"]["critical"] == "Critical"
    assert ui["cat_label"]["headers"] == "HTTP headers"
    assert ui["remediation"]["copy_prompt"] == "Copy AI prompt"


def test_finding_renders_english():
    f = Finding("hdr-csp", Category.HEADERS, Severity.MEDIUM, code="absent").as_dict()
    en = render.render_finding(f, "en")
    fr = render.render_finding(f, "fr")
    assert en["title"] and en["title"] != fr["title"]            # bien rendu, et distinct du FR
    assert en["remediation"]["steps"]                            # remédiation traduite présente


def test_en_coverage_complete_for_house_checks():
    cat_en = loader.content_catalog("en")
    missing = set()
    for findings in scenarios.run_all().values():
        for f in findings:
            if f.get("code") and not f.get("catalog"):           # maison structuré
                if ("checks", f["check_id"], f["code"]) not in cat_en:
                    missing.add((f["check_id"], f["code"]))
    assert not missing, f"codes maison sans entrée EN (repli FR) : {sorted(missing)}"


def test_set_lang_accepts_en(client):
    c, _ = client
    r = c.post("/api/lang", json={"lang": "en"})
    assert r.status_code == 200 and r.json()["lang"] == "en"
    ui = c.get("/api/i18n/ui?lang=en").json()
    assert ui["lang"] == "en" and "en" in ui["available"]
    assert ui["ui"]["sev_label"]["critical"] == "Critical"


def test_me_lists_en(client):
    c, _ = client
    u = auth.create_user("en@b.com")
    c.cookies.set("sonar_session", auth.create_session(u["id"]))
    assert "en" in c.get("/api/me").json()["available_langs"]
