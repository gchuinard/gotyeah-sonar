"""Couche de présentation i18n : rendu, interpolation, chaîne de fallback, UI.

On monte un catalogue temporaire (fr + en partiel) pour prouver que :
  - le rendu interpole `params`/`evidence` sans toucher aux accolades de code ;
  - la chaîne de fallback langue→fr→source_text→défaut est respectée ;
  - ajouter une langue = déposer des fichiers (zéro code).
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from scanner import i18n
from scanner.finding import Category, Finding, Severity
from scanner.i18n import loader


@pytest.fixture
def temp_catalog(tmp_path, monkeypatch):
    content = tmp_path / "content"
    (content / "checks").mkdir(parents=True)
    (content / "zap").mkdir()
    ui = tmp_path / "locales" / "ui"
    ui.mkdir(parents=True)

    (content / "checks" / "demo.fr.yaml").write_text(textwrap.dedent("""\
        hdr-csp:
          absent:
            title: "CSP absent sur {host}"
            detail: "Aucune CSP. evidence={evidence}"
            recommendation: "Ajoute une CSP, vise `default-src 'self'`."
            explanation: "La CSP est une liste blanche."
            why: "Sans elle, le XSS s'exploite sans garde-fou."
            steps:
              - "Pose une CSP sur {host}."
              - "Snippet nginx : add_header CSP \\"default-src 'self'\\" always;"
            stacks:
              nginx: "add_header Content-Security-Policy \\"default-src 'self'\\" always;"
              nextjs: "headers(): { key: 'Content-Security-Policy', value: '...' }"
            ai_prompt: "Ajoute une CSP stricte à {host} (stack {stack})."
            refs:
              - "https://developer.mozilla.org/fr/docs/Web/HTTP/CSP"
            a_verifier: false
    """), encoding="utf-8")

    # en PARTIEL : seulement le strict nécessaire — prouve l'ajout d'une langue.
    (content / "checks" / "demo.en.yaml").write_text(textwrap.dedent("""\
        hdr-csp:
          absent:
            title: "CSP missing on {host}"
            detail: "No CSP set."
            recommendation: "Add a CSP."
    """), encoding="utf-8")

    (ui / "fr.json").write_text(json.dumps(
        {"lang_name": "Français", "fallback": {"title": "Indisponible", "detail": "x"}}), encoding="utf-8")
    (ui / "en.json").write_text(json.dumps(
        {"lang_name": "English", "fallback": {"title": "Unavailable", "detail": "y"}}), encoding="utf-8")

    monkeypatch.setattr(loader, "CONTENT_DIR", content)
    monkeypatch.setattr(loader, "UI_DIR", ui)
    loader.clear_cache()
    yield
    loader.clear_cache()


def _struct(**kw):
    return Finding("hdr-csp", Category.HEADERS, Severity.MEDIUM, **kw).as_dict()


def test_available_langs(temp_catalog):
    assert i18n.available_langs() == ["en", "fr"]


def test_render_structured_fr(temp_catalog):
    f = _struct(code="absent", params={"host": "x.com"}, evidence="dump")
    r = i18n.render_finding(f, "fr")
    assert r["title"] == "CSP absent sur x.com"
    assert r["detail"] == "Aucune CSP. evidence=dump"          # {evidence} interpolé
    assert r["severity"] == "medium" and r["category"] == "headers"
    rem = r["remediation"]
    assert rem["explanation"] and rem["why"]
    assert rem["steps"][0] == "Pose une CSP sur x.com."
    # Accolades de CODE préservées (ni format ni KeyError) :
    assert rem["stacks"]["nextjs"] == "headers(): { key: 'Content-Security-Policy', value: '...' }"
    # placeholder {stack} laissé pour l'UI ; {host} rempli :
    assert rem["ai_prompt"] == "Ajoute une CSP stricte à x.com (stack {stack})."
    assert rem["refs"] == ["https://developer.mozilla.org/fr/docs/Web/HTTP/CSP"]


def test_add_a_language_is_just_files(temp_catalog):
    f = _struct(code="absent", params={"host": "x.com"})
    assert i18n.render_finding(f, "en")["title"] == "CSP missing on x.com"


def test_fallback_unknown_lang_to_fr(temp_catalog):
    f = _struct(code="absent", params={"host": "x.com"})
    assert i18n.render_finding(f, "de")["title"] == "CSP absent sur x.com"


def test_external_source_text_fallback(temp_catalog):
    # pluginId zap inconnu du catalogue → texte d'origine (EN) tel quel.
    f = Finding("zap-0-99999", Category.ZAP, Severity.LOW, code="alert",
                catalog="zap", entry_id="99999",
                source_text={"title": "Some ZAP Alert", "detail": "english desc",
                             "recommendation": "english fix", "refs": ["http://r"]}).as_dict()
    r = i18n.render_finding(f, "fr")
    assert r["title"] == "Some ZAP Alert"
    assert r["remediation"]["untranslated"] is True
    assert r["remediation"]["refs"] == ["http://r"]


def test_safe_default_when_nothing(temp_catalog):
    # structuré, aucune entrée, pas de source_text → défaut sûr localisé (jamais de clé brute).
    f = _struct(code="inexistant", params={})
    r = i18n.render_finding(f, "fr")
    assert r["title"] == "Indisponible" and r["remediation"] is None


def test_legacy_passthrough(temp_catalog):
    f = Finding("hdr-csp", Category.HEADERS, Severity.MEDIUM, "Titre legacy", "détail", "reco").as_dict()
    r = i18n.render_finding(f, "fr")
    assert r["title"] == "Titre legacy" and r["detail"] == "détail"
    assert r["remediation"] is None


def test_render_ui_merges_over_fr(temp_catalog):
    ui_en = i18n.render_ui("en")
    assert ui_en["lang_name"] == "English"
    assert ui_en["fallback"]["title"] == "Unavailable"
