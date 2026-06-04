"""Catalogue ZAP FR : couverture des pluginIds curés + fallback EN propre.

Garantit que chaque alerte ZAP de tools/zap_sources possède une entrée FR chargée,
que les entrées générées sont marquées `a_verifier`, et que la chaîne de fallback
fonctionne (pluginId connu → FR ; inconnu → texte d'origine anglais).
"""
from __future__ import annotations

import json
from pathlib import Path

from scanner.finding import Category, Finding, Severity
from scanner.i18n import loader, render

ROOT = Path(__file__).resolve().parents[1]
SOURCES = json.loads((ROOT / "tools" / "zap_sources" / "zap_alerts.json").read_text(encoding="utf-8"))
PLUGIN_IDS = [str(a["pluginId"]) for a in SOURCES["alerts"]]


def _zap_finding(plugin_id: str, known_title: str = "EN original"):
    return Finding("zap-0-" + plugin_id, Category.ZAP, Severity.MEDIUM, code="alert",
                   catalog="zap", entry_id=plugin_id, params={"cwe": "", "count": 1},
                   source_text={"title": known_title, "detail": "EN", "recommendation": "EN", "refs": []}).as_dict()


def test_all_curated_plugins_have_fr_entry():
    cat = loader.content_catalog("fr")
    missing = [pid for pid in PLUGIN_IDS if ("zap", pid, "alert") not in cat]
    assert not missing, f"pluginIds ZAP sans entrée FR : {missing}"


def test_all_curated_plugins_have_en_entry():
    # Couverture EN complète → en mode anglais une alerte ZAP est rendue en anglais
    # (et ne retombe pas sur le FR).
    cat = loader.content_catalog("en")
    missing = [pid for pid in PLUGIN_IDS if ("zap", pid, "alert") not in cat]
    assert not missing, f"pluginIds ZAP sans entrée EN : {missing}"


def test_zap_entries_have_explicit_a_verifier():
    # Chaque entrée porte un drapeau a_verifier booléen explicite (true = à relire,
    # false = relu). Les 20 entrées curées sont relues → a_verifier: false.
    cat = loader.content_catalog("fr")
    bad = [pid for pid in PLUGIN_IDS
           if not isinstance(cat[("zap", pid, "alert")].get("a_verifier"), bool)]
    assert not bad, f"entrées ZAP sans a_verifier booléen explicite : {bad}"


def test_known_plugin_renders_fr_not_source_text():
    r = render.render_finding(_zap_finding("10038", known_title="CSP Header Not Set"), "fr")
    # Rendu depuis le catalogue FR (pas le source_text anglais) :
    assert r["title"] != "CSP Header Not Set"
    assert r["remediation"] and not r["remediation"].get("untranslated")
    assert r["remediation"]["steps"]


def test_unknown_plugin_falls_back_to_source_text():
    r = render.render_finding(_zap_finding("99999999", known_title="Totally Unknown Alert"), "fr")
    assert r["title"] == "Totally Unknown Alert"
    assert r["remediation"]["untranslated"] is True
