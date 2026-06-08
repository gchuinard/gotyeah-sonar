"""Phase 3 (bonus) : wrapper OWASP ZAP — mapping, dédup, flux API mocké, dégradations."""
from types import SimpleNamespace

import httpx
import pytest

import scanner.checks.zap as zapmod
from scanner.checks.zap import zap
from scanner.finding import Category, Severity


# ---- helpers ----

def _handler(alerts):
    """Simule l'API REST de ZAP : chaque endpoint renvoie un JSON plausible."""
    def handle(request):
        p = request.url.path
        if p.endswith("/core/action/accessUrl/"):
            return httpx.Response(200, json={"Result": "OK"})
        if p.endswith("/spider/action/scan/") or p.endswith("/ascan/action/scan/"):
            return httpx.Response(200, json={"scan": "0"})
        if p.endswith("/spider/view/status/") or p.endswith("/ascan/view/status/"):
            return httpx.Response(200, json={"status": "100"})
        if p.endswith("/pscan/view/recordsToScan/"):
            return httpx.Response(200, json={"recordsToScan": "0"})
        if p.endswith("/core/view/alerts/"):
            return httpx.Response(200, json={"alerts": alerts})
        return httpx.Response(404, json={})
    return handle


def _mock_client(alerts):
    return httpx.AsyncClient(base_url="http://zap:8090",
                             transport=httpx.MockTransport(_handler(alerts)))


# ---- unités pures ----

def test_map_risk():
    assert zapmod._map_risk("High") == Severity.HIGH
    assert zapmod._map_risk("Medium") == Severity.MEDIUM
    assert zapmod._map_risk("Informational") == Severity.INFO
    assert zapmod._map_risk("bizarre") == Severity.INFO


def test_dedup_groups_and_counts():
    alerts = [
        {"pluginId": "1", "alert": "A", "risk": "Low", "url": "https://x/u1"},
        {"pluginId": "1", "alert": "A", "risk": "Low", "url": "https://x/u2"},
        {"pluginId": "2", "alert": "B", "risk": "High", "url": "https://x/u3", "cweid": "79"},
    ]
    out = zapmod._dedup_to_findings(alerts)
    assert len(out) == 2
    # Finding externe : le texte ZAP (anglais d'origine) vit dans source_text.
    a = next(f for f in out if f.source_text["title"].startswith("A"))
    assert a.severity == Severity.LOW and "2 occurrence" in a.source_text["detail"]
    b = next(f for f in out if f.source_text["title"].startswith("B"))
    assert b.severity == Severity.HIGH and "CWE-79" in b.source_text["title"]
    assert all(f.category == Category.ZAP for f in out)
    assert all(f.catalog == "zap" and f.code == "alert" for f in out)


def test_drop_cdn_cgi_filters_cloudflare_false_positives():
    alerts = [
        # Private IP Disclosure (id 2) sur un endpoint cdn-cgi -> faux positif Cloudflare.
        {"pluginId": "2", "alert": "Private IP Disclosure", "risk": "Low",
         "url": "https://x/cdn-cgi/l/email-protection", "evidence": "10.0.0.1"},
        # cdn-cgi remonté côté evidence -> écarté aussi.
        {"pluginId": "2", "alert": "Private IP Disclosure", "risk": "Low",
         "url": "https://x/page", "evidence": "https://x/cdn-cgi/trace"},
        # Vraie alerte hors cdn-cgi -> conservée.
        {"pluginId": "40012", "alert": "XSS", "risk": "High", "url": "https://x/a"},
    ]
    kept = zapmod._drop_cdn_cgi(alerts)
    assert [a["alert"] for a in kept] == ["XSS"]


# ---- flux complet (API mockée) ----

async def test_zap_full_flow(monkeypatch):
    monkeypatch.delenv("SONAR_ZAP", raising=False)
    monkeypatch.setenv("ZAP_API_URL", "http://zap:8090")
    alerts = [
        {"pluginId": "40012", "alert": "Cross Site Scripting", "risk": "High",
         "description": "d", "solution": "s", "url": "https://x/a", "cweid": "79"},
        {"pluginId": "10038", "alert": "CSP absente", "risk": "Medium",
         "description": "d2", "solution": "s2", "url": "https://x/"},
        {"pluginId": "10038", "alert": "CSP absente", "risk": "Medium",
         "description": "d2", "solution": "s2", "url": "https://x/b"},
    ]
    monkeypatch.setattr(zapmod, "_make_client", lambda base: _mock_client(alerts))
    out = await zap(SimpleNamespace(url="https://x/"))
    sevs = {f.severity for f in out}
    assert Severity.HIGH in sevs and Severity.MEDIUM in sevs
    assert len([f for f in out if f.entry_id == "10038"]) == 1  # dédup des 2 mediums (pluginId)


async def test_zap_skips_cdn_cgi_alerts(monkeypatch):
    monkeypatch.delenv("SONAR_ZAP", raising=False)
    monkeypatch.setenv("ZAP_API_URL", "http://zap:8090")
    alerts = [
        {"pluginId": "2", "alert": "Private IP Disclosure", "risk": "Low",
         "url": "https://x/cdn-cgi/l/email-protection", "evidence": "192.168.0.1"},
        {"pluginId": "40012", "alert": "XSS", "risk": "High", "url": "https://x/a", "cweid": "79"},
    ]
    monkeypatch.setattr(zapmod, "_make_client", lambda base: _mock_client(alerts))
    out = await zap(SimpleNamespace(url="https://x/"))
    # L'alerte cdn-cgi (ZAP id 2) est écartée ; seule la vraie alerte XSS subsiste.
    assert all(f.entry_id != "2" for f in out)
    assert any(f.entry_id == "40012" for f in out)


async def test_zap_no_alerts_pass(monkeypatch):
    monkeypatch.delenv("SONAR_ZAP", raising=False)
    monkeypatch.setenv("ZAP_API_URL", "http://zap:8090")
    monkeypatch.setattr(zapmod, "_make_client", lambda base: _mock_client([]))
    out = await zap(SimpleNamespace(url="https://x/"))
    assert len(out) == 1 and out[0].severity == Severity.PASS


async def test_zap_unreachable(monkeypatch):
    monkeypatch.delenv("SONAR_ZAP", raising=False)
    monkeypatch.setenv("ZAP_API_URL", "http://zap:8090")

    def boom(request):
        raise httpx.ConnectError("connexion refusée")

    client = httpx.AsyncClient(base_url="http://zap:8090", transport=httpx.MockTransport(boom))
    monkeypatch.setattr(zapmod, "_make_client", lambda base: client)
    out = await zap(SimpleNamespace(url="https://x/"))
    assert out[0].severity == Severity.INFO and out[0].code == "unreachable"


# ---- dégradations de config ----

async def test_zap_not_configured(monkeypatch):
    monkeypatch.delenv("SONAR_ZAP", raising=False)
    monkeypatch.delenv("ZAP_API_URL", raising=False)
    out = await zap(SimpleNamespace(url="https://x/"))
    assert out[0].severity == Severity.INFO and out[0].code == "not-configured"


async def test_zap_disabled(monkeypatch):
    monkeypatch.setenv("SONAR_ZAP", "off")
    monkeypatch.setenv("ZAP_API_URL", "http://zap:8090")
    out = await zap(SimpleNamespace(url="https://x/"))
    assert out[0].code == "off"
