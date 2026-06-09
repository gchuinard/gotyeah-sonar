"""Comparaison de scans + extraction de remédiation (scan_compare) — logique pure.

Aucun MCP, DB ni réseau : on alimente des rapports rendus « à la main » et on vérifie le
diff (resolved/new/persistent + delta) et l'extraction des correctifs (filtre + prompt IA)."""
import pytest

from scan_compare import detected_stack, diff_reports, extract_fixes


def _f(check_id, code, severity, title="", params=None, category="headers", remediation=None):
    return {"check_id": check_id, "code": code, "severity": severity, "title": title,
            "category": category, "params": params, "remediation": remediation}


def test_diff_resolved_new_persistent_and_delta():
    before = {"id": "a", "target": "https://x.com", "score": 70, "grade": "C", "created_at": "t0",
              "findings": [
                  _f("hdr-csp", "absent", "medium", "CSP absente"),
                  _f("hdr-hsts", "absent", "low", "HSTS absent"),
                  _f("hdr-xfo", "ok", "pass", "OK"),          # conforme -> ignoré du diff
              ]}
    after = {"id": "b", "target": "https://x.com", "score": 85, "grade": "A", "created_at": "t1",
             "findings": [
                 _f("hdr-hsts", "absent", "low", "HSTS absent"),                 # persiste
                 _f("leak-srcmap", "exposed", "medium", "Source map", params={"path": "/a.js.map"}),  # nouveau
                 _f("hdr-csp", "ok", "pass", "OK"),           # CSP corrigée (absent a disparu)
             ]}
    d = diff_reports(before, after)
    assert d["score_delta"] == 15
    ids = lambda lst: {(x["check_id"], x["code"]) for x in lst}
    assert ids(d["resolved"]) == {("hdr-csp", "absent")}
    assert ids(d["new"]) == {("leak-srcmap", "exposed")}
    assert ids(d["persistent"]) == {("hdr-hsts", "absent")}
    assert d["summary"] == {"resolved": 1, "new": 1, "persistent": 1, "uncertain": 0}
    assert d["from"]["score"] == 70 and d["to"]["grade"] == "A"


def test_diff_params_distinguish_same_check():
    before = {"score": 90, "findings": [
        _f("leak", "exposed", "high", params={"path": "/.env"}),
        _f("leak", "exposed", "high", params={"path": "/.git/config"}),
    ]}
    after = {"score": 95, "findings": [
        _f("leak", "exposed", "high", params={"path": "/.git/config"}),         # /.env corrigé
    ]}
    d = diff_reports(before, after)
    assert d["summary"] == {"resolved": 1, "new": 0, "persistent": 1, "uncertain": 0}
    assert d["score_delta"] == 5


def test_diff_failed_check_does_not_count_as_resolved():
    # Le scan A voit un problème TLS ; dans le scan B le check tls a ÉCHOUÉ (unexecuted).
    # Le problème « disparaît » de B — mais on ne doit PAS le déclarer corrigé : il bascule
    # dans `uncertain` (couverture incomplète), pas dans `resolved` (fausse remédiation).
    before = {"score": 60, "findings": [
        _f("tls-cert-expiry", "expired", "critical", category="tls"),
    ]}
    after = {"score": 100, "findings": [
        _f("tls", "unreachable", "info", category="tls"),   # le check tls n'a pas tourné…
    ]}
    after["findings"][0]["unexecuted"] = True               # …et le signale
    d = diff_reports(before, after)
    assert d["summary"] == {"resolved": 0, "new": 0, "persistent": 0, "uncertain": 1}
    assert {(x["check_id"], x["code"]) for x in d["uncertain"]} == {("tls-cert-expiry", "expired")}


def test_diff_rejects_running_scan():
    with pytest.raises(ValueError):
        diff_reports({"status": "running", "findings": []}, {"findings": []})


def test_extract_fixes_filters_and_interpolates_prompt():
    report = {"target": "https://shop.example.com", "findings": [
        _f("tech", "detected", "info", category="tech", params={"name": "nginx"}),   # détection stack
        _f("hdr-csp", "absent", "medium", "CSP absente", category="headers",
           remediation={"explanation": "e", "why": "w", "steps": ["s1"],
                        "stacks": {"nginx": "add_header CSP ...;", "apache": "Header set CSP ..."},
                        "ai_prompt": "Sécurise {host} sur {stack} en ajoutant une CSP.",
                        "refs": ["https://ref"]}),
        _f("hdr-xfo", "ok", "pass", category="headers"),                             # conforme -> exclu
    ]}
    report["findings"][1]["recommendation"] = "Ajoute une CSP."

    fixes = extract_fixes(report)
    assert len(fixes) == 1                          # seul le problème ; ni le pass ni le tech/info
    fix = fixes[0]
    assert fix["check_id"] == "hdr-csp"
    assert fix["detected_stack"] == "nginx"
    assert fix["suggested_snippet"] == "add_header CSP ...;"
    # {host}/{stack} remplis comme sur le dashboard.
    assert "shop.example.com" in fix["ai_prompt"] and "nginx" in fix["ai_prompt"]
    assert "{host}" not in fix["ai_prompt"] and "{stack}" not in fix["ai_prompt"]

    # Filtres.
    assert extract_fixes(report, check_id="inconnu") == []
    assert len(extract_fixes(report, check_id="hdr-csp", code="absent")) == 1
    assert extract_fixes(report, check_id="hdr-csp", code="autre") == []


def test_detected_stack_mapping():
    assert detected_stack([_f("tech", "detected", "info", category="tech",
                              params={"name": "Next.js"})]) == "nextjs"
    assert detected_stack([_f("tech", "detected", "info", category="tech",
                              params={"name": "Inconnu"})]) is None
    assert detected_stack([]) is None
