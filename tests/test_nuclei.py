"""Phase 3 : parsing de la sortie nuclei + dégradations (off / absent / faux binaire)."""
import json
import os
import stat
from types import SimpleNamespace

import pytest

from scanner.checks.nuclei import _SEV, _build_args, _dedup_to_findings, _to_finding, nuclei
from scanner.finding import Category, Severity


def test_sev_map():
    assert _SEV["critical"] == Severity.CRITICAL
    assert _SEV["info"] == Severity.INFO
    assert _SEV.get("inconnu", Severity.INFO) == Severity.INFO


def test_to_finding_maps_all_fields():
    obj = {
        "template-id": "CVE-2021-1",
        "info": {"name": "RCE", "severity": "high", "description": "desc",
                 "reference": ["https://nvd"], "remediation": "patch"},
        "matched-at": "https://x/p",
        "extracted-results": ["v1"],
    }
    f = _to_finding(obj, 0, "https://x/")
    assert f.severity == Severity.HIGH
    assert f.category == Category.PENTEST
    # Finding externe : le texte (anglais de nuclei) vit dans source_text (fallback).
    assert f.code == "result" and f.catalog == "nuclei" and f.entry_id == "CVE-2021-1"
    st = f.source_text
    assert "CVE-2021-1" in st["title"] and "RCE" in st["title"]
    assert "patch" in st["recommendation"]
    assert "Références" in st["detail"]
    assert "v1" in f.evidence


def test_build_args(monkeypatch):
    for v in ("NUCLEI_TAGS", "NUCLEI_SEVERITY", "NUCLEI_RATE_LIMIT", "NUCLEI_ARGS"):
        monkeypatch.delenv(v, raising=False)
    args = _build_args("nuclei", "https://x/")
    assert "-jsonl" in args
    assert args[args.index("-target") + 1] == "https://x/"
    # Défauts : classes exploitables (cve, panels, default-login, takeover…), bornées par
    # la sévérité (medium+) + rate-limit.
    assert args[args.index("-tags") + 1] == "cve,misconfig,exposure,exposed-panels,default-login,takeover"
    assert args[args.index("-severity") + 1] == "medium,high,critical"
    assert args[args.index("-rate-limit") + 1] == "50"


def test_build_args_tags_override_and_disable(monkeypatch):
    monkeypatch.setenv("NUCLEI_TAGS", "cve,takeover")
    args = _build_args("nuclei", "https://x/")
    assert args[args.index("-tags") + 1] == "cve,takeover"
    # Sentinel "all" => filtre levé (tous les templates). Vide retomberait sur le défaut.
    monkeypatch.setenv("NUCLEI_TAGS", "all")
    assert "-tags" not in _build_args("nuclei", "https://x/")
    monkeypatch.setenv("NUCLEI_TAGS", "")          # vide => défaut, donc filtre toujours là
    assert _build_args("nuclei", "https://x/").count("-tags") == 1


def test_build_args_rate_limit_override(monkeypatch):
    monkeypatch.setenv("NUCLEI_RATE_LIMIT", "10")
    args = _build_args("nuclei", "https://x/")
    assert args[args.index("-rate-limit") + 1] == "10"


async def test_disabled_via_env(monkeypatch):
    monkeypatch.setenv("SONAR_NUCLEI", "off")
    out = await nuclei(SimpleNamespace(url="https://x/"))
    assert out[0].severity == Severity.INFO and out[0].code == "off"


async def test_binary_absent(monkeypatch):
    monkeypatch.delenv("SONAR_NUCLEI", raising=False)
    monkeypatch.setenv("NUCLEI_BIN", "nuclei-binaire-absent-zzz")
    out = await nuclei(SimpleNamespace(url="https://x/"))
    assert out[0].severity == Severity.INFO and out[0].code == "not-installed"


@pytest.mark.skipif(os.name != "posix", reason="faux binaire = script shell (posix)")
async def test_parses_subprocess_output(monkeypatch, tmp_path):
    monkeypatch.delenv("SONAR_NUCLEI", raising=False)
    lines = [
        {"template-id": "t1", "info": {"name": "Info un", "severity": "info"}, "matched-at": "https://x/"},
        {"template-id": "CVE-9", "info": {"name": "Crit", "severity": "critical"}, "matched-at": "https://x/a"},
    ]
    script = tmp_path / "fake_nuclei"
    script.write_text("#!/bin/sh\n" + "".join("echo '%s'\n" % json.dumps(o) for o in lines))
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("NUCLEI_BIN", str(script))

    out = await nuclei(SimpleNamespace(url="https://x/"))
    sevs = {f.severity.value for f in out}
    assert len(out) == 2 and "info" in sevs and "critical" in sevs


def test_dedup_groups_same_template():
    # Un même template qui matche 3 URL -> UN seul Finding, avec le compte (pas 3× la pénalité).
    results = [
        {"template-id": "missing-header", "info": {"name": "H", "severity": "low"}, "matched-at": f"https://x/p{i}"}
        for i in range(3)
    ] + [{"template-id": "CVE-9", "info": {"name": "RCE", "severity": "critical"}, "matched-at": "https://x/a"}]
    out = _dedup_to_findings(results, "https://x/")
    assert len(out) == 2
    grouped = next(f for f in out if f.entry_id == "missing-header")
    assert grouped.params["count"] == 3 and "3 occurrence" in grouped.source_text["detail"]


@pytest.mark.skipif(os.name != "posix", reason="faux binaire = script shell (posix)")
async def test_timeout_keeps_partial_results(monkeypatch, tmp_path):
    # nuclei remonte un critical PUIS traîne au-delà du timeout : on garde le critical trouvé
    # ET on signale le timeout (couverture incomplète), au lieu de tout jeter.
    monkeypatch.delenv("SONAR_NUCLEI", raising=False)
    crit = {"template-id": "CVE-1", "info": {"name": "RCE", "severity": "critical"}, "matched-at": "https://x/a"}
    script = tmp_path / "slow_nuclei"
    script.write_text("#!/bin/sh\necho '%s'\nsleep 5\n" % json.dumps(crit))
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("NUCLEI_BIN", str(script))
    monkeypatch.setenv("NUCLEI_TIMEOUT", "1")          # coupe avant la fin du `sleep 5`

    out = await nuclei(SimpleNamespace(url="https://x/"))
    codes = {f.code for f in out}
    sevs = {f.severity for f in out}
    assert "timeout" in codes                          # le scan est marqué incomplet…
    assert Severity.CRITICAL in sevs                   # …mais le critical trouvé est conservé
    # le finding timeout est bien celui qui plafonnera la note (check_id "nuclei").
    assert any(f.check_id == "nuclei" and f.code == "timeout" for f in out)
