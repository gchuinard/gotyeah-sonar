"""Phase 3 : parsing de la sortie nuclei + dégradations (off / absent / faux binaire)."""
import json
import os
import stat
from types import SimpleNamespace

import pytest

from scanner.checks.nuclei import _SEV, _build_args, _to_finding, nuclei
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
    # Défauts : tags pertinents (limite les requêtes) + sévérité + rate-limit.
    assert args[args.index("-tags") + 1] == "misconfig,exposure,config"
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
