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
    assert "CVE-2021-1" in f.title and "RCE" in f.title
    assert "patch" in f.recommendation
    assert "Références" in f.detail
    assert "v1" in f.evidence
    assert f.category == Category.PENTEST


def test_build_args():
    args = _build_args("nuclei", "https://x/")
    assert "-jsonl" in args
    assert args[args.index("-target") + 1] == "https://x/"


async def test_disabled_via_env(monkeypatch):
    monkeypatch.setenv("SONAR_NUCLEI", "off")
    out = await nuclei(SimpleNamespace(url="https://x/"))
    assert out[0].severity == Severity.INFO and "désactiv" in out[0].title.lower()


async def test_binary_absent(monkeypatch):
    monkeypatch.delenv("SONAR_NUCLEI", raising=False)
    monkeypatch.setenv("NUCLEI_BIN", "nuclei-binaire-absent-zzz")
    out = await nuclei(SimpleNamespace(url="https://x/"))
    assert out[0].severity == Severity.INFO and "non install" in out[0].title.lower()


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
