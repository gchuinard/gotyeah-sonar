"""Cœur : format Finding/scoring, registre, moteur (isolation d'erreurs), DB."""
import asyncio

import pytest

import scanner.checks  # noqa: F401 — enregistre les 15 checks réels
from scanner.finding import Category, Finding, Severity, score_and_grade, summarize
from scanner.registry import Check, all_checks, check
from scanner.runner import _safe_run, normalize_target


def _f(sev):
    return Finding("x", Category.HEADERS, sev, "t")


# ---- finding.py ----

def test_grade_boundaries():
    assert score_and_grade([]) == (100, "A+")
    assert score_and_grade([_f(Severity.LOW)]) == (97, "A+")
    assert score_and_grade([_f(Severity.CRITICAL)]) == (75, "B")
    assert score_and_grade([_f(Severity.CRITICAL), _f(Severity.HIGH)]) == (60, "D")
    score, grade = score_and_grade([_f(Severity.CRITICAL)] * 3)  # 75 de pénalité
    assert score == 25 and grade == "F"


def test_pass_and_info_do_not_penalize():
    assert score_and_grade([_f(Severity.PASS), _f(Severity.INFO)]) == (100, "A+")


def test_summarize():
    findings = [_f(Severity.CRITICAL), _f(Severity.LOW), _f(Severity.PASS)]
    s = summarize(findings)
    assert s["total"] == 3
    assert s["counts"]["critical"] == 1 and s["counts"]["low"] == 1 and s["counts"]["pass"] == 1
    assert s["score"] == 100 - 25 - 3
    assert s["grade"] == "C"


def test_as_dict():
    d = Finding("cid", Category.TLS, Severity.HIGH, "titre", "det", "reco", evidence="ev").as_dict()
    assert d == {
        "check_id": "cid", "category": "tls", "severity": "high", "title": "titre",
        "detail": "det", "recommendation": "reco", "evidence": "ev",
    }


# ---- registry.py ----

def test_real_checks_registered():
    ids = {c.id for c in all_checks()}
    for expected in ("hdr-csp", "cookies", "tls", "dns", "exposed", "cors", "mixed",
                     "subresources", "tech", "nuclei"):
        assert expected in ids


def test_duplicate_id_raises():
    with pytest.raises(ValueError):
        @check("hdr-csp", "doublon", Category.HEADERS)
        async def _dup(ctx):
            return []


def test_decorator_registers_and_returns_coro():
    @check("test-dummy-unique", "Dummy", Category.INFO)
    async def dummy(ctx):
        return []
    assert any(c.id == "test-dummy-unique" for c in all_checks())
    assert asyncio.iscoroutinefunction(dummy)


# ---- runner.py ----

def test_normalize_target():
    assert normalize_target("example.com") == "https://example.com"
    assert normalize_target("http://x.com") == "http://x.com"
    assert normalize_target("https://x.com") == "https://x.com"
    assert normalize_target("  example.com  ") == "https://example.com"


async def test_safe_run_isolates_exceptions():
    async def boom(ctx):
        raise RuntimeError("boom")
    chk = Check(id="boom", title="Boom", category=Category.HEADERS, fn=boom)
    rchk, findings = await _safe_run(chk, ctx=None)
    assert rchk is chk
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].category == Category.INFO


async def test_safe_run_none_returns_empty():
    async def nothing(ctx):
        return None
    _c, findings = await _safe_run(
        Check(id="n", title="N", category=Category.HEADERS, fn=nothing), ctx=None)
    assert findings == []


async def test_safe_run_passthrough():
    async def ok(ctx):
        return [Finding("ok", Category.HEADERS, Severity.PASS, "ok")]
    _c, findings = await _safe_run(
        Check(id="ok", title="OK", category=Category.HEADERS, fn=ok), ctx=None)
    assert len(findings) == 1 and findings[0].severity == Severity.PASS


# ---- db.py ----

def test_db_roundtrip(tmp_path, monkeypatch):
    import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", tmp_path / "scans.db")
    dbmod.init_db()
    summary = {"score": 82, "grade": "B", "counts": {"low": 2}, "total": 5, "target": "https://x"}
    findings = [{"check_id": "hdr-csp", "category": "headers", "severity": "low",
                 "title": "t", "detail": "d", "recommendation": "r", "evidence": None}]
    sid = dbmod.save_scan("https://x", summary, findings)
    assert isinstance(sid, str) and sid

    row = dbmod.list_scans()[0]
    assert row["id"] == sid and row["score"] == 82 and row["grade"] == "B"
    assert "findings" not in row  # la liste latérale ne porte pas les findings

    one = dbmod.get_scan(sid)
    assert one["target"] == "https://x"
    assert isinstance(one["counts"], dict) and one["counts"]["low"] == 2
    assert isinstance(one["findings"], list) and one["findings"][0]["check_id"] == "hdr-csp"

    assert dbmod.get_scan("inexistant") is None
