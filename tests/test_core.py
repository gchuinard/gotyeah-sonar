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


def test_as_dict_legacy():
    # Forme legacy (texte rendu en dur) : title/detail/reco renseignés, structuré vide.
    d = Finding("cid", Category.TLS, Severity.HIGH, "titre", "det", "reco", evidence="ev").as_dict()
    assert d == {
        "check_id": "cid", "category": "tls", "severity": "high",
        "code": "", "params": {}, "evidence": "ev",
        "catalog": None, "entry_id": None, "source_text": None,
        "title": "titre", "detail": "det", "recommendation": "reco",
    }


def test_as_dict_structured():
    # Forme structurée (cible) : code/params portent la détection, pas de texte humain.
    d = Finding("hdr-csp", Category.HEADERS, Severity.MEDIUM,
                code="absent", params={"host": "x.com"}, evidence="ev").as_dict()
    assert d["check_id"] == "hdr-csp" and d["code"] == "absent"
    assert d["params"] == {"host": "x.com"} and d["title"] == ""
    assert d["catalog"] is None and d["source_text"] is None


# ---- registry.py ----

def test_real_checks_registered():
    ids = {c.id for c in all_checks()}
    for expected in ("hdr-csp", "cookies", "tls", "dns", "exposed", "cors", "mixed",
                     "subresources", "tech", "nuclei", "zap"):
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
    assert "findings" not in row                 # la liste latérale ne porte pas les findings
    assert row["counts"] == {"low": 2}           # mais bien les compteurs de sévérité (pastilles)  # la liste latérale ne porte pas les findings

    one = dbmod.get_scan(sid)
    assert one["target"] == "https://x"
    assert isinstance(one["counts"], dict) and one["counts"]["low"] == 2
    assert isinstance(one["findings"], list) and one["findings"][0]["check_id"] == "hdr-csp"

    assert dbmod.get_scan("inexistant") is None


def test_db_delete_scan(tmp_path, monkeypatch):
    import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", tmp_path / "scans.db")
    dbmod.init_db()
    summary = {"score": 70, "grade": "C", "counts": {}, "total": 0, "target": "https://x"}
    sid_a = dbmod.save_scan("https://x", summary, [], user_id="alice")
    sid_b = dbmod.save_scan("https://y", summary, [], user_id="bob")

    # Contrôle de propriété : bob ne peut pas supprimer le scan d'alice (pas d'IDOR).
    assert dbmod.delete_scan(sid_a, user_id="bob") is False
    assert dbmod.get_scan(sid_a) is not None
    # Le propriétaire supprime le sien.
    assert dbmod.delete_scan(sid_a, user_id="alice") is True
    assert dbmod.get_scan(sid_a) is None
    assert dbmod.delete_scan(sid_a, user_id="alice") is False   # déjà parti
    # Sans user_id (admin) : supprime quel que soit le propriétaire.
    assert dbmod.delete_scan(sid_b) is True
    assert dbmod.get_scan(sid_b) is None


def test_db_status_legacy_and_save(tmp_path, monkeypatch):
    import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", tmp_path / "scans.db")
    dbmod.init_db()
    summary = {"score": 88, "grade": "A", "counts": {}, "total": 0, "target": "https://x"}
    sid = dbmod.save_scan("https://x", summary, [])
    # Un scan enregistré via save_scan est 'done'.
    assert dbmod.get_scan(sid)["status"] == "done"
    assert dbmod.list_scans()[0]["status"] == "done"
    # Une ligne sans statut (base d'avant la feature) est lue comme 'done'.
    import sqlite3
    with sqlite3.connect(dbmod.DB_PATH) as conn:
        conn.execute("UPDATE scans SET status=NULL WHERE id=?", (sid,))
    assert dbmod.get_scan(sid)["status"] == "done"


def test_db_running_finalize_fail(tmp_path, monkeypatch):
    import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", tmp_path / "scans.db")
    dbmod.init_db()

    # create_running_scan : ligne 'running', sans score ni findings.
    sid = dbmod.create_running_scan("https://x", user_id="u1")
    running = dbmod.get_scan(sid)
    assert running["status"] == "running" and running["score"] is None
    assert running["findings"] == [] and running["target"] == "https://x"
    assert dbmod.list_scans(user_id="u1")[0]["status"] == "running"

    # finalize_scan : complète la ligne (statut 'done').
    summary = {"score": 73, "grade": "C", "counts": {"low": 1}, "total": 1, "target": "https://x/final"}
    findings = [{"check_id": "hdr-csp", "category": "headers", "severity": "low", "code": "absent"}]
    dbmod.finalize_scan(sid, summary, findings)
    done = dbmod.get_scan(sid)
    assert done["status"] == "done" and done["score"] == 73 and done["grade"] == "C"
    assert done["target"] == "https://x/final" and done["findings"][0]["check_id"] == "hdr-csp"

    # fail_scan : statut 'error' + message restitué en finding passthrough.
    sid2 = dbmod.create_running_scan("https://y", user_id="u1")
    dbmod.fail_scan(sid2, "Cible injoignable : timeout")
    failed = dbmod.get_scan(sid2)
    assert failed["status"] == "error"
    assert "injoignable" in failed["findings"][0]["detail"]


def test_checks_for_fast_excludes_slow():
    from scanner.finding import Category
    from scanner.runner import checks_for
    full = {c.id for c in checks_for(fast=False)}
    fast = {c.id for c in checks_for(fast=True)}
    # Les checks lents (nuclei/ZAP/ports) sont dans le scan complet, jamais dans le rapide.
    assert {"nuclei", "zap", "ports"} <= full
    assert not ({"nuclei", "zap", "ports"} & fast)
    assert fast < full and len(fast) == len(full) - 3      # le rapide n'enlève QUE ces 3
    cats = {c.category for c in checks_for(fast=True)}
    assert not ({Category.PENTEST, Category.ZAP, Category.PORTS} & cats)
