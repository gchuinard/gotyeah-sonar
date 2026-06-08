"""Scans asynchrones (scan_jobs) : lancement en tâche de fond + attente bornée.

Le moteur de scan est remplacé par un faux générateur (aucun réseau) ; on vérifie que la
ligne passe de 'running' à 'done'/'error', et que `wait_for_completion` rend None quand le
scan dure plus longtemps que le délai (puis finalise bien en arrière-plan)."""
import asyncio

import db
import scan_jobs


async def _engine_ok(target, fast=False):
    yield {"event": "started", "data": {"target": target, "total_checks": 1, "categories": {}}}
    yield {"event": "finding", "data": {"check_id": "x", "category": "info", "severity": "info", "code": "ok"}}
    yield {"event": "done",
           "data": {"score": 90, "grade": "A", "counts": {}, "total": 1, "target": target},
           "_findings": [{"check_id": "x", "category": "info", "severity": "info", "code": "ok"}]}


async def _engine_err(target, fast=False):
    yield {"event": "scan_error", "data": {"message": "Cible injoignable : boom"}}
    return


def _engine_slow(delay):
    async def gen(target, fast=False):
        await asyncio.sleep(delay)
        yield {"event": "done",
               "data": {"score": 50, "grade": "D", "counts": {}, "total": 0, "target": target},
               "_findings": []}
    return gen


async def test_start_scan_finalizes(authdb, monkeypatch):
    monkeypatch.setattr(scan_jobs, "_engine_run_scan", _engine_ok)
    sid = scan_jobs.start_scan("https://x.example", user_id="u1")
    # Juste après start (aucun await), la tâche de fond n'a pas tourné -> 'running'.
    assert db.get_scan(sid)["status"] == "running"
    data = await scan_jobs.wait_for_completion(sid, wait_secs=5, interval=0.02)
    assert data and data["status"] == "done" and data["score"] == 90
    assert db.get_scan(sid)["findings"][0]["check_id"] == "x"


async def test_start_scan_marks_error(authdb, monkeypatch):
    monkeypatch.setattr(scan_jobs, "_engine_run_scan", _engine_err)
    sid = scan_jobs.start_scan("https://x.example", user_id="u1")
    data = await scan_jobs.wait_for_completion(sid, wait_secs=5, interval=0.02)
    assert data and data["status"] == "error"
    assert "injoignable" in data["findings"][0]["detail"]


async def test_wait_returns_none_when_still_running(authdb, monkeypatch):
    monkeypatch.setattr(scan_jobs, "_engine_run_scan", _engine_slow(0.4))
    sid = scan_jobs.start_scan("https://x.example", user_id="u1")
    # Délai d'attente plus court que le scan -> None, scan toujours en cours.
    data = await scan_jobs.wait_for_completion(sid, wait_secs=0.1, interval=0.02)
    assert data is None
    assert db.get_scan(sid)["status"] == "running"
    # On laisse la tâche de fond se terminer DANS la base temporaire (pas d'écriture parasite).
    for t in list(scan_jobs._BG_TASKS):
        await t
    assert db.get_scan(sid)["status"] == "done"


async def test_fast_flag_passed_through(authdb, monkeypatch):
    seen = {}

    async def eng(target, fast=False):
        seen["fast"] = fast
        yield {"event": "done",
               "data": {"score": 99, "grade": "A+", "counts": {}, "total": 0, "target": target},
               "_findings": []}

    monkeypatch.setattr(scan_jobs, "_engine_run_scan", eng)
    sid = scan_jobs.start_scan("https://x.example", user_id="u1", fast=True)
    await scan_jobs.wait_for_completion(sid, wait_secs=5, interval=0.02)
    assert seen["fast"] is True


async def test_progress_tracked_then_cleared(authdb, monkeypatch):
    async def eng(target, fast=False):
        yield {"event": "progress", "data": {"done": 1, "total": 3, "category": "headers"}}
        await asyncio.sleep(0.3)                       # garde le scan « en cours »
        yield {"event": "done",
               "data": {"score": 60, "grade": "C", "counts": {}, "total": 3, "target": target},
               "_findings": []}

    monkeypatch.setattr(scan_jobs, "_engine_run_scan", eng)
    sid = scan_jobs.start_scan("https://x.example", user_id="u1")
    # Pendant le scan : la progression est exposée, le scan est 'running'.
    data = await scan_jobs.wait_for_completion(sid, wait_secs=0.1, interval=0.02)
    assert data is None
    assert scan_jobs.progress_of(sid) == {"done": 1, "total": 3}
    # Une fois terminé : progression libérée (mémoire), ligne 'done'.
    for t in list(scan_jobs._BG_TASKS):
        await t
    assert scan_jobs.progress_of(sid) is None
    assert db.get_scan(sid)["status"] == "done"


def test_scan_wait_secs_env(monkeypatch):
    monkeypatch.delenv("SONAR_MCP_SCAN_WAIT", raising=False)
    assert scan_jobs.scan_wait_secs() == 25.0
    monkeypatch.setenv("SONAR_MCP_SCAN_WAIT", "5")
    assert scan_jobs.scan_wait_secs() == 5.0
    monkeypatch.setenv("SONAR_MCP_SCAN_WAIT", "pasunnombre")
    assert scan_jobs.scan_wait_secs() == 25.0      # repli robuste
