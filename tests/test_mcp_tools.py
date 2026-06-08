"""Logique des outils du MCP DISTANT (mcp_remote.tools) — sans le SDK fastmcp.

C'est la surface PUBLIQUE et ACTIVE du serveur : on couvre le mapping d'identité, le
cloisonnement par propriétaire (pas d'IDOR), le gate de scan (domaine vérifié), le
rate-limit, et le rendu. `remote.py` n'est plus qu'un câblage par-dessus ces fonctions.
"""
import sqlite3
from types import SimpleNamespace

import pytest

import auth
import db
import scan_jobs
from mcp_remote import tools


def _verify_domain(user_id, domain):
    """Crée et marque vérifié un domaine pour ce compte (sans passer par le DNS)."""
    d = auth.add_domain(user_id, domain)
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.execute("UPDATE verified_domains SET verified=1 WHERE id=?", (d["id"],))
    return d


def _save(user_id, target, score=80, findings=None):
    summary = {"score": score, "grade": "B", "counts": {"low": 1}, "total": 1, "target": target}
    return db.save_scan(target, summary, findings or [], user_id=user_id)


# --------------------------------------------------------------------------- #
# Mapping d'identité (token -> compte)
# --------------------------------------------------------------------------- #
def test_resolve_user_from_token(authdb):
    u = auth.create_user("user@b.com")
    # email dans les claims (normalisé)
    assert tools.resolve_user_from_token(
        SimpleNamespace(claims={"email": "User@B.com"}, token="t"))["id"] == u["id"]
    # pas de token / email inconnu -> None
    assert tools.resolve_user_from_token(None) is None
    assert tools.resolve_user_from_token(SimpleNamespace(claims={"email": "x@y.com"}, token="t")) is None
    assert tools.resolve_user_from_token(SimpleNamespace(claims={}, token="t")) is None


def test_resolve_user_userinfo_fallback(authdb):
    u = auth.create_user("user@b.com")
    calls = {}

    def fake_get(url, headers=None, timeout=None):
        calls["url"] = url
        calls["auth"] = (headers or {}).get("Authorization")
        return SimpleNamespace(status_code=200, json=lambda: {"email": "user@b.com"})

    tok = SimpleNamespace(claims={}, token="ACCESS")     # email absent de l'access token
    got = tools.resolve_user_from_token(tok, "https://idp/userinfo", http_get=fake_get)
    assert got["id"] == u["id"]
    assert calls["url"] == "https://idp/userinfo" and calls["auth"] == "Bearer ACCESS"


# --------------------------------------------------------------------------- #
# Garde-fou identité + cloisonnement (IDOR)
# --------------------------------------------------------------------------- #
async def test_logic_requires_user(authdb):
    for coro in (tools.list_domains_logic(None),
                 tools.list_scans_logic(None),
                 tools.get_report_logic(None, "x"),
                 tools.run_scan_logic(None, "x.com")):
        with pytest.raises(ValueError, match="identité"):
            await coro


async def test_read_logic_owner_scoped_no_idor(authdb):
    a = auth.create_user("a@b.com")
    b = auth.create_user("b@b.com")
    admin = auth.create_user("admin@b.com", is_admin=True)
    sid = _save(a["id"], "https://a.example",
                findings=[{"check_id": "hdr-csp", "code": "absent", "category": "headers", "severity": "low"}])

    # A lit son scan (et il est RENDU : un titre apparaît).
    rep = await tools.get_report_logic(a, sid)
    assert rep["target"] == "https://a.example" and rep["findings"][0].get("title")
    # B ne lit PAS le scan de A (pas d'IDOR).
    with pytest.raises(ValueError, match="introuvable"):
        await tools.get_report_logic(b, sid)
    # L'admin lit tout.
    assert (await tools.get_report_logic(admin, sid))["target"] == "https://a.example"


async def test_list_scans_logic_scope_and_filter(authdb):
    a = auth.create_user("a@b.com")
    b = auth.create_user("b@b.com")
    admin = auth.create_user("admin@b.com", is_admin=True)
    _save(a["id"], "https://a.example")
    _save(b["id"], "https://b.example")

    sa = await tools.list_scans_logic(a)
    assert len(sa) == 1 and "a.example" in sa[0]["target"]       # cloisonné
    assert len(await tools.list_scans_logic(admin)) == 2          # admin : tout
    assert len(await tools.list_scans_logic(admin, domain="b.example")) == 1   # filtre


async def test_get_scan_status_logic(authdb, monkeypatch):
    a = auth.create_user("a@b.com")
    sid = _save(a["id"], "https://a.example", score=90)
    st = await tools.get_scan_status_logic(a, sid)
    assert st["status"] == "done" and st["score"] == 90

    rid = db.create_running_scan("https://a.example", user_id=a["id"])
    monkeypatch.setattr(scan_jobs, "progress_of", lambda s: {"done": 2, "total": 5})
    st2 = await tools.get_scan_status_logic(a, rid)
    assert st2 == {"scan_id": rid, "status": "running", "done": 2, "total": 5}


async def test_diff_scans_logic(authdb):
    a = auth.create_user("a@b.com")
    s1 = _save(a["id"], "https://a.example", score=70,
               findings=[{"check_id": "hdr-csp", "code": "absent", "category": "headers", "severity": "medium"}])
    s2 = _save(a["id"], "https://a.example", score=85)
    d = await tools.diff_scans_logic(a, s1, s2)
    assert d["score_delta"] == 15
    assert any(x["check_id"] == "hdr-csp" for x in d["resolved"]) and d["lang"]


# --------------------------------------------------------------------------- #
# run_scan : gate domaine vérifié + rate-limit + rendu / branche "running"
# --------------------------------------------------------------------------- #
async def test_run_scan_gate_locked_and_not_owned(authdb):
    plain = auth.create_user("p@b.com")               # aucun domaine vérifié
    with pytest.raises(ValueError, match="verrouillé"):
        await tools.run_scan_logic(plain, "x.com")
    # Domaine A vérifié, mais on tente B -> refus "domaines vérifiés".
    _verify_domain(plain["id"], "mysite.com")
    with pytest.raises(ValueError, match="vérifiés"):
        await tools.run_scan_logic(plain, "autre.com")


async def test_run_scan_rate_limited(authdb, monkeypatch):
    monkeypatch.setenv("SONAR_SCAN_RATE", "1")
    admin = auth.create_user("a@b.com", is_admin=True)   # admin -> gate domaine ouvert
    monkeypatch.setattr(scan_jobs, "start_scan", lambda t, u, fast=False: "SID")

    async def _wait_running(scan_id):
        return None
    monkeypatch.setattr(scan_jobs, "wait_for_completion", _wait_running)

    await tools.run_scan_logic(admin, "x.com")           # 1er passe
    with pytest.raises(ValueError, match="Trop de scans"):
        await tools.run_scan_logic(admin, "x.com")       # 2e refusé (quota=1)


async def test_run_scan_returns_rendered_report(authdb, monkeypatch):
    admin = auth.create_user("a@b.com", is_admin=True)
    seen = {}
    monkeypatch.setattr(scan_jobs, "start_scan",
                        lambda t, u, fast=False: seen.update(target=t, fast=fast) or "SID")

    async def _wait_done(scan_id):
        return {"id": scan_id, "target": "https://x.com", "score": 88, "grade": "A",
                "status": "done",
                "findings": [{"check_id": "hdr-csp", "code": "absent",
                              "category": "headers", "severity": "low"}]}
    monkeypatch.setattr(scan_jobs, "wait_for_completion", _wait_done)

    out = await tools.run_scan_logic(admin, "x.com", profile="fast")
    assert seen["fast"] is True and seen["target"] == "https://x.com"   # profil + normalisation
    assert out["status"] == "done" and out["score"] == 88
    assert out["findings"][0].get("title") and out["lang"]              # rendu localisé


async def test_run_scan_running_branch(authdb, monkeypatch):
    admin = auth.create_user("a@b.com", is_admin=True)
    monkeypatch.setattr(scan_jobs, "start_scan", lambda t, u, fast=False: "SID")

    async def _wait_running(scan_id):
        return None
    monkeypatch.setattr(scan_jobs, "wait_for_completion", _wait_running)

    out = await tools.run_scan_logic(admin, "x.com")
    assert out["scan_id"] == "SID" and out["status"] == "running"
    assert "get_report" in out["message"] and "get_scan_status" in out["message"]
