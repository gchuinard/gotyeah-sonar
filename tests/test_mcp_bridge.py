"""Pont de confiance /api/mcp/* (mcp_bridge) : le hub gotyeah-mcp appelle Sonar avec un secret
partagé + X-Act-As-Email. On couvre la garde (secret/identité, default-deny), la délégation à
la logique `mcp_remote.tools` (réutilisée, inchangée), et la traduction ValueError -> 400.
"""
import sqlite3

import pytest

import auth
import db
from mcp_remote import tools


def _verify_domain(user_id, domain):
    d = auth.add_domain(user_id, domain)
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.execute("UPDATE verified_domains SET verified=1 WHERE id=?", (d["id"],))
    return d


def _save(user_id, target, score=80, findings=None):
    summary = {"score": score, "grade": "B", "counts": {"low": 1}, "total": 1, "target": target}
    return db.save_scan(target, summary, findings or [], user_id=user_id)


SECRET = "shared-secret-xyz"
HDR = {"X-MCP-Secret": SECRET, "X-Act-As-Email": "user@b.com"}


# --------------------------------------------------------------------------- #
# Garde du pont (secret + identité)
# --------------------------------------------------------------------------- #
def test_bridge_wrong_secret_is_401(client, monkeypatch):
    c, _ = client
    monkeypatch.setenv("SONAR_MCP_SHARED_SECRET", SECRET)
    r = c.get("/api/mcp/list_domains",
              headers={"X-MCP-Secret": "nope", "X-Act-As-Email": "user@b.com"})
    assert r.status_code == 401


def test_bridge_no_secret_configured_is_401(client, monkeypatch):
    # Default-deny : sans SONAR_MCP_SHARED_SECRET, la route est fermée même avec un en-tête.
    c, _ = client
    monkeypatch.delenv("SONAR_MCP_SHARED_SECRET", raising=False)
    r = c.get("/api/mcp/list_domains", headers=HDR)
    assert r.status_code == 401


def test_bridge_missing_email_is_401(client, monkeypatch):
    c, _ = client
    monkeypatch.setenv("SONAR_MCP_SHARED_SECRET", SECRET)
    r = c.get("/api/mcp/list_domains", headers={"X-MCP-Secret": SECRET})
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# Délégation à la logique (identité résolue -> tools.*)
# --------------------------------------------------------------------------- #
def test_bridge_list_domains_ok(client, monkeypatch):
    c, _ = client
    monkeypatch.setenv("SONAR_MCP_SHARED_SECRET", SECRET)
    u = auth.create_user("user@b.com")
    _verify_domain(u["id"], "example.com")
    r = c.get("/api/mcp/list_domains", headers=HDR)
    assert r.status_code == 200
    assert any(d.get("domain") == "example.com" for d in r.json())


def test_bridge_get_report_ok_and_owner_scoped(client, monkeypatch):
    c, _ = client
    monkeypatch.setenv("SONAR_MCP_SHARED_SECRET", SECRET)
    u = auth.create_user("user@b.com")
    scan_id = _save(u["id"], "https://example.com/")
    r = c.get("/api/mcp/get_report", headers=HDR, params={"scan_id": scan_id})
    assert r.status_code == 200
    assert r.json().get("score") == 80


def test_bridge_get_report_unknown_scan_is_400(client, monkeypatch):
    # tools.get_report_logic lève ValueError (scan introuvable) -> traduit en 400 par le pont.
    c, _ = client
    monkeypatch.setenv("SONAR_MCP_SHARED_SECRET", SECRET)
    auth.create_user("user@b.com")
    r = c.get("/api/mcp/get_report", headers=HDR, params={"scan_id": "nope"})
    assert r.status_code == 400


def test_bridge_run_scan_guard_is_400(client, monkeypatch):
    # Compte sans domaine vérifié -> run_scan_logic lève "Scan verrouillé" (ValueError) -> 400.
    # (On ne lance JAMAIS de vrai scan ici : la garde échoue avant.)
    c, _ = client
    monkeypatch.setenv("SONAR_MCP_SHARED_SECRET", SECRET)
    auth.create_user("user@b.com")
    r = c.post("/api/mcp/run_scan", headers=HDR, json={"domain": "example.com", "profile": "fast"})
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Résolution d'identité depuis l'email de confiance (logique pure)
# --------------------------------------------------------------------------- #
def test_resolve_trusted_email_closed_registration_strict(authdb):
    # authdb = inscription fermée : lookup strict, pas d'auto-création.
    u = auth.create_user("a@b.com")
    assert tools.resolve_user_from_trusted_email("A@B.com")["id"] == u["id"]  # normalisé
    assert tools.resolve_user_from_trusted_email("inconnu@b.com") is None
    assert tools.resolve_user_from_trusted_email("") is None
    assert tools.resolve_user_from_trusted_email(None) is None


def test_resolve_trusted_email_open_registration_autocreate(authdb, monkeypatch):
    monkeypatch.setenv("SONAR_OPEN_REGISTRATION", "true")
    user = tools.resolve_user_from_trusted_email("new@b.com")
    assert user and user.get("email") == "new@b.com"
