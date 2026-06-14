"""Administration des comptes (admin only).

Couvre : `auth.list_users` (compteurs domaines/scans/jetons), `auth.count_admins`,
`auth.delete_user` (cascade + isolation), et les endpoints `/api/admin/users*` —
gating admin, et garde-fous anti-lockout (pas soi-même, pas le dernier admin).
"""
import sqlite3

import auth
import db


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _verify_domain(user_id, domain):
    d = auth.add_domain(user_id, domain)
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.execute("UPDATE verified_domains SET verified=1 WHERE id=?", (d["id"],))
    return d


def _save_scan_for(user, target="https://a.example"):
    summary = {"score": 80, "grade": "B", "counts": {"low": 1}, "total": 1, "target": target}
    findings = [{"check_id": "hdr-csp", "category": "headers", "severity": "low",
                 "code": "absent", "params": {}}]
    return db.save_scan(target, summary, findings, user_id=user["id"])


# --------------------------------------------------------------------------- #
# Unités (auth)
# --------------------------------------------------------------------------- #
def test_list_users_counts(authdb):
    a = auth.create_user("a@b.com")
    auth.create_user("admin@b.com", is_admin=True)
    _verify_domain(a["id"], "a.com")
    auth.add_domain(a["id"], "pas-verifie.com")   # non vérifié → pas compté
    _save_scan_for(a, "https://a.com")
    _save_scan_for(a, "https://a.com/2")
    auth.create_pat(a["id"])

    users = {u["email"]: u for u in auth.list_users()}
    assert users["a@b.com"]["verified_domains"] == 1
    assert users["a@b.com"]["scans"] == 2
    assert users["a@b.com"]["active_tokens"] == 1
    assert users["admin@b.com"]["is_admin"] == 1
    assert users["admin@b.com"]["scans"] == 0


def test_count_admins(authdb):
    assert auth.count_admins() == 0
    auth.create_user("u@b.com")
    assert auth.count_admins() == 0
    auth.create_user("admin@b.com", is_admin=True)
    assert auth.count_admins() == 1


def test_delete_user_cascade_and_isolation(authdb):
    a = auth.create_user("a@b.com")
    b = auth.create_user("b@b.com")
    _verify_domain(a["id"], "a.com")
    sid_a = _save_scan_for(a, "https://a.com")
    _, pat_a = auth.create_pat(a["id"])
    sess_a = auth.create_session(a["id"])
    sid_b = _save_scan_for(b, "https://b.com")

    assert auth.delete_user(a["id"]) is True
    # A et toutes ses données ont disparu
    assert auth.get_user_by_id(a["id"]) is None
    assert auth.list_domains(a["id"]) == []
    assert auth.list_pats(a["id"]) == []
    assert db.get_scan(sid_a) is None
    assert auth.get_session_user(sess_a) is None        # session invalidée
    # B est intact (isolation)
    assert auth.get_user_by_id(b["id"]) is not None
    assert db.get_scan(sid_b) is not None
    # supprimer un inconnu → False
    assert auth.delete_user("inexistant") is False


# --------------------------------------------------------------------------- #
# Endpoints (HTTP) : gating + garde-fous
# --------------------------------------------------------------------------- #
def _login(c, user):
    c.cookies.set("sonar_session", auth.create_session(user["id"]))


def test_admin_routes_require_admin(client):
    c, _ = client
    # sans auth → 401
    assert c.get("/api/admin/users").status_code == 401
    # connecté non-admin → 403
    u = auth.create_user("u@b.com")
    _login(c, u)
    assert c.get("/api/admin/users").status_code == 403
    assert c.delete("/api/admin/users/x").status_code == 403


def test_admin_list_and_delete_user(client):
    c, _ = client
    admin = auth.create_user("admin@b.com", is_admin=True)
    victim = auth.create_user("victim@b.com")
    _save_scan_for(victim, "https://v.com")
    _login(c, admin)

    data = c.get("/api/admin/users").json()
    assert data["me_id"] == admin["id"]
    assert {u["email"] for u in data["users"]} == {"admin@b.com", "victim@b.com"}

    assert c.delete("/api/admin/users/" + victim["id"]).status_code == 200
    assert auth.get_user_by_id(victim["id"]) is None
    # inexistant → 404
    assert c.delete("/api/admin/users/" + victim["id"]).status_code == 404


def test_cannot_delete_self(client):
    c, _ = client
    admin = auth.create_user("admin@b.com", is_admin=True)
    auth.create_user("other-admin@b.com", is_admin=True)   # pas le dernier admin
    _login(c, admin)
    r = c.delete("/api/admin/users/" + admin["id"])
    assert r.status_code == 409 and r.json()["code"] == "self"
    assert auth.get_user_by_id(admin["id"]) is not None


def test_cannot_remove_last_admin(client):
    c, _ = client
    admin = auth.create_user("admin@b.com", is_admin=True)
    other = auth.create_user("other@b.com")
    _login(c, admin)
    # rétrograder le seul admin → 409
    r = c.post("/api/admin/users/" + admin["id"] + "/admin", json={"is_admin": False})
    assert r.status_code == 409 and r.json()["code"] == "last_admin"
    assert auth.get_user_by_id(admin["id"])["is_admin"] == 1
    # promouvoir un autre, PUIS la rétrogradation du 1er passe (2 admins)
    assert c.post("/api/admin/users/" + other["id"] + "/admin",
                  json={"is_admin": True}).status_code == 200
    assert c.post("/api/admin/users/" + admin["id"] + "/admin",
                  json={"is_admin": False}).status_code == 200
    assert auth.get_user_by_id(admin["id"])["is_admin"] == 0
