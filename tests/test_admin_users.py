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


def test_purge_expired(authdb):
    u = auth.create_user("u@b.com")
    valid = auth.create_session(u["id"])           # expiration future
    with sqlite3.connect(db.DB_PATH) as conn:      # une session + un lien magique EXPIRÉS
        conn.execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) "
                     "VALUES (?,?,?,?)", ("old", u["id"], "2000-01-01T00:00:00", "2000-01-02T00:00:00"))
        conn.execute("INSERT INTO magic_tokens (token_hash, email, purpose, created_at, expires_at) "
                     "VALUES (?,?,?,?,?)", ("oldmt", "u@b.com", "login",
                                            "2000-01-01T00:00:00", "2000-01-02T00:00:00"))
    assert auth.purge_expired() == 2               # les 2 expirés supprimés
    assert auth.get_session_user(valid) is not None  # la session valide est intacte


def test_wal_mode_enabled(authdb):
    """WAL persistant posé par init_db → lecteurs/écrivains ne se bloquent plus."""
    with db.connect() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_demote_and_delete_guard_last_admin(authdb):
    """Garde-fous ATOMIQUES anti-lockout : ni rétrograder ni supprimer le dernier admin."""
    a1 = auth.create_user("a1@b.com", is_admin=True)
    # un seul admin → rétrogradation refusée, compte intact
    assert auth.demote_admin(a1["id"]) is False
    assert auth.get_user_by_id(a1["id"])["is_admin"] == 1
    assert auth.delete_user_guarded(a1["id"]) == "last_admin"
    assert auth.get_user_by_id(a1["id"]) is not None
    # 2ᵉ admin → on peut rétrograder le 1er
    auth.create_user("a2@b.com", is_admin=True)
    assert auth.demote_admin(a1["id"]) is True
    assert auth.get_user_by_id(a1["id"])["is_admin"] == 0
    # suppression : inconnu → not_found ; non-admin (a1) → ok, cascade
    assert auth.delete_user_guarded("inexistant") == "not_found"
    assert auth.delete_user_guarded(a1["id"]) == "ok"
    assert auth.get_user_by_id(a1["id"]) is None


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


# --------------------------------------------------------------------------- #
# Domaines d'un utilisateur (drill-down admin) : renommer / supprimer
# --------------------------------------------------------------------------- #
def test_update_domain_rename_resets_verification(authdb):
    u = auth.create_user("u@b.com")
    d = _verify_domain(u["id"], "old.com")
    assert auth.get_domain(d["id"], u["id"])["verified"] is True
    res = auth.update_domain(d["id"], u["id"], "New.COM")
    assert res["domain"] == "new.com"      # normalisé
    assert res["verified"] is False        # renommage → non vérifié (nom non prouvé)
    assert res["token"] != d["token"]      # nouveau token de challenge


def test_update_domain_noop_conflict_invalid_missing(authdb):
    u = auth.create_user("u@b.com")
    keep = _verify_domain(u["id"], "keep.com")
    a = auth.add_domain(u["id"], "a.com")
    auth.add_domain(u["id"], "b.com")
    # même nom → no-op, la vérification est préservée
    assert auth.update_domain(keep["id"], u["id"], "keep.com")["verified"] is True
    # nom déjà pris par un autre domaine du même user → "conflict"
    assert auth.update_domain(a["id"], u["id"], "b.com") == "conflict"
    # nom invalide / domaine inexistant → None
    assert auth.update_domain(a["id"], u["id"], "pas valide!!") is None
    assert auth.update_domain("inexistant", u["id"], "x.com") is None


def test_admin_domain_endpoints_list_rename_delete(client):
    c, _ = client
    admin = auth.create_user("admin@b.com", is_admin=True)
    target = auth.create_user("t@b.com")
    d = _verify_domain(target["id"], "old.com")
    _login(c, admin)

    doms = c.get(f"/api/admin/users/{target['id']}/domains").json()["domains"]
    assert [x["domain"] for x in doms] == ["old.com"]

    r = c.patch(f"/api/admin/users/{target['id']}/domains/{d['id']}", json={"domain": "new.com"})
    assert r.status_code == 200
    assert r.json()["domain"]["domain"] == "new.com" and r.json()["domain"]["verified"] is False
    # nom invalide → 400
    assert c.patch(f"/api/admin/users/{target['id']}/domains/{d['id']}",
                   json={"domain": "??"}).status_code == 400
    # suppression → 200, plus de domaine
    assert c.delete(f"/api/admin/users/{target['id']}/domains/{d['id']}").status_code == 200
    assert auth.list_domains(target["id"]) == []


def test_admin_domain_conflict_and_gating(client):
    c, _ = client
    admin = auth.create_user("admin@b.com", is_admin=True)
    t = auth.create_user("t@b.com")
    a = auth.add_domain(t["id"], "a.com")
    auth.add_domain(t["id"], "b.com")
    _login(c, admin)
    assert c.patch(f"/api/admin/users/{t['id']}/domains/{a['id']}",
                   json={"domain": "b.com"}).status_code == 409
    # non-admin → 403 sur les 3 routes
    c.cookies.clear()
    _login(c, auth.create_user("nobody@b.com"))
    assert c.get(f"/api/admin/users/{t['id']}/domains").status_code == 403
    assert c.patch(f"/api/admin/users/{t['id']}/domains/{a['id']}",
                   json={"domain": "x.com"}).status_code == 403
    assert c.delete(f"/api/admin/users/{t['id']}/domains/{a['id']}").status_code == 403


# --------------------------------------------------------------------------- #
# Édition de l'email d'un compte (admin)
# --------------------------------------------------------------------------- #
def test_update_user_email_success_purges_magic_tokens(authdb):
    u = auth.create_user("old@b.com")
    # liens magiques en vol sur l'ancienne ET la future adresse
    with sqlite3.connect(db.DB_PATH) as conn:
        for em in ("old@b.com", "new@b.com"):
            conn.execute("INSERT INTO magic_tokens (token_hash, email, purpose, created_at, expires_at) "
                         "VALUES (?,?,?,?,?)", ("mt-" + em, em, "login",
                                                "2099-01-01T00:00:00", "2099-01-02T00:00:00"))
    res = auth.update_user_email(u["id"], "New@B.com")       # casse normalisée
    assert res["email"] == "new@b.com"
    assert auth.get_user_by_email("new@b.com")["id"] == u["id"]
    with sqlite3.connect(db.DB_PATH) as conn:                # les 2 liens purgés
        n = conn.execute("SELECT COUNT(*) FROM magic_tokens "
                         "WHERE email IN ('old@b.com','new@b.com')").fetchone()[0]
    assert n == 0


def test_update_user_email_noop_invalid_conflict_missing(authdb):
    u = auth.create_user("u@b.com")
    auth.create_user("taken@b.com")
    assert auth.update_user_email(u["id"], "u@b.com")["email"] == "u@b.com"   # no-op
    assert auth.update_user_email(u["id"], "pas-un-email") == "invalid"
    assert auth.update_user_email(u["id"], "taken@b.com") == "conflict"
    assert auth.update_user_email("inexistant", "x@y.com") == "not_found"
    assert auth.get_user_by_id(u["id"])["email"] == "u@b.com"   # inchangé après échecs


def test_admin_update_email_endpoint(client):
    c, _ = client
    admin = auth.create_user("admin@b.com", is_admin=True)
    t = auth.create_user("t@b.com")
    auth.create_user("taken@b.com")
    _login(c, admin)
    # succès
    assert c.patch("/api/admin/users/" + t["id"], json={"email": "moved@b.com"}).status_code == 200
    assert auth.get_user_by_id(t["id"])["email"] == "moved@b.com"
    # invalide → 400 ; conflit → 409 ; inconnu → 404
    assert c.patch("/api/admin/users/" + t["id"], json={"email": "nope"}).status_code == 400
    r = c.patch("/api/admin/users/" + t["id"], json={"email": "taken@b.com"})
    assert r.status_code == 409 and r.json()["code"] == "conflict"
    assert c.patch("/api/admin/users/inexistant", json={"email": "x@y.com"}).status_code == 404
    # non-admin → 403
    c.cookies.clear()
    _login(c, auth.create_user("nobody@b.com"))
    assert c.patch("/api/admin/users/" + t["id"], json={"email": "z@b.com"}).status_code == 403
