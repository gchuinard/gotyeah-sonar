"""Vérification de domaine par DNS : normalisation, revendication, résolution mockée, gate."""
import sqlite3

import auth
import db


# --------------------------------------------------------------------------- #
# Normalisation / validation
# --------------------------------------------------------------------------- #
def test_normalize_domain():
    assert auth.normalize_domain("https://www.Example.COM/path") == "example.com"
    assert auth.normalize_domain("EXAMPLE.com:8080") == "example.com"
    assert auth.normalize_domain("sub.example.com") == "sub.example.com"
    assert auth.normalize_domain("example.com.") == "example.com"


def test_is_valid_domain():
    assert auth.is_valid_domain("example.com")
    assert auth.is_valid_domain("a.b.co.uk")
    assert not auth.is_valid_domain("localhost")
    assert not auth.is_valid_domain("pas un domaine")
    assert not auth.is_valid_domain("")


# --------------------------------------------------------------------------- #
# Revendication (add / list / get / delete)
# --------------------------------------------------------------------------- #
def test_add_domain_idempotent_and_invalid(authdb):
    u = auth.create_user("a@b.com")
    c1 = auth.add_domain(u["id"], "Example.com")
    c2 = auth.add_domain(u["id"], "example.com")          # même domaine normalisé
    assert c1["id"] == c2["id"]
    assert c1["verified"] is False and len(c1["token"]) >= 16
    assert c1["dns"]["apex"]["value"] == f"sonar-verify={c1['token']}"
    assert c1["dns"]["subdomain"]["host"] == f"_sonar-verify.example.com"
    assert auth.add_domain(u["id"], "localhost") is None  # invalide


def test_list_get_delete_ownership(authdb):
    u = auth.create_user("l@b.com")
    other = auth.create_user("o@b.com")
    c = auth.add_domain(u["id"], "x.com")
    assert any(d["id"] == c["id"] for d in auth.list_domains(u["id"]))
    assert auth.get_domain(c["id"], u["id"])["domain"] == "x.com"
    assert auth.get_domain(c["id"], other["id"]) is None  # propriété respectée
    auth.delete_domain(c["id"], u["id"])
    assert auth.get_domain(c["id"], u["id"]) is None


# --------------------------------------------------------------------------- #
# Vérification DNS (résolution TXT mockée)
# --------------------------------------------------------------------------- #
def _fake_txt(mapping):
    async def f(name):
        return mapping.get(name, [])
    return f


async def test_verify_apex_unlocks_scan(authdb, monkeypatch):
    u = auth.create_user("d@b.com")
    c = auth.add_domain(u["id"], "example.com")
    monkeypatch.setattr(auth, "_txt_records",
                        _fake_txt({"example.com": [f"sonar-verify={c['token']}"]}))
    ok, _msg = await auth.verify_domain(c["id"], u["id"])
    assert ok is True
    assert auth.user_can_scan(u) is True
    assert auth.user_can_scan_target(u, "app.example.com") is True   # sous-domaine OK
    assert auth.user_can_scan_target(u, "example.com") is True
    assert auth.user_can_scan_target(u, "autre.com") is False


async def test_verify_subdomain_method(authdb, monkeypatch):
    u = auth.create_user("d2@b.com")
    c = auth.add_domain(u["id"], "site.org")
    monkeypatch.setattr(auth, "_txt_records",
                        _fake_txt({"_sonar-verify.site.org": [c["token"]]}))
    ok, _ = await auth.verify_domain(c["id"], u["id"])
    assert ok is True


async def test_verify_no_record(authdb, monkeypatch):
    u = auth.create_user("d3@b.com")
    c = auth.add_domain(u["id"], "nope.com")
    monkeypatch.setattr(auth, "_txt_records", _fake_txt({}))
    ok, msg = await auth.verify_domain(c["id"], u["id"])
    assert ok is False and "TXT" in msg
    assert auth.user_can_scan(u) is False


async def test_verify_wrong_token(authdb, monkeypatch):
    u = auth.create_user("d4@b.com")
    c = auth.add_domain(u["id"], "bad.com")
    monkeypatch.setattr(auth, "_txt_records",
                        _fake_txt({"bad.com": ["sonar-verify=un-autre-token"]}))
    ok, _ = await auth.verify_domain(c["id"], u["id"])
    assert ok is False


async def test_verify_already_verified(authdb):
    u = auth.create_user("d5@b.com")
    c = auth.add_domain(u["id"], "done.com")
    auth._mark_verified(c["id"])
    ok, msg = await auth.verify_domain(c["id"], u["id"])
    assert ok is True and "déjà" in msg.lower()


# --------------------------------------------------------------------------- #
# Migration de l'ancienne table verified_domains
# --------------------------------------------------------------------------- #
def test_migration_recreates_old_table(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "sonar.db")
    db.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db.DB_PATH)
    conn.execute("CREATE TABLE verified_domains "
                 "(id TEXT PRIMARY KEY, user_id TEXT, domain TEXT, verified_at TEXT NOT NULL)")
    conn.commit()
    conn.close()
    auth.init_auth()
    cols = {r[1] for r in sqlite3.connect(db.DB_PATH)
            .execute("PRAGMA table_info(verified_domains)").fetchall()}
    assert {"token", "verified", "created_at"} <= cols


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
def test_domains_requires_auth(client):
    c, _ = client
    assert c.get("/api/domains").status_code == 401


def test_domains_invalid_400(client):
    c, _ = client
    u = auth.create_user("e2@b.com")
    c.cookies.set("sonar_session", auth.create_session(u["id"]))
    assert c.post("/api/domains", json={"domain": "localhost"}).status_code == 400


def test_domains_full_flow_unlocks_scan(client, monkeypatch):
    c, _ = client
    u = auth.create_user("e@b.com")
    c.cookies.set("sonar_session", auth.create_session(u["id"]))

    r = c.post("/api/domains", json={"domain": "example.com"})
    assert r.status_code == 201
    claim = r.json()
    assert claim["dns"]["apex"]["value"] == f"sonar-verify={claim['token']}"

    assert any(d["domain"] == "example.com" for d in c.get("/api/domains").json()["domains"])
    assert c.get("/api/me").json()["can_scan"] is False         # pas encore

    monkeypatch.setattr(auth, "_txt_records",
                        _fake_txt({"example.com": [f"sonar-verify={claim['token']}"]}))
    rv = c.post(f"/api/domains/{claim['id']}/verify")
    assert rv.status_code == 200 and rv.json()["verified"] is True

    assert c.get("/api/me").json()["can_scan"] is True          # débloqué !

    assert c.delete(f"/api/domains/{claim['id']}").status_code == 200
    assert c.get("/api/me").json()["can_scan"] is False         # re-verrouillé
