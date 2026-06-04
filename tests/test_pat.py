"""Jetons d'accès personnels (PAT) : unités (génération/hash/résolution/révocation/
expiry/scope) + endpoints de gestion (réservés à la session)."""
import datetime
import sqlite3

import auth
import db


# --------------------------------------------------------------------------- #
# Unités : couche PAT dans auth.py
# --------------------------------------------------------------------------- #
def test_pat_created_hashed_and_prefixed(authdb):
    u = auth.create_user("p@b.com")
    raw, meta = auth.create_pat(u["id"], name="mon mcp")
    assert raw.startswith("sonar_pat_") and len(raw) > 40
    assert meta["name"] == "mon mcp" and meta["scope"] == "scans:read"
    assert meta["revoked"] is False and meta["last_used_at"] is None
    # Stocké HASHÉ : seul le SHA-256 est en base, jamais le secret brut.
    row = sqlite3.connect(db.DB_PATH).execute("SELECT * FROM personal_tokens").fetchone()
    stored = sqlite3.connect(db.DB_PATH).execute(
        "SELECT token_hash FROM personal_tokens").fetchone()[0]
    assert stored == auth._hash(raw) and stored != raw
    assert raw not in " ".join(str(c) for c in row)          # nulle part en clair


def test_pat_resolve_ok_updates_last_used(authdb):
    u = auth.create_user("p@b.com")
    raw, _ = auth.create_pat(u["id"])
    got = auth.resolve_pat(raw)
    assert got and got["id"] == u["id"]
    assert auth.list_pats(u["id"])[0]["last_used_at"] is not None   # marqué utilisé


def test_pat_resolve_scope(authdb):
    u = auth.create_user("p@b.com")
    raw, _ = auth.create_pat(u["id"])
    assert auth.resolve_pat(raw, "scans:read") is not None
    assert auth.resolve_pat(raw, "scans:write") is None       # default-deny


def test_pat_resolve_unknown(authdb):
    assert auth.resolve_pat(None) is None
    assert auth.resolve_pat("") is None
    assert auth.resolve_pat("pas-un-token") is None           # mauvais préfixe
    assert auth.resolve_pat("sonar_pat_inconnu") is None      # bon préfixe, inconnu


def test_pat_revoke_owner_scoped(authdb):
    a = auth.create_user("a@b.com")
    b = auth.create_user("b@b.com")
    raw, meta = auth.create_pat(a["id"])
    # B ne peut pas révoquer le jeton de A (pas d'IDOR) -> reste valide.
    assert auth.revoke_pat(meta["id"], b["id"]) is False
    assert auth.resolve_pat(raw) is not None
    # A révoque le sien.
    assert auth.revoke_pat(meta["id"], a["id"]) is True
    assert auth.resolve_pat(raw) is None
    assert auth.list_pats(a["id"])[0]["revoked"] is True
    assert auth.revoke_pat(meta["id"], a["id"]) is False      # idempotent


def test_pat_expired(authdb):
    u = auth.create_user("p@b.com")
    raw, meta = auth.create_pat(u["id"], ttl_days=7)
    assert auth.resolve_pat(raw) is not None
    past = auth._iso(auth._now() - datetime.timedelta(days=1))
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.execute("UPDATE personal_tokens SET expires_at=? WHERE id=?", (past, meta["id"]))
    assert auth.resolve_pat(raw) is None


def test_pat_list_no_secret(authdb):
    u = auth.create_user("p@b.com")
    raw, _ = auth.create_pat(u["id"], name="t1")
    auth.create_pat(u["id"], name="t2")
    items = auth.list_pats(u["id"])
    assert len(items) == 2 and {i["name"] for i in items} == {"t1", "t2"}
    for i in items:
        assert "token" not in i and raw not in str(i)


# --------------------------------------------------------------------------- #
# Endpoints de gestion : création (secret affiché une fois), liste, révocation.
# Réservés à la SESSION (cookie) — testé default-deny côté PAT à l'Étape 2.
# --------------------------------------------------------------------------- #
def test_tokens_endpoints_session(client):
    c, _appmod = client
    u = auth.create_user("e@b.com")
    c.cookies.set("sonar_session", auth.create_session(u["id"]))

    r = c.post("/api/tokens", json={"name": "mcp"})
    assert r.status_code == 201
    body = r.json()
    assert body["token"].startswith("sonar_pat_") and body["name"] == "mcp"
    tid = body["id"]
    # Le secret renvoyé fonctionne réellement pour s'authentifier.
    assert auth.resolve_pat(body["token"])["id"] == u["id"]

    items = c.get("/api/tokens").json()["tokens"]
    assert len(items) == 1 and "token" not in items[0]        # liste sans secret

    assert c.delete(f"/api/tokens/{tid}").status_code == 200
    assert auth.resolve_pat(body["token"]) is None            # révoqué


def test_tokens_endpoints_require_session(client):
    c, _appmod = client
    assert c.get("/api/tokens").status_code == 401
    assert c.post("/api/tokens", json={}).status_code == 401
    assert c.delete("/api/tokens/whatever").status_code == 401
