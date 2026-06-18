"""Annotations de findings : persistance, identité stable, report scan→scan, API session-only.

L'annotation est rattachée au (user, domaine, identité du finding) — la MÊME identité que le
diff (`scan_compare.finding_key`, evidence exclue) — donc elle se reporte automatiquement de
scan en scan du même domaine, et N'AFFECTE JAMAIS le score (purement documentaire).
"""
import auth
import db
import scan_compare


def _finding(check_id="hdr-csp", code="absent", params=None, evidence="x"):
    return {"check_id": check_id, "category": "headers", "severity": "high",
            "code": code, "params": params or {}, "evidence": evidence}


_SUMMARY = {"score": 50, "grade": "E", "counts": {}, "total": 1}


# ---- identité (clé partagée avec le diff) ----

def test_finding_key_ignores_evidence():
    # L'evidence est volatile → exclue de la clé : l'annotation suit le finding même si sa
    # preuve change d'un scan à l'autre.
    k1 = scan_compare.finding_key(_finding(params={"a": 1}, evidence="v1"))
    k2 = scan_compare.finding_key(_finding(params={"a": 1}, evidence="v2-DIFFERENT"))
    assert k1 == k2
    # ...mais des params différents donnent des findings distincts.
    assert k1 != scan_compare.finding_key(_finding(params={"a": 2}))


def test_target_domain_normalizes():
    assert scan_compare.target_domain("https://Ex.COM/path") == "ex.com"
    assert scan_compare.target_domain("https://ex.com/autre") == "ex.com"


# ---- DB ----

def test_db_annotation_upsert_get_delete(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    db.init_db()
    key = scan_compare.finding_key(_finding())

    a = db.upsert_annotation("alice", "ex.com", key, "on laisse", True)
    assert a["text"] == "on laisse" and a["accepted"] is True

    got = db.get_annotations("alice", "ex.com")
    assert got[key]["text"] == "on laisse" and got[key]["accepted"] is True

    # upsert = mise à jour en place (une seule annotation par (user, domaine, finding)).
    db.upsert_annotation("alice", "ex.com", key, "maj", False)
    got = db.get_annotations("alice", "ex.com")
    assert len(got) == 1 and got[key]["text"] == "maj" and got[key]["accepted"] is False

    # isolation stricte par utilisateur.
    assert db.get_annotations("bob", "ex.com") == {}

    assert db.delete_annotation("alice", "ex.com", key) is True
    assert db.delete_annotation("alice", "ex.com", key) is False   # idempotent
    assert db.get_annotations("alice", "ex.com") == {}


# ---- API (endpoint d'écriture session-only + greffe au rendu) ----

def _login(c, email="a@b.com"):
    u = auth.create_user(email)
    c.cookies.set("sonar_session", auth.create_session(u["id"]))
    return u


def test_annotation_requires_session(client):
    c, _ = client
    assert c.post("/api/annotations", json={}).status_code == 401


def test_annotation_crud_and_carryover(client):
    c, _ = client
    u = _login(c)
    f = _finding()
    sid1 = db.save_scan("https://ex.com/", _SUMMARY, [f], user_id=u["id"])

    # créer
    r = c.post("/api/annotations", json={
        "scan_id": sid1, "check_id": f["check_id"], "code": f["code"],
        "params": f["params"], "text": "on laisse, c'est voulu", "accepted": True})
    assert r.status_code == 200 and r.json()["annotation"]["accepted"] is True

    # le rapport rendu porte l'annotation
    rep = c.get(f"/api/scan/{sid1}").json()
    assert rep["findings"][0]["annotation"]["text"] == "on laisse, c'est voulu"

    # REPORT scan→scan : un AUTRE scan du même domaine (URL différente, evidence absente) où le
    # même finding revient → l'annotation réapparaît automatiquement.
    sid2 = db.save_scan("https://ex.com/autre", _SUMMARY,
                        [_finding(evidence=None)], user_id=u["id"])
    rep2 = c.get(f"/api/scan/{sid2}").json()
    assert rep2["findings"][0]["annotation"]["accepted"] is True

    # suppression : texte vide ET non accepté
    r = c.post("/api/annotations", json={
        "scan_id": sid1, "check_id": f["check_id"], "code": f["code"],
        "params": f["params"], "text": "", "accepted": False})
    assert r.status_code == 200 and r.json()["annotation"] is None
    assert "annotation" not in c.get(f"/api/scan/{sid1}").json()["findings"][0]


def test_annotation_other_user_cannot(client):
    c, _ = client
    u = _login(c)
    sid = db.save_scan("https://ex.com/", _SUMMARY, [_finding()], user_id=u["id"])
    # bascule sur un autre compte : il ne possède pas le scan → 404 (pas de fuite).
    c.cookies.set("sonar_session", auth.create_session(auth.create_user("b@b.com")["id"]))
    r = c.post("/api/annotations", json={
        "scan_id": sid, "check_id": "hdr-csp", "code": "absent", "params": {}, "text": "x"})
    assert r.status_code == 404


def test_annotation_accepted_only_no_text(client):
    # Marquer « risque accepté » SANS texte crée bien une annotation (≠ suppression).
    c, _ = client
    u = _login(c)
    f = _finding()
    sid = db.save_scan("https://ex.com/", _SUMMARY, [f], user_id=u["id"])
    r = c.post("/api/annotations", json={
        "scan_id": sid, "check_id": f["check_id"], "code": f["code"],
        "params": f["params"], "text": "", "accepted": True})
    assert r.status_code == 200
    a = r.json()["annotation"]
    assert a is not None and a["accepted"] is True and a["text"] == ""
    assert c.get(f"/api/scan/{sid}").json()["findings"][0]["annotation"]["accepted"] is True


def test_annotation_rejects_unknown_finding(client):
    # Anti-forge / anti-DoS de stockage : on n'annote qu'un finding RÉELLEMENT présent dans le scan.
    c, _ = client
    u = _login(c)
    sid = db.save_scan("https://ex.com/", _SUMMARY, [_finding()], user_id=u["id"])
    r = c.post("/api/annotations", json={
        "scan_id": sid, "check_id": "ghost", "code": "nope", "params": {"x": 1}, "text": "spam"})
    assert r.status_code == 400


def test_annotations_purged_on_account_deletion(authdb):
    # Cascade : supprimer un compte purge ses annotations (pas de lignes orphelines, dépôt public).
    import auth as authmod
    u = authmod.create_user("z@b.com")
    db.upsert_annotation(u["id"], "ex.com", scan_compare.finding_key(_finding()), "x", True)
    assert db.get_annotations(u["id"], "ex.com")
    assert authmod.delete_user(u["id"]) is True
    assert db.get_annotations(u["id"], "ex.com") == {}


def test_annotation_pat_is_read_only(client):
    c, _ = client
    u = auth.create_user("a@b.com")
    raw, _meta = auth.create_pat(u["id"], name="ro")
    sid = db.save_scan("https://ex.com/", _SUMMARY, [_finding()], user_id=u["id"])
    hdr = {"Authorization": f"Bearer {raw}"}
    # un PAT lit le rapport...
    assert c.get(f"/api/scan/{sid}", headers=hdr).status_code == 200
    # ...mais NE peut PAS écrire une annotation (écriture = session uniquement).
    r = c.post("/api/annotations", headers=hdr, json={
        "scan_id": sid, "check_id": "hdr-csp", "code": "absent", "params": {}, "text": "x"})
    assert r.status_code == 401
