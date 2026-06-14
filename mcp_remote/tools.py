"""Logique PURE des outils du MCP distant — testable SANS le SDK fastmcp.

`remote.py` ne fait plus que le câblage : il résout l'utilisateur depuis le token OAuth
(`_resolve_user`), puis appelle ces fonctions. Tout ici n'importe que `auth`/`db`/
`scan_jobs`/`scan_compare`/`scanner.i18n` (jamais fastmcp), donc importable et testable
directement — c'est la surface PUBLIQUE et ACTIVE du serveur, on veut la couvrir.

Chaque fonction reçoit l'utilisateur DÉJÀ résolu (ou None) ; le garde-fou identité
(`_require_user`) et le cloisonnement par propriétaire (`_owner` : admin = tout, sinon
ses propres scans → pas d'IDOR) sont centralisés ici.
"""
from __future__ import annotations

from urllib.parse import urlparse


# --------------------------------------------------------------------------- #
# Identité : access token (claims.email, ou userinfo en repli) -> compte Sonar
# --------------------------------------------------------------------------- #
def _claim_truthy(val) -> bool:
    """`email_verified` (OIDC) est un booléen ; on tolère la string "true" par robustesse."""
    return val is True or (isinstance(val, str) and val.strip().lower() == "true")


def resolve_user_from_token(tok, userinfo_endpoint: str | None = None, *, http_get=None):
    """Mappe un access token vers un compte Sonar, ou None.

    tok : objet avec `.claims` (dict) et `.token` (str), ou None.
    Pocket ID ne met PAS l'email dans l'access token (seulement dans le userinfo) → repli
    sur le userinfo avec le token porteur. `http_get` est injectable pour les tests.

    Modes d'inscription (gouvernés par SONAR_OPEN_REGISTRATION, le MÊME flag que le web) :
      • FERMÉ (défaut) : lookup strict — seules les identités créées par l'admin existent.
        Comportement historique ; un email inconnu → None. (En pratique l'IdP est lui-même
        en signup fermé, donc seul l'admin peut même atteindre cette étape.)
      • OUVERT : surface PUBLIQUE. On EXIGE alors un email VÉRIFIÉ par l'IdP (claim
        `email_verified`) pour TOUTE correspondance — création comme mapping sur un compte
        existant — puis on crée le compte à la volée au 1er login. C'est le REMPART
        anti-usurpation : sans email vérifié, un inconnu s'inscrivant chez un IdP laxiste
        avec l'email de l'admin récupérerait le compte admin. On lit l'email ET sa vérif à
        la MÊME source (claims, ou userinfo en repli — Pocket ID ne met l'email que là).
    """
    import auth as sonar_auth

    if not tok:
        return None
    claims = getattr(tok, "claims", None) or {}
    email = (claims.get("email") or "").strip()
    verified = _claim_truthy(claims.get("email_verified"))
    if not email and userinfo_endpoint and getattr(tok, "token", None):
        getter = http_get
        if getter is None:
            import httpx
            getter = httpx.get
        try:
            r = getter(userinfo_endpoint,
                       headers={"Authorization": f"Bearer {tok.token}"}, timeout=10)
            if r.status_code == 200:
                info = r.json()
                email = (info.get("email") or "").strip()
                verified = _claim_truthy(info.get("email_verified"))
        except Exception:
            pass
    if not email:
        return None
    norm = sonar_auth.normalize_email(email)
    if sonar_auth.open_registration():
        # Surface publique : email vérifié obligatoire (anti-usurpation), puis auto-création.
        return sonar_auth.get_or_create_user(norm) if verified else None
    # Inscription fermée : lookup strict, identités gérées par l'admin (comportement historique).
    return sonar_auth.get_user_by_email(norm)


# --------------------------------------------------------------------------- #
# Helpers communs
# --------------------------------------------------------------------------- #
def _require_user(user):
    if not user:
        raise ValueError("Aucun compte Sonar ne correspond à cette identité.")


def _owner(user):
    """Portée des lectures : None (= tout l'historique) pour l'admin, sinon ses scans."""
    return None if user.get("is_admin") else user["id"]


def _pick_lang(user, lang):
    from scanner import i18n
    available = set(i18n.available_langs())
    return lang if (lang and lang in available) else (user.get("lang") or "fr")


def _render(data: dict, chosen: str) -> dict:
    from scanner import i18n
    data["findings"] = [{**f, **i18n.render_finding(f, chosen)} for f in data.get("findings", [])]
    return data


# --------------------------------------------------------------------------- #
# Outils — lectures
# --------------------------------------------------------------------------- #
async def list_domains_logic(user) -> list[dict]:
    import auth as sonar_auth
    _require_user(user)
    return sonar_auth.list_domains(user["id"])


async def list_scans_logic(user, domain: str | None = None) -> list[dict]:
    import db
    _require_user(user)
    scans = db.list_scans(user_id=_owner(user))
    if domain:
        needle = domain.strip().lower()
        scans = [s for s in scans if needle in ((s.get("target") or "").lower())]
    return scans


async def get_report_logic(user, scan_id: str, lang: str | None = None) -> dict:
    import db
    _require_user(user)
    data = db.get_scan(scan_id, user_id=_owner(user))
    if not data:
        raise ValueError("Scan introuvable (ou n'appartient pas à ce compte).")
    chosen = _pick_lang(user, lang)
    _render(data, chosen)
    data["lang"] = chosen
    return data


async def diff_scans_logic(user, scan_a: str, scan_b: str, lang: str | None = None) -> dict:
    import db
    import scan_compare
    _require_user(user)
    owner = _owner(user)
    before = db.get_scan(scan_a, user_id=owner)
    after = db.get_scan(scan_b, user_id=owner)
    if not before or not after:
        raise ValueError("Scan introuvable (ou n'appartient pas à ce compte).")
    chosen = _pick_lang(user, lang)
    _render(before, chosen)
    _render(after, chosen)
    out = scan_compare.diff_reports(before, after)
    out["lang"] = chosen
    return out


async def get_fix_logic(user, scan_id: str, check_id: str | None = None,
                        code: str | None = None, lang: str | None = None) -> list[dict]:
    import db
    import scan_compare
    _require_user(user)
    data = db.get_scan(scan_id, user_id=_owner(user))
    if not data:
        raise ValueError("Scan introuvable (ou n'appartient pas à ce compte).")
    chosen = _pick_lang(user, lang)
    _render(data, chosen)
    return scan_compare.extract_fixes(data, check_id, code)


async def get_scan_status_logic(user, scan_id: str) -> dict:
    import db
    import scan_jobs
    _require_user(user)
    data = db.get_scan(scan_id, user_id=_owner(user))
    if not data:
        raise ValueError("Scan introuvable (ou n'appartient pas à ce compte).")
    status = data.get("status") or "done"
    out = {"scan_id": scan_id, "status": status}
    if status == "running":
        prog = scan_jobs.progress_of(scan_id)
        if prog:
            out.update(prog)
    else:
        out.update(score=data.get("score"), grade=data.get("grade"), counts=data.get("counts"))
    return out


# --------------------------------------------------------------------------- #
# Outil — action (scan)
# --------------------------------------------------------------------------- #
async def run_scan_logic(user, domain: str, profile: str = "full") -> dict:
    import auth as sonar_auth
    import scan_jobs
    from scanner.runner import normalize_target

    _require_user(user)
    if not sonar_auth.user_can_scan(user):
        raise ValueError("Scan verrouillé : vérifie d'abord un domaine dans Sonar.")
    target = normalize_target(domain)
    host = urlparse(target).hostname or ""
    if not sonar_auth.user_can_scan_target(user, host):
        raise ValueError(
            "Tu ne peux scanner que tes domaines vérifiés (ou leurs sous-domaines).")
    if not sonar_auth.scan_rate_ok(user["id"]):
        raise ValueError("Trop de scans lancés récemment. Réessaie dans quelques minutes.")

    fast = (profile or "full").strip().lower() in ("fast", "rapide", "quick")
    scan_id = scan_jobs.start_scan(target, user["id"], fast=fast)
    data = await scan_jobs.wait_for_completion(scan_id)
    if data is None:
        return {
            "scan_id": scan_id,
            "status": "running",
            "message": ("Scan lancé. Suis-le avec get_scan_status('"
                        f"{scan_id}'), puis get_report('{scan_id}') une fois terminé."),
        }
    chosen = user.get("lang") or "fr"
    _render(data, chosen)
    data["lang"] = chosen
    return data
