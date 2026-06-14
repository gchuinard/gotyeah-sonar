"""Couche web : page, auth par lien magique, et flux SSE du moteur.

Volontairement mince : l'auth (liens, sessions, gate) vit dans `auth.py`, l'envoi
d'email dans `mailer.py`, le moteur dans `scanner/`. Ici on câble les routes et on
protège le scan + l'historique derrière la session.
"""
from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote, urlparse

from fastapi import FastAPI, Query, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)

import auth
import db
import mailer
from scanner import i18n
from scanner.runner import normalize_target, run_scan

BASE = Path(__file__).parent
PAGE = (BASE / "templates" / "index.html").read_text(encoding="utf-8")
LOGIN_PAGE = (BASE / "templates" / "login.html").read_text(encoding="utf-8")
HELP_MCP_PAGE = (BASE / "templates" / "help_mcp.html").read_text(encoding="utf-8")

SESSION_COOKIE = "sonar_session"
LANG_COOKIE = "sonar_lang"

# Heartbeat SSE : si aucun event n'arrive pendant ce délai (ex. nuclei qui tourne
# plusieurs minutes), on émet un commentaire `: ...` pour garder le flux actif et
# empêcher un proxy (nginx ~60 s, Cloudflare ~100 s) de couper la connexion inactive.
SSE_HEARTBEAT_SECS = 15.0


def _env_bool(name: str, default: bool = False) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


def _cookie_kwargs() -> dict:
    # secure=True en prod (derrière NPM en HTTPS) ; passe SONAR_COOKIE_SECURE=false
    # pour tester en local sur http://.
    return dict(httponly=True, secure=_env_bool("SONAR_COOKIE_SECURE", True),
                samesite="lax", path="/")


def _client_ip(request: Request) -> str:
    # Derrière Nginx Proxy Manager, l'IP réelle est dans X-Forwarded-For.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"


def _base_url(request: Request) -> str:
    base = (os.environ.get("SONAR_BASE_URL") or "").strip().rstrip("/")
    return base or str(request.base_url).rstrip("/")


def _safe_next(raw: str | None) -> str | None:
    """Chemin de redirection post-login SÛR (anti open-redirect) : uniquement un
    chemin relatif same-origin (commence par un seul '/', sans schéma ni hôte).
    Sert au flux de consentement MCP (retour sur /mcp/consent après le lien magique)."""
    if not raw or len(raw) > 512:
        return None
    if not raw.startswith("/") or raw.startswith("//") or "\\" in raw or "://" in raw:
        return None
    return raw


def _current_user(request: Request):
    return auth.get_session_user(request.cookies.get(SESSION_COOKIE))


def _bearer_token(request: Request) -> str | None:
    """Jeton d'un en-tête 'Authorization: Bearer <token>' (insensible à la casse), sinon None."""
    header = request.headers.get("authorization") or ""
    if header[:7].lower() == "bearer ":
        return header[7:].strip() or None
    return None


def _pat_or_session_user(request: Request, scope: str = "scans:read"):
    """Utilisateur courant pour les endpoints de LECTURE exposés au MCP (concept
    « require_pat »). Accepte la session (cookie) OU un PAT « Authorization: Bearer
    sonar_pat_… » portant le `scope` requis. Retourne l'utilisateur ou None.

    On NE touche PAS `_current_user` : les routes d'écriture/admin restent en cookie
    seul, donc un PAT ne peut JAMAIS les atteindre (default-deny par construction).
    Le jeton n'est jamais journalisé.
    """
    user = _current_user(request)            # session (cookie) d'abord
    if user:
        return user
    token = _bearer_token(request)           # sinon PAT, scope imposé
    if token:
        return auth.resolve_pat(token, required_scope=scope)
    return None


def _lang(request: Request, user=None) -> str:
    """Langue active : préférence utilisateur → cookie → Accept-Language → fr.

    On n'accepte qu'une langue réellement disponible (un fichier de locale existe),
    sinon on retombe sur `fr`.
    """
    available = set(i18n.available_langs())
    if user and user.get("lang") and user["lang"] in available:
        return user["lang"]
    cookie = request.cookies.get(LANG_COOKIE)
    if cookie and cookie in available:
        return cookie
    for part in (request.headers.get("accept-language") or "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in available:
            return code
    return "fr"


def _pick_lang(lang_param, request: Request, user=None) -> str:
    """Langue explicite (?lang=) si valide, sinon la langue active déduite."""
    if lang_param and lang_param in set(i18n.available_langs()):
        return lang_param
    return _lang(request, user)


def _render_index(request: Request, user) -> str:
    """Injecte le bootstrap i18n (langue + dict UI) dans la page (no-op si absent)."""
    lang = _lang(request, user)
    boot = json.dumps(
        {"lang": lang, "available": i18n.available_langs(), "ui": i18n.render_ui(lang),
         # Pour guider la connexion MCP côté dashboard : URL publique + si le connecteur
         # distant (claude.ai web) est réellement monté.
         "base_url": _base_url(request), "mcp_remote": _REMOTE_APP is not None},
        ensure_ascii=False,
    )
    return PAGE.replace("__SONAR_BOOTSTRAP__", boot)


# --------------------------------------------------------------------------- #
# MCP distant (claude.ai web) — surface OAuth PUBLIQUE, DÉSACTIVÉE par défaut.
# On ne construit (et n'importe le SDK `mcp`) que si SONAR_MCP_REMOTE=on ET qu'une
# SONAR_BASE_URL HTTPS absolue est fournie (OAuth l'exige). Fail-soft : toute erreur
# d'init désactive le MCP distant sans empêcher le reste du site de démarrer.
# Le transport est monté en DERNIER (voir bas de fichier) et son session manager
# tourne dans le lifespan ci-dessous.
# --------------------------------------------------------------------------- #
_REMOTE_MCP = None
_REMOTE_APP = None
if _env_bool("SONAR_MCP_REMOTE"):
    _remote_base = (os.environ.get("SONAR_BASE_URL") or "").strip().rstrip("/")
    if not _remote_base.startswith("https://"):
        print("[mcp-remote] SONAR_MCP_REMOTE=on mais SONAR_BASE_URL HTTPS absente "
              "→ MCP distant désactivé (OAuth exige une URL HTTPS publique).")
    else:
        try:
            from mcp_remote.remote import build_remote

            _REMOTE_MCP, _REMOTE_APP = build_remote(_remote_base)
            print(f"[mcp-remote] activé sur {_remote_base}/mcp (auth fédérée OIDC)")
        except Exception as exc:  # dépendance absente, IdP injoignable, conflit de version…
            _REMOTE_MCP = _REMOTE_APP = None
            print(f"[mcp-remote] échec d'init ({exc!r}) → MCP distant désactivé.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    auth.init_auth()
    auth.bootstrap_admin()  # imprime un lien admin one-time dans les logs si configuré
    if _REMOTE_APP is not None:
        # Le transport Streamable HTTP a son propre lifespan (gestionnaire de sessions) ;
        # sans lui, /mcp plante. On le compose avec le nôtre. Plus de tables OAuth maison :
        # l'auth est déléguée à l'IdP (tokens JWT validés via la discovery OIDC).
        async with _REMOTE_APP.lifespan(app):
            yield
    else:
        yield


app = FastAPI(title="Sonar", lifespan=lifespan)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = _current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return HTMLResponse(_render_index(request, user))


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(LOGIN_PAGE)


@app.get("/help/mcp", response_class=HTMLResponse)
async def help_mcp(request: Request):
    """Page d'aide : connecter une app IA à Sonar via MCP (10 clients). L'URL publique de
    l'instance est injectée pour pré-remplir les exemples (URL /mcp + commande locale)."""
    user = _current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    page = HELP_MCP_PAGE.replace("__SONAR_HELP_BASE__", json.dumps(_base_url(request)))
    return HTMLResponse(page)


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
@app.post("/api/auth/request")
async def auth_request(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    email = body.get("email", "") if isinstance(body, dict) else ""
    nxt = _safe_next(body.get("next") if isinstance(body, dict) else None)

    raw = auth.request_login_link(email, _client_ip(request))
    if raw:
        link = f"{_base_url(request)}/auth/verify?token={raw}"
        if nxt:
            # Retour post-login (ex. page de consentement MCP). Validé same-origin.
            link += f"&next={quote(nxt, safe='')}"
        # Pas encore de session : langue déduite du cookie / de l'Accept-Language.
        await mailer.send_magic_link(auth.normalize_email(email), link, _lang(request))

    # Message adapté au mode d'inscription :
    #  - inscription OUVERTE : un lien est envoyé pour tout email valide (le compte se crée
    #    à la connexion) → on l'annonce directement, l'existence du compte n'est pas un secret ;
    #  - invite-only : message GÉNÉRIQUE qui ne révèle pas si le compte existe (anti-énumération).
    if auth.open_registration():
        message = "Un lien de connexion vient d'être envoyé à cet email."
    else:
        message = "Si un compte existe pour cet email, un lien de connexion vient d'être envoyé."
    return JSONResponse({"ok": True, "message": message})


@app.get("/auth/verify")
async def auth_verify(token: str = Query(...), next: str = Query(None)):
    session_raw, _user = auth.complete_login(token)
    if not session_raw:
        return RedirectResponse("/login?error=expired", status_code=302)
    # Retour post-login : same-origin uniquement (anti open-redirect), sinon accueil.
    dest = _safe_next(next) or "/"
    resp = RedirectResponse(dest, status_code=302)
    resp.set_cookie(SESSION_COOKIE, session_raw, max_age=auth.session_max_age(), **_cookie_kwargs())
    return resp


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    auth.destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/me")
async def api_me(request: Request):
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    payload = {
        "email": user["email"],
        "is_admin": bool(user["is_admin"]),
        "can_scan": auth.user_can_scan(user),
        "lang": _lang(request, user),
        "available_langs": i18n.available_langs(),
    }
    if user["is_admin"]:
        payload["admin_scan_any"] = auth.admin_scan_any()
    return JSONResponse(payload)


@app.post("/api/admin/scan-any")
async def api_admin_scan_any(request: Request):
    """Toggle (admin only) : l'admin scanne-t-il sans vérification DNS ?"""
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    if not user["is_admin"]:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        body = await request.json()
    except Exception:
        body = {}
    enabled = bool(body.get("enabled")) if isinstance(body, dict) else False
    auth.set_admin_scan_any(enabled)
    return JSONResponse({"ok": True, "admin_scan_any": enabled})


# --------------------------------------------------------------------------- #
# Administration des comptes (réservé aux admins, session cookie uniquement —
# jamais via un PAT lecture seule). Garde-fous anti-lockout : on ne supprime pas
# son propre compte ici, ni le dernier admin.
# --------------------------------------------------------------------------- #
def _require_admin(request: Request):
    """(user, None) si l'appelant est un admin connecté ; sinon (None, réponse d'erreur)."""
    user = _current_user(request)
    if not user:
        return None, JSONResponse({"error": "auth required"}, status_code=401)
    if not user["is_admin"]:
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return user, None


@app.get("/api/admin/users")
async def admin_users_list(request: Request):
    """Liste tous les comptes + compteurs (domaines/scans/jetons) — admin only."""
    user, err = _require_admin(request)
    if err:
        return err
    return JSONResponse({"users": auth.list_users(), "me_id": user["id"]})


@app.post("/api/admin/users/{user_id}/admin")
async def admin_set_admin(request: Request, user_id: str):
    """Promeut/rétrograde un compte admin. Refuse de retirer le DERNIER admin."""
    user, err = _require_admin(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        body = {}
    make_admin = bool(body.get("is_admin")) if isinstance(body, dict) else False
    target = auth.get_user_by_id(user_id)
    if not target:
        return JSONResponse({"error": "not found"}, status_code=404)
    if not make_admin and target["is_admin"] and auth.count_admins() <= 1:
        return JSONResponse(
            {"error": "Impossible de retirer le dernier admin.", "code": "last_admin"},
            status_code=409)
    auth.set_admin(user_id, make_admin)
    return JSONResponse({"ok": True})


@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(request: Request, user_id: str):
    """Supprime un compte et toutes ses données. Refuse soi-même et le dernier admin."""
    user, err = _require_admin(request)
    if err:
        return err
    if user_id == user["id"]:
        return JSONResponse(
            {"error": "Tu ne peux pas supprimer ton propre compte ici.", "code": "self"},
            status_code=409)
    target = auth.get_user_by_id(user_id)
    if not target:
        return JSONResponse({"error": "not found"}, status_code=404)
    if target["is_admin"] and auth.count_admins() <= 1:
        return JSONResponse(
            {"error": "Impossible de supprimer le dernier admin.", "code": "last_admin"},
            status_code=409)
    auth.delete_user(user_id)
    return JSONResponse({"ok": True})


@app.get("/api/admin/users/{user_id}/domains")
async def admin_user_domains(request: Request, user_id: str):
    """Domaines d'un utilisateur donné (drill-down depuis la liste des comptes)."""
    _, err = _require_admin(request)
    if err:
        return err
    if auth.get_user_by_id(user_id) is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"domains": auth.list_domains(user_id)})


@app.patch("/api/admin/users/{user_id}/domains/{domain_id}")
async def admin_update_domain(request: Request, user_id: str, domain_id: str):
    """Renomme un domaine d'un utilisateur. Le renommage le remet en attente de vérif."""
    _, err = _require_admin(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        body = {}
    new_domain = body.get("domain", "") if isinstance(body, dict) else ""
    res = auth.update_domain(domain_id, user_id, new_domain)
    if res is None:
        return JSONResponse(
            {"error": "Domaine invalide ou introuvable.", "code": "invalid"}, status_code=400)
    if res == "conflict":
        return JSONResponse(
            {"error": "Cet utilisateur a déjà un domaine portant ce nom.", "code": "conflict"},
            status_code=409)
    return JSONResponse({"domain": res})


@app.delete("/api/admin/users/{user_id}/domains/{domain_id}")
async def admin_delete_domain(request: Request, user_id: str, domain_id: str):
    """Supprime un domaine d'un utilisateur."""
    _, err = _require_admin(request)
    if err:
        return err
    auth.delete_domain(domain_id, user_id)
    return JSONResponse({"ok": True})


# --------------------------------------------------------------------------- #
# i18n (chrome UI + préférence de langue)
# --------------------------------------------------------------------------- #
@app.get("/api/i18n/ui")
async def i18n_ui(request: Request, lang: str = Query(None)):
    user = _current_user(request)
    chosen = _pick_lang(lang, request, user)
    return JSONResponse({
        "lang": chosen,
        "available": i18n.available_langs(),
        "ui": i18n.render_ui(chosen),
    })


@app.post("/api/lang")
async def set_lang(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    lang = body.get("lang", "") if isinstance(body, dict) else ""
    if lang not in set(i18n.available_langs()):
        return JSONResponse({"error": "langue non disponible"}, status_code=400)
    user = _current_user(request)
    if user:
        auth.set_user_lang(user["id"], lang)
    resp = JSONResponse({"ok": True, "lang": lang})
    # Cookie non-httponly : non sensible, et permet au front de connaître la langue.
    resp.set_cookie(LANG_COOKIE, lang, max_age=365 * 86400,
                    secure=_env_bool("SONAR_COOKIE_SECURE", True), samesite="lax", path="/")
    return resp


# --------------------------------------------------------------------------- #
# Domaines (vérification DNS — débloque le scan)
# --------------------------------------------------------------------------- #
@app.get("/api/domains")
async def domains_list(request: Request):
    user = _pat_or_session_user(request)   # lecture : session OU PAT scans:read
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    return JSONResponse({"domains": auth.list_domains(user["id"])})


@app.post("/api/domains")
async def domains_add(request: Request):
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        body = {}
    domain = body.get("domain", "") if isinstance(body, dict) else ""
    claim = auth.add_domain(user["id"], domain)
    if not claim:
        return JSONResponse({"error": "Domaine invalide."}, status_code=400)
    return JSONResponse(claim, status_code=201)


@app.post("/api/domains/{domain_id}/verify")
async def domains_verify(request: Request, domain_id: str):
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    if auth.get_domain(domain_id, user["id"]) is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    ok, message = await auth.verify_domain(domain_id, user["id"])
    return JSONResponse({
        "verified": ok,
        "message": message,
        "domain": auth.get_domain(domain_id, user["id"]),
    })


@app.delete("/api/domains/{domain_id}")
async def domains_delete(request: Request, domain_id: str):
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    auth.delete_domain(domain_id, user["id"])
    return JSONResponse({"ok": True})


# --------------------------------------------------------------------------- #
# Jetons d'accès personnels (PAT) — gestion RÉSERVÉE À LA SESSION (cookie).
# Un PAT donne un accès LECTURE SEULE à l'API (pour le MCP). Volontairement
# inaccessible via un PAT : on ne crée/révoque pas de jeton avec un jeton.

@app.get("/api/tokens")
async def tokens_list(request: Request):
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    return JSONResponse({"tokens": auth.list_pats(user["id"])})


@app.post("/api/tokens")
async def tokens_create(request: Request):
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        body = {}
    body = body if isinstance(body, dict) else {}
    name = body.get("name") or ""
    raw_ttl = body.get("ttl_days")
    try:
        ttl = int(raw_ttl) if raw_ttl not in (None, "") else None
    except (TypeError, ValueError):
        ttl = None
    if ttl is not None and ttl <= 0:
        ttl = None
    raw, meta = auth.create_pat(user["id"], name=name, ttl_days=ttl)
    # `token` (le secret brut) n'est renvoyé qu'ICI, une seule fois.
    return JSONResponse({"token": raw, **meta}, status_code=201)


@app.delete("/api/tokens/{token_id}")
async def tokens_revoke(request: Request, token_id: str):
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    auth.revoke_pat(token_id, user["id"])
    return JSONResponse({"ok": True})


@app.delete("/api/tokens/{token_id}/purge")
async def tokens_delete(request: Request, token_id: str):
    """Supprime DÉFINITIVEMENT un jeton DÉJÀ révoqué (nettoyage de la liste).

    On impose de révoquer d'abord (la révocation coupe l'accès ; cette purge ne fait
    qu'effacer la ligne). 409 si le jeton n'existe pas ou n'est pas encore révoqué."""
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    if not auth.delete_pat(token_id, user["id"]):
        return JSONResponse(
            {"error": "Révoque le jeton avant de le supprimer.", "code": "not_revoked"},
            status_code=409)
    return JSONResponse({"ok": True})


# --------------------------------------------------------------------------- #
# Scan + historique (protégés par la session)
# --------------------------------------------------------------------------- #
@app.get("/api/scan/stream")
async def scan_stream(request: Request, target: str = Query(..., min_length=3)):
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    if not auth.user_can_scan(user):
        return JSONResponse(
            {"error": "Scan verrouillé : vérifie d'abord un domaine.", "code": "no_verified_domain"},
            status_code=403)
    host = urlparse(normalize_target(target)).hostname or ""
    if not auth.user_can_scan_target(user, host):
        return JSONResponse(
            {"error": "Tu ne peux scanner que tes domaines vérifiés.", "code": "domain_not_owned"},
            status_code=403)

    lang = _lang(request, user)

    async def gen():
        summary = None
        findings = None
        agen = run_scan(target)
        # On attend le prochain event SANS l'annuler au timeout : on émet juste un
        # heartbeat et on continue d'attendre la même tâche (sinon on casserait le scan).
        nxt = asyncio.ensure_future(agen.__anext__())
        try:
            while True:
                done, _ = await asyncio.wait({nxt}, timeout=SSE_HEARTBEAT_SECS)
                if not done:
                    yield ": keepalive\n\n"          # commentaire SSE (ignoré par EventSource)
                    continue
                try:
                    ev = nxt.result()
                except StopAsyncIteration:
                    break
                nxt = asyncio.ensure_future(agen.__anext__())
                data = ev["data"]
                if ev["event"] == "finding":
                    # Rendu dans la langue active pour l'affichage live ; la forme
                    # structurée (`_findings`) reste celle persistée.
                    data = {**data, **i18n.render_finding(data, lang)}
                elif ev["event"] == "done":
                    summary = ev["data"]
                    findings = ev.get("_findings", [])
                yield _sse(ev["event"], data)
            if summary is not None:
                scan_id = db.save_scan(summary.get("target", target), summary, findings or [],
                                       user_id=user["id"])
                yield _sse("saved", {"id": scan_id})
        finally:
            if not nxt.done():
                nxt.cancel()
                try:
                    await nxt
                except BaseException:
                    pass
            try:
                await agen.aclose()
            except Exception:
                pass

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)


@app.get("/api/history")
async def history(request: Request):
    user = _pat_or_session_user(request)   # lecture : session OU PAT scans:read
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    scope = None if user["is_admin"] else user["id"]
    return JSONResponse(db.list_scans(user_id=scope))


@app.get("/api/scan/{scan_id}")
async def scan_detail(request: Request, scan_id: str, lang: str = Query(None)):
    user = _pat_or_session_user(request)   # lecture : session OU PAT scans:read
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    scope = None if user["is_admin"] else user["id"]
    data = db.get_scan(scan_id, user_id=scope)
    if not data:
        return JSONResponse({"error": "not found"}, status_code=404)
    # Re-render des findings STRUCTURÉS archivés dans la langue demandée (le passé se
    # relit dans n'importe quelle langue ; un finding legacy retombe en passthrough).
    chosen = _pick_lang(lang, request, user)
    data["findings"] = [{**f, **i18n.render_finding(f, chosen)} for f in data.get("findings", [])]
    data["lang"] = chosen
    return JSONResponse(data)


@app.delete("/api/scan/{scan_id}")
async def scan_delete(request: Request, scan_id: str):
    """Supprime un scan archivé. Écriture → SESSION uniquement (jamais via un PAT
    lecture seule). L'admin peut supprimer n'importe quel scan ; sinon, propriété
    obligatoire (404 si le scan n'existe pas ou n'appartient pas à l'utilisateur)."""
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    scope = None if user["is_admin"] else user["id"]
    if not db.delete_scan(scan_id, user_id=scope):
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"ok": True})


# --------------------------------------------------------------------------- #
# MCP distant : monté EN DERNIER pour servir de fallback. Starlette évalue les
# routes dans l'ordre → les routes Sonar ci-dessus matchent d'abord, et ce mount
# « / » ne récupère que ce qu'elles laissent passer : /mcp et /.well-known/oauth-*.
# (Aucun effet si SONAR_MCP_REMOTE est éteint : _REMOTE_APP reste None.)
# --------------------------------------------------------------------------- #
if _REMOTE_APP is not None:
    # L'app FastMCP (OIDCProxy) sert elle-même /mcp, la metadata OAuth (Protected Resource
    # Metadata RFC 9728 + serveur d'autorisation RFC 8414, issuer correct + CORS), la DCR
    # (/register) et le callback IdP (/auth/callback). Montée en DERNIER : Starlette évalue
    # les routes dans l'ordre, donc les routes Sonar ci-dessus priment et ce mount ne
    # récupère que /mcp + /.well-known/oauth-* + /authorize|/token|/register|/auth/callback.
    app.mount("/", _REMOTE_APP)
