"""Couche web : page, auth par lien magique, et flux SSE du moteur.

Volontairement mince : l'auth (liens, sessions, gate) vit dans `auth.py`, l'envoi
d'email dans `mailer.py`, le moteur dans `scanner/`. Ici on câble les routes et on
protège le scan + l'historique derrière la session.
"""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

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
from scanner.runner import normalize_target, run_scan

BASE = Path(__file__).parent
PAGE = (BASE / "templates" / "index.html").read_text(encoding="utf-8")
LOGIN_PAGE = (BASE / "templates" / "login.html").read_text(encoding="utf-8")

SESSION_COOKIE = "sonar_session"


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


def _current_user(request: Request):
    return auth.get_session_user(request.cookies.get(SESSION_COOKIE))


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    auth.init_auth()
    auth.bootstrap_admin()  # imprime un lien admin one-time dans les logs si configuré
    yield


app = FastAPI(title="Sonar", lifespan=lifespan)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=302)
    return HTMLResponse(PAGE)


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(LOGIN_PAGE)


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

    raw = auth.request_login_link(email, _client_ip(request))
    if raw:
        link = f"{_base_url(request)}/auth/verify?token={raw}"
        await mailer.send_magic_link(auth.normalize_email(email), link)

    # Réponse GÉNÉRIQUE quoi qu'il arrive : on ne révèle pas si le compte existe.
    return JSONResponse({
        "ok": True,
        "message": "Si un compte existe pour cet email, un lien de connexion vient d'être envoyé.",
    })


@app.get("/auth/verify")
async def auth_verify(token: str = Query(...)):
    session_raw, _user = auth.complete_login(token)
    if not session_raw:
        return RedirectResponse("/login?error=expired", status_code=302)
    resp = RedirectResponse("/", status_code=302)
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
    return JSONResponse({
        "email": user["email"],
        "is_admin": bool(user["is_admin"]),
        "can_scan": auth.user_can_scan(user),
    })


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

    async def gen():
        summary = None
        findings = None
        async for ev in run_scan(target):
            if ev["event"] == "done":
                summary = ev["data"]
                findings = ev.get("_findings", [])
            yield _sse(ev["event"], ev["data"])
        if summary is not None:
            scan_id = db.save_scan(summary.get("target", target), summary, findings or [],
                                   user_id=user["id"])
            yield _sse("saved", {"id": scan_id})

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)


@app.get("/api/history")
async def history(request: Request):
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    scope = None if user["is_admin"] else user["id"]
    return JSONResponse(db.list_scans(user_id=scope))


@app.get("/api/scan/{scan_id}")
async def scan_detail(request: Request, scan_id: str):
    user = _current_user(request)
    if not user:
        return JSONResponse({"error": "auth required"}, status_code=401)
    scope = None if user["is_admin"] else user["id"]
    data = db.get_scan(scan_id, user_id=scope)
    if not data:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(data)
