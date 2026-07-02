"""Connexion OIDC (bouton « Se connecter avec GotYeah ») à côté du lien magique.

Flux Authorization Code + PKCE piloté par le backend ; le callback ouvre une SESSION
Sonar habituelle (auth.create_session + cookie) — comme `auth.complete_login`, mais depuis
un email vérifié par l'IdP au lieu d'un lien magique.

Aucune dépendance lourde : httpx + PyJWT. Le JWKS est récupéré via **httpx** (pas
PyJWKClient/urllib, dont l'User-Agent est bloqué en 403 par le Bot Fight Mode Cloudflare) ;
RS256 via cryptography (déjà présent).

Config (env) :
  OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET / OIDC_REDIRECT_URI  — client Keycloak
  OIDC_ALLOW_SIGNUP (défaut true)   — créer le compte Sonar au 1er login OIDC
  OIDC_BUTTON_LABEL                 — libellé du bouton
  LEGACY_LOGIN (défaut on)          — "off" : désactive le lien magique (comptes GotYeah only)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from jwt import PyJWKSet, PyJWTError

import auth

OIDC_ISSUER = (os.environ.get("OIDC_ISSUER") or "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID") or ""
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET") or ""
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI") or ""
OIDC_BUTTON_LABEL = os.environ.get("OIDC_BUTTON_LABEL") or "Se connecter avec GotYeah"
OIDC_SCOPES = "openid email profile"

SESSION_COOKIE = "sonar_session"  # identique à app.py
_STATE_COOKIE = "oidc_tx"
_STATE_PATH = "/auth/oidc"
_STATE_TTL = 600
_SAFE_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

router = APIRouter(prefix="/auth/oidc", tags=["oidc"])

_discovery: dict | None = None
_jwks_set: PyJWKSet | None = None


def oidc_enabled() -> bool:
    return bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_REDIRECT_URI)


def oidc_allow_signup() -> bool:
    return (os.environ.get("OIDC_ALLOW_SIGNUP") or "true").strip().lower() != "false"


def legacy_login_enabled() -> bool:
    """Lien magique (formulaire email). Désactivable via LEGACY_LOGIN=off. Réactivable."""
    return (os.environ.get("LEGACY_LOGIN") or "on").strip().lower() != "off"


def _secure_cookie() -> bool:
    return (os.environ.get("SONAR_COOKIE_SECURE") or "true").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _session_cookie_kwargs() -> dict:
    return dict(httponly=True, secure=_secure_cookie(), samesite="lax", path="/")


async def _get_discovery() -> dict:
    global _discovery
    if _discovery is None:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{OIDC_ISSUER}/.well-known/openid-configuration", timeout=10.0)
            r.raise_for_status()
            _discovery = r.json()
    return _discovery


async def _signing_key(jwks_uri: str, id_token: str):
    """Clé de signature (par kid) via httpx (PyJWKClient/urllib = 403 Cloudflare)."""
    global _jwks_set
    kid = jwt.get_unverified_header(id_token).get("kid")

    def _find(ks: PyJWKSet):
        for k in ks.keys:
            if k.key_id == kid:
                return k.key
        return None

    if _jwks_set is not None:
        key = _find(_jwks_set)
        if key is not None:
            return key
    async with httpx.AsyncClient() as c:
        r = await c.get(jwks_uri, timeout=10.0)
        r.raise_for_status()
        _jwks_set = PyJWKSet.from_dict(r.json())
    key = _find(_jwks_set)
    if key is None:
        raise PyJWTError("aucune JWK ne correspond au kid de l'id_token")
    return key


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


@router.get("/status")
async def oidc_status() -> dict:
    """Lu par la page de login : afficher le bouton + garder ou non le lien magique."""
    return {
        "enabled": oidc_enabled(),
        "label": OIDC_BUTTON_LABEL if oidc_enabled() else None,
        "legacy_login": legacy_login_enabled(),
    }


@router.get("/login")
async def oidc_login() -> RedirectResponse:
    if not oidc_enabled():
        return RedirectResponse("/login?sso_error=disabled", status_code=303)
    disc = await _get_discovery()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = _pkce()
    params = {
        "response_type": "code",
        "client_id": OIDC_CLIENT_ID,
        "redirect_uri": OIDC_REDIRECT_URI,
        "scope": OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    resp = RedirectResponse(
        f"{disc['authorization_endpoint']}?{urlencode(params)}", status_code=303
    )
    tx = base64.urlsafe_b64encode(
        json.dumps({"state": state, "nonce": nonce, "cv": verifier}).encode()
    ).decode()
    resp.set_cookie(
        _STATE_COOKIE,
        tx,
        max_age=_STATE_TTL,
        httponly=True,
        secure=_secure_cookie(),
        samesite="lax",
        path=_STATE_PATH,
    )
    return resp


@router.get("/callback")
async def oidc_callback(request: Request) -> RedirectResponse:
    def _fail(code: str) -> RedirectResponse:
        r = RedirectResponse(f"/login?sso_error={code}", status_code=303)
        r.delete_cookie(_STATE_COOKIE, path=_STATE_PATH)
        return r

    if not oidc_enabled():
        return _fail("disabled")
    if request.query_params.get("error"):
        return _fail("provider")
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    tx = request.cookies.get(_STATE_COOKIE)
    if not code or not state or not tx:
        return _fail("state")
    try:
        st = json.loads(base64.urlsafe_b64decode(tx.encode()).decode())
    except Exception:
        return _fail("state")
    if not secrets.compare_digest(st.get("state", ""), state):
        return _fail("state")

    disc = await _get_discovery()

    # Échange du code (avec le code_verifier PKCE).
    try:
        async with httpx.AsyncClient() as c:
            tr = await c.post(
                disc["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": OIDC_REDIRECT_URI,
                    "client_id": OIDC_CLIENT_ID,
                    "client_secret": OIDC_CLIENT_SECRET,
                    "code_verifier": st.get("cv", ""),
                },
                headers={"Accept": "application/json"},
                timeout=10.0,
            )
        tr.raise_for_status()
        id_token = tr.json().get("id_token")
        if not id_token:
            return _fail("token")
    except (httpx.HTTPError, ValueError):
        return _fail("token")

    # Validation de l'id_token (signature/iss/aud/exp + nonce).
    try:
        key = await _signing_key(disc["jwks_uri"], id_token)
        algs = [
            a for a in disc.get("id_token_signing_alg_values_supported", []) if a in _SAFE_ALGS
        ] or ["RS256"]
        claims = jwt.decode(
            id_token,
            key,
            algorithms=algs,
            audience=OIDC_CLIENT_ID,
            issuer=disc["issuer"],
            options={"require": ["exp", "iat", "aud", "iss"]},
        )
    except (PyJWTError, httpx.HTTPError):
        return _fail("idtoken")
    if not secrets.compare_digest(claims.get("nonce", ""), st.get("nonce", "")):
        return _fail("nonce")

    email = auth.normalize_email(claims.get("email") or "")
    if not email:
        return _fail("noemail")
    if claims.get("email_verified") is False:
        return _fail("unverified")

    # Liaison par email (exact) ou provisioning. Compte NON admin par défaut (comme le
    # lien magique) ; le rôle admin reste géré par SONAR_ADMIN_EMAIL / l'UI admin.
    user = auth.get_user_by_email(email)
    if user is None:
        if not oidc_allow_signup():
            return _fail("nosignup")
        user = auth.get_or_create_user(email)

    session_raw = auth.create_session(user["id"])
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE, session_raw, max_age=auth.session_max_age(), **_session_cookie_kwargs()
    )
    resp.delete_cookie(_STATE_COOKIE, path=_STATE_PATH)
    return resp
