"""Pont de confiance HTTP `/api/mcp/*` pour le hub MCP central (gotyeah-mcp).

Le hub (gotyeah-mcp) est la SEULE porte d'entrée MCP/OAuth pour claude.ai : il authentifie
l'utilisateur via l'IdP (Pocket ID), extrait l'email VÉRIFIÉ, puis appelle ces endpoints
avec `X-MCP-Secret` (secret partagé) + `X-Act-As-Email`. Ici on ne refait AUCUNE auth OAuth :
le secret partagé authentifie le hub comme appelant de confiance, on résout l'email → compte
Sonar, et on réutilise la logique PURE de `mcp_remote.tools` — moteur de scan, DB, i18n et
cloisonnement anti-IDOR restent INCHANGÉS et vivent dans Sonar.

Default-deny : sans `SONAR_MCP_SHARED_SECRET` (ou avec un mauvais secret), toute route renvoie
401. Le secret DOIT être identique à `SONAR_MCP_SECRET` côté gotyeah-mcp. Symétrique du pont
`X-MCP-Secret`/`X-Act-As-Email` déjà utilisé par gotyeah-notes.
"""
from __future__ import annotations

import hmac
import os

from fastapi import APIRouter, Body, Header, HTTPException, Query

from mcp_remote import tools

router = APIRouter(prefix="/api/mcp")


def bridge_enabled() -> bool:
    """Vrai si le pont est configuré (secret partagé présent). Purement indicatif :
    la garde réelle est par-requête dans `_require_bridge` (default-deny)."""
    return bool((os.environ.get("SONAR_MCP_SHARED_SECRET") or "").strip())


def _require_bridge(secret: str | None, email: str | None):
    """Vérifie le secret partagé (temps constant) puis résout l'email → compte Sonar.

    Le hub ne transmet QUE des emails vérifiés par l'IdP ; le secret prouve que l'appel
    vient bien du hub. Lève 401 si secret absent/invalide, email manquant, ou compte inconnu.
    """
    expected = (os.environ.get("SONAR_MCP_SHARED_SECRET") or "").strip()
    # Comparaison en bytes : compare_digest lève TypeError sur une str non-ASCII (un
    # X-MCP-Secret forgé avec des octets latin-1 renverrait alors 500 au lieu de 401).
    if (not expected or not secret
            or not hmac.compare_digest(secret.encode("utf-8"), expected.encode("utf-8"))):
        raise HTTPException(status_code=401, detail="Secret MCP invalide.")
    if not email:
        raise HTTPException(status_code=401, detail="X-Act-As-Email requis.")
    user = tools.resolve_user_from_trusted_email(email)
    if not user:
        raise HTTPException(status_code=401, detail="Aucun compte Sonar pour cet email.")
    return user


async def _run(coro):
    """Exécute la logique et traduit ses `ValueError` (introuvable / garde-fou) en 400,
    pour que le hub relaie un message exploitable par l'IA plutôt qu'une 500 opaque."""
    try:
        return await coro
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Lectures
# --------------------------------------------------------------------------- #
@router.get("/list_domains")
async def _list_domains(x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                        x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.list_domains_logic(user))


@router.get("/list_scans")
async def _list_scans(domain: str | None = Query(None),
                      x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                      x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.list_scans_logic(user, domain))


@router.get("/get_report")
async def _get_report(scan_id: str = Query(...), lang: str | None = Query(None),
                      x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                      x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.get_report_logic(user, scan_id, lang))


@router.get("/diff_scans")
async def _diff_scans(scan_a: str = Query(...), scan_b: str = Query(...),
                      lang: str | None = Query(None),
                      x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                      x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.diff_scans_logic(user, scan_a, scan_b, lang))


@router.get("/get_fix")
async def _get_fix(scan_id: str = Query(...), check_id: str | None = Query(None),
                   code: str | None = Query(None), lang: str | None = Query(None),
                   x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                   x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.get_fix_logic(user, scan_id, check_id, code, lang))


@router.get("/get_scan_status")
async def _get_scan_status(scan_id: str = Query(...),
                           x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                           x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.get_scan_status_logic(user, scan_id))


# --------------------------------------------------------------------------- #
# Action
# --------------------------------------------------------------------------- #
@router.post("/run_scan")
async def _run_scan(domain: str = Body(..., embed=True),
                    profile: str = Body("full", embed=True),
                    x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                    x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.run_scan_logic(user, domain, profile))
