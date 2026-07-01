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

Les routes sont montées via `register(app)` (add_api_route → APIRoute normales avec `.path`),
et non un APIRouter/include_router, pour rester robuste à toutes les versions FastAPI.
"""
from __future__ import annotations

import hmac
import os

from fastapi import Body, Header, HTTPException, Query

from mcp_remote import tools


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
# Endpoints (lectures + une action). Miroir de mcp_remote/sonar_tools.py côté hub.
# --------------------------------------------------------------------------- #
async def _list_domains(x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                        x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.list_domains_logic(user))


async def _list_scans(domain: str | None = Query(None),
                      x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                      x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.list_scans_logic(user, domain))


async def _get_report(scan_id: str = Query(...), lang: str | None = Query(None),
                      x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                      x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.get_report_logic(user, scan_id, lang))


async def _diff_scans(scan_a: str = Query(...), scan_b: str = Query(...),
                      lang: str | None = Query(None),
                      x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                      x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.diff_scans_logic(user, scan_a, scan_b, lang))


async def _get_fix(scan_id: str = Query(...), check_id: str | None = Query(None),
                   code: str | None = Query(None), lang: str | None = Query(None),
                   x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                   x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.get_fix_logic(user, scan_id, check_id, code, lang))


async def _get_scan_status(scan_id: str = Query(...),
                           x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                           x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.get_scan_status_logic(user, scan_id))


async def _run_scan(domain: str = Body(..., embed=True),
                    profile: str = Body("full", embed=True),
                    x_mcp_secret: str | None = Header(None, alias="X-MCP-Secret"),
                    x_act_as_email: str | None = Header(None, alias="X-Act-As-Email")):
    user = _require_bridge(x_mcp_secret, x_act_as_email)
    return await _run(tools.run_scan_logic(user, domain, profile))


def register(app) -> None:
    """Monte /api/mcp/* sur l'app. `add_api_route` produit des APIRoute normales (avec `.path`)
    — robuste à toutes les versions FastAPI, contrairement à include_router."""
    app.add_api_route("/api/mcp/list_domains", _list_domains, methods=["GET"])
    app.add_api_route("/api/mcp/list_scans", _list_scans, methods=["GET"])
    app.add_api_route("/api/mcp/get_report", _get_report, methods=["GET"])
    app.add_api_route("/api/mcp/diff_scans", _diff_scans, methods=["GET"])
    app.add_api_route("/api/mcp/get_fix", _get_fix, methods=["GET"])
    app.add_api_route("/api/mcp/get_scan_status", _get_scan_status, methods=["GET"])
    app.add_api_route("/api/mcp/run_scan", _run_scan, methods=["POST"])
