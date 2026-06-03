"""Phase 3 (bonus) — wrapper OWASP ZAP en mode API.

Comme nuclei, ZAP n'est qu'une source de `Finding` de plus. Mais ZAP est une
grosse appli Java : au lieu de l'embarquer dans l'image Sonar, on dialogue avec
un démon ZAP qui tourne à côté (un conteneur `zaproxy/zap-stable -daemon`) via
son API REST. On utilise httpx, déjà présent.

Par défaut on fait un *baseline* PASSIF, sûr et borné : on fait charger l'URL
par ZAP, on déroule un petit spider, on attend la fin du scan passif, puis on lit
les alertes. Le scan ACTIF (intrusif) reste opt-in via `ZAP_ACTIVE=on`.

Dégradation propre (comme nuclei) : si aucun démon n'est configuré, le check
renvoie un Finding INFO au lieu d'échouer.

Variables d'environnement :
  ZAP_API_URL     base de l'API ZAP, ex. http://zap:8090   (vide -> check ignoré)
  ZAP_API_KEY     clé d'API ZAP (recommandée en production)
  ZAP_ACTIVE      "on" pour lancer aussi un scan actif (intrusif) — défaut: passif
  ZAP_SPIDER_MAX  nb max de pages explorées par le spider (défaut 10)
  ZAP_TIMEOUT     délai global en secondes (défaut 240)
  SONAR_ZAP       "off" pour désactiver même si ZAP_API_URL est défini
"""
from __future__ import annotations

import asyncio
import os

import httpx

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.ZAP

# Niveau de risque ZAP -> notre échelle (ZAP n'a pas de "critical").
_RISK = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _make_client(base_url: str) -> httpx.AsyncClient:
    """Isolé dans une fonction pour pouvoir l'injecter dans les tests."""
    return httpx.AsyncClient(base_url=base_url, timeout=httpx.Timeout(30.0))


def _map_risk(risk: str) -> Severity:
    return _RISK.get((risk or "").strip().lower(), Severity.INFO)


async def _zap_get(client: httpx.AsyncClient, path: str, **params):
    """GET d'un endpoint JSON de l'API ZAP, avec la clé d'API si fournie."""
    key = _env("ZAP_API_KEY")
    if key:
        params["apikey"] = key
    params = {k: v for k, v in params.items() if v is not None}
    resp = await client.get(path, params=params)
    resp.raise_for_status()
    return resp.json()


async def _poll(client, path, params, key, *, target=100, descending=False, interval=2.0):
    """Attend qu'un scan se termine (status -> 100, ou recordsToScan -> 0).

    Borné par un nombre d'itérations ; le `wait_for` global borne déjà l'ensemble.
    """
    for _ in range(120):
        try:
            data = await _zap_get(client, path, **params)
            val = int(str(data.get(key, target)))
        except Exception:
            return
        if (descending and val <= target) or (not descending and val >= target):
            return
        await asyncio.sleep(interval)


def _dedup_to_findings(alerts: list[dict]) -> list[Finding]:
    """Regroupe les alertes par (plugin, risque), compte les instances, mappe en Finding."""
    grouped: dict = {}
    order: list = []
    for a in alerts:
        plugin = a.get("pluginId") or a.get("alertRef") or a.get("alert") or a.get("name")
        gkey = (plugin, (a.get("risk") or "").lower())
        if gkey not in grouped:
            grouped[gkey] = {"sample": a, "count": 0, "urls": []}
            order.append(gkey)
        g = grouped[gkey]
        g["count"] += 1
        u = a.get("url")
        if u and u not in g["urls"]:
            g["urls"].append(u)

    findings: list[Finding] = []
    for i, gkey in enumerate(order):
        g = grouped[gkey]
        a = g["sample"]
        name = a.get("alert") or a.get("name") or "Alerte ZAP"
        cwe = str(a.get("cweid") or "").strip()
        title = name + (f" (CWE-{cwe})" if cwe and cwe not in ("-1", "0") else "")

        detail = (a.get("description") or "").strip()
        refs = (a.get("reference") or "").strip()
        if refs:
            detail = (detail + "\n" if detail else "") + "Références : " + ", ".join(refs.split("\n")[:3])
        if g["count"] > 1:
            detail = (detail + "\n" if detail else "") + f"{g['count']} occurrence(s) détectée(s)."

        evidence = a.get("evidence") or (g["urls"][0] if g["urls"] else "")

        findings.append(Finding(
            check_id=f"zap-{i}-{a.get('pluginId') or 'x'}",
            category=C,
            severity=_map_risk(a.get("risk")),
            title=title,
            detail=detail,
            recommendation=(a.get("solution") or "").strip(),
            evidence=str(evidence)[:400] or None,
        ))
    return findings


async def _run(ctx, base: str) -> list[Finding]:
    client = _make_client(base)
    try:
        target = ctx.url

        # 1) ZAP charge l'URL : le scan passif analyse le trafic.
        await _zap_get(client, "/JSON/core/action/accessUrl/", url=target, followRedirects="true")

        # 2) Petit spider borné (best effort : on continue même s'il échoue).
        try:
            r = await _zap_get(client, "/JSON/spider/action/scan/",
                               url=target, maxChildren=_env("ZAP_SPIDER_MAX", "10"), recurse="true")
            await _poll(client, "/JSON/spider/view/status/", {"scanId": r.get("scan")}, key="status")
        except Exception:
            pass

        # 3) Scan actif (intrusif) — uniquement si explicitement demandé.
        if _env("ZAP_ACTIVE").lower() == "on":
            try:
                r = await _zap_get(client, "/JSON/ascan/action/scan/", url=target, recurse="true")
                await _poll(client, "/JSON/ascan/view/status/", {"scanId": r.get("scan")}, key="status")
            except Exception:
                pass

        # 4) Attendre la fin du scan passif.
        await _poll(client, "/JSON/pscan/view/recordsToScan/", {},
                    key="recordsToScan", target=0, descending=True)

        # 5) Récupérer les alertes pour la cible.
        data = await _zap_get(client, "/JSON/core/view/alerts/", baseurl=target)
        findings = _dedup_to_findings(data.get("alerts") or [])

        if findings:
            return findings
        return [Finding("zap", C, Severity.PASS, "ZAP : aucune alerte",
            "Le scan OWASP ZAP n'a remonté aucune alerte sur cette cible.")]
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


@check("zap", "Pentest (OWASP ZAP)", C)
async def zap(ctx):
    if _env("SONAR_ZAP").lower() == "off":
        return [Finding("zap", C, Severity.INFO, "Pentest ZAP désactivé",
            "Le check est désactivé par configuration (`SONAR_ZAP=off`).")]

    base = _env("ZAP_API_URL")
    if not base:
        return [Finding("zap", C, Severity.INFO, "ZAP non configuré",
            "Aucun démon OWASP ZAP n'est configuré (`ZAP_API_URL` vide) : l'étape ZAP est ignorée.",
            "Lance un conteneur ZAP en mode démon et renseigne `ZAP_API_URL` (voir le README).")]

    timeout = int(_env("ZAP_TIMEOUT", "240") or "240")
    try:
        return await asyncio.wait_for(_run(ctx, base), timeout=timeout)
    except asyncio.TimeoutError:
        return [Finding("zap", C, Severity.INFO, "ZAP : délai dépassé",
            f"Le scan ZAP a dépassé {timeout}s et a été interrompu.",
            "Augmente `ZAP_TIMEOUT`, réduis `ZAP_SPIDER_MAX`, ou désactive le scan actif.")]
    except Exception as exc:
        return [Finding("zap", C, Severity.INFO, "ZAP injoignable",
            f"Impossible de dialoguer avec l'API ZAP ({type(exc).__name__}: {exc}).",
            "Vérifie `ZAP_API_URL` / `ZAP_API_KEY` et que le démon ZAP est bien démarré.")]
