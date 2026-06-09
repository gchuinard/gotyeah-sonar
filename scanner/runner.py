"""Moteur de scan.

`run_scan(target)` est un générateur asynchrone : il lance tous les checks
enregistrés en parallèle et émet des événements (dict) au fur et à mesure que
chaque check se termine. La couche web n'a plus qu'à transformer ces événements
en SSE.

Événements émis :
  - started     {target, total_checks, categories}
  - finding     {<un Finding sérialisé>}
  - progress    {done, total, category}
  - done        {score, grade, counts, total, target}   (+ clé interne _findings)
  - scan_error  {message}
"""
from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from . import checks as _checks  # noqa: F401  -> importe les modules = enregistre les checks
from .finding import Category, Finding, Severity, summarize
from .registry import Check, all_checks

USER_AGENT = "Sonar/0.1 (+homelab; authorized use only)"

# Catégories des checks « lents » (Phase 3 pentest + scan réseau) : exclues du profil
# rapide, qui ne garde que le passif/actif léger (quelques secondes, retour synchrone).
_SLOW_CATEGORIES = {Category.PENTEST, Category.ZAP, Category.PORTS}


def checks_for(fast: bool = False):
    """Checks à exécuter pour ce scan. `fast=True` exclut nuclei/ZAP/ports (en-têtes,
    TLS, DNS, cookies, exposition passive… seulement) pour un scan de quelques secondes."""
    checks = all_checks()
    if fast:
        checks = [c for c in checks if c.category not in _SLOW_CATEGORIES]
    return checks


@dataclass
class Context:
    """Tout ce qu'un check peut avoir besoin de connaître sur la cible."""
    url: str            # URL finale, après redirections
    requested_url: str  # URL demandée au départ
    host: str
    response: httpx.Response
    history: list
    client: httpx.AsyncClient


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


async def _fetch_root(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """GET la racine. Si l'HTTPS échoue au niveau TRANSPORT (443 fermé / pas de TLS),
    on retombe sur http:// : un site HTTP-only doit quand même être scanné — le check
    `tls` émettra alors le finding « http » (trafic en clair) au lieu que TOUT le scan
    échoue en « cible injoignable »."""
    try:
        return await client.get(url)
    except httpx.TransportError:
        if url.startswith("https://"):
            return await client.get("http://" + url[len("https://"):])
        raise


async def _build_context(target: str) -> Context:
    requested = normalize_target(target)
    # verify=False À DESSEIN : un certificat invalide (expiré, auto-signé, mauvais hôte,
    # chaîne cassée) ne doit PAS faire échouer la construction du contexte et perdre la
    # cible — c'est précisément un cas qu'on veut signaler. C'est le check `tls` qui rejoue
    # un handshake VÉRIFIANT et fait autorité sur la validité du certificat.
    client = httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
        headers={"User-Agent": USER_AGENT},
        verify=False,
    )
    try:
        resp = await _fetch_root(client, requested)
    except Exception:
        await client.aclose()
        raise
    parsed = urlparse(str(resp.url))
    return Context(
        url=str(resp.url),
        requested_url=requested,
        host=parsed.hostname or "",
        response=resp,
        history=list(resp.history),
        client=client,
    )


# (check_id, code) qu'un check émet pour dire « je n'ai PAS pu m'exécuter » (outil absent,
# timeout, hôte injoignable) — à distinguer d'un vrai PASS. Marqués `unexecuted` → plafond
# de grade. NB : les codes « off »/« not-configured » (désactivation VOLONTAIRE) n'y sont
# pas : couper nuclei/ZAP exprès n'est pas une couverture défaillante.
_UNEXECUTED_CODES = {
    ("nuclei", "not-installed"), ("nuclei", "unavailable"),
    ("nuclei", "timeout"), ("nuclei", "incomplete"),
    ("zap", "timeout"), ("zap", "unreachable"),
    ("tls", "unreachable"), ("tls", "error"),
}


async def _safe_run(chk: Check, ctx: Context):
    """Un check qui plante ne doit jamais casser le scan entier — mais son échec est TRACÉ
    (`unexecuted`) pour que le score n'en tire pas un faux bon point (couverture réduite)."""
    try:
        findings = await chk.fn(ctx) or []
    except Exception as exc:
        return chk, [Finding(
            check_id=chk.id,
            category=chk.category,
            severity=Severity.INFO,
            title=f"Check « {chk.title} » indisponible",
            detail=f"{type(exc).__name__}: {exc}",
            unexecuted=True,
        )]
    for f in findings:
        if (f.check_id, f.code) in _UNEXECUTED_CODES:
            f.unexecuted = True
    return chk, findings


async def run_scan(target: str, fast: bool = False):
    try:
        ctx = await _build_context(target)
    except Exception as exc:
        yield {"event": "scan_error", "data": {"message": f"Cible injoignable : {exc}"}}
        return

    checks = checks_for(fast)
    total = len(checks)
    cat_counts = Counter(c.category for c in checks)
    yield {"event": "started", "data": {
        "target": ctx.url,
        "total_checks": total,
        "categories": dict(cat_counts),
    }}

    collected: list[Finding] = []
    done = 0
    tasks = [asyncio.create_task(_safe_run(c, ctx)) for c in checks]
    try:
        for future in asyncio.as_completed(tasks):
            chk, findings = await future
            done += 1
            for f in findings:
                collected.append(f)
                yield {"event": "finding", "data": f.as_dict()}
            yield {"event": "progress", "data": {
                "done": done, "total": total, "category": chk.category,
            }}
    finally:
        await ctx.client.aclose()

    summary = summarize(collected)
    summary["target"] = ctx.url
    yield {"event": "done", "data": summary,
           "_findings": [f.as_dict() for f in collected]}
