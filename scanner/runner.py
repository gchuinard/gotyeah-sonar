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


async def _build_context(target: str) -> Context:
    url = normalize_target(target)
    client = httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
        headers={"User-Agent": USER_AGENT},
        verify=True,
    )
    resp = await client.get(url)
    parsed = urlparse(str(resp.url))
    return Context(
        url=str(resp.url),
        requested_url=url,
        host=parsed.hostname or "",
        response=resp,
        history=list(resp.history),
        client=client,
    )


async def _safe_run(chk: Check, ctx: Context):
    """Un check qui plante ne doit jamais casser le scan entier."""
    try:
        findings = await chk.fn(ctx) or []
    except Exception as exc:
        findings = [Finding(
            check_id=chk.id,
            category=Category.INFO,
            severity=Severity.INFO,
            title=f"Check « {chk.title} » indisponible",
            detail=f"{type(exc).__name__}: {exc}",
        )]
    return chk, findings


async def run_scan(target: str):
    try:
        ctx = await _build_context(target)
    except Exception as exc:
        yield {"event": "scan_error", "data": {"message": f"Cible injoignable : {exc}"}}
        return

    checks = all_checks()
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
