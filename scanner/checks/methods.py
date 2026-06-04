"""Méthodes HTTP — durcissement des verbes (Phase 2, actif léger, lecture seule).

On lit l'en-tête `Allow` via une requête `OPTIONS`, et on confirme `TRACE` par une
requête inoffensive (TRACE se contente de renvoyer la requête en écho — aucune
écriture). On NE teste PAS réellement PUT/DELETE (pas d'écriture de données) : on
signale seulement qu'ils sont annoncés, à vérifier côté contrôle d'accès.
"""
from __future__ import annotations

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.HTTP

_DANGEROUS = ("PUT", "DELETE", "PATCH")


async def _allow(ctx) -> set[str]:
    try:
        resp = await ctx.client.request("OPTIONS", ctx.url)
    except Exception:
        return set()
    allow = (resp.headers.get("allow") or "").upper()
    return {m.strip() for m in allow.split(",") if m.strip()}


async def _trace_enabled(ctx) -> bool:
    try:
        resp = await ctx.client.request("TRACE", ctx.url)
    except Exception:
        return False
    if resp.status_code != 200:
        return False
    ctype = (resp.headers.get("content-type") or "").lower()
    try:
        body = (resp.text or "")[:200]
    except Exception:
        body = ""
    return "message/http" in ctype or "TRACE " in body


@check("http-methods", "Méthodes HTTP", C)
async def methods(ctx):
    if getattr(ctx, "client", None) is None:
        return []
    allow = await _allow(ctx)
    findings: list[Finding] = []

    if "TRACE" in allow or await _trace_enabled(ctx):
        findings.append(Finding("http-methods", C, Severity.LOW, code="trace-enabled"))

    dangerous = sorted(m for m in _DANGEROUS if m in allow)
    if dangerous:
        findings.append(Finding("http-methods", C, Severity.INFO, code="dangerous-methods",
                                params={"methods": ", ".join(dangerous)},
                                evidence=", ".join(sorted(allow))))

    if not findings:
        findings.append(Finding("http-methods", C, Severity.PASS, code="ok",
                                evidence=", ".join(sorted(allow)) or None))
    return findings
