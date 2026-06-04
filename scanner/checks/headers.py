"""En-têtes de sécurité HTTP — le gros du scan passif.

Détection pure : chaque check ne renvoie qu'un `code` (+ `params`/`evidence`). Le
texte humain (titre, détail, recommandation, remédiation) vit dans
`content/checks/headers.fr.yaml` et est rendu par `scanner.i18n`.
"""
from __future__ import annotations

import re

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.HEADERS


@check("hdr-csp", "Content-Security-Policy", C)
async def csp(ctx):
    v = ctx.response.headers.get("content-security-policy")
    if not v:
        return [Finding("hdr-csp", C, Severity.MEDIUM, code="absent")]
    weak = []
    if "unsafe-inline" in v:
        weak.append("`unsafe-inline`")
    if "unsafe-eval" in v:
        weak.append("`unsafe-eval`")
    if weak:
        return [Finding("hdr-csp", C, Severity.LOW, code="weak",
                        params={"items": ", ".join(weak)}, evidence=v[:300])]
    return [Finding("hdr-csp", C, Severity.PASS, code="ok", evidence=v[:300])]


@check("hdr-hsts", "Strict-Transport-Security", C)
async def hsts(ctx):
    v = ctx.response.headers.get("strict-transport-security")
    if not v:
        return [Finding("hdr-hsts", C, Severity.MEDIUM, code="absent")]
    findings = [Finding("hdr-hsts", C, Severity.PASS, code="ok", evidence=v)]
    m = re.search(r"max-age=(\d+)", v)
    if m and int(m.group(1)) < 15552000:  # < ~6 mois
        findings.append(Finding("hdr-hsts-maxage", C, Severity.LOW, code="low",
                                params={"maxage": m.group(1)}))
    return findings


@check("hdr-xfo", "Protection clickjacking", C)
async def xfo(ctx):
    h = ctx.response.headers
    csp = (h.get("content-security-policy") or "").lower()
    if h.get("x-frame-options") or "frame-ancestors" in csp:
        return [Finding("hdr-xfo", C, Severity.PASS, code="ok")]
    return [Finding("hdr-xfo", C, Severity.MEDIUM, code="absent")]


@check("hdr-nosniff", "X-Content-Type-Options", C)
async def nosniff(ctx):
    v = (ctx.response.headers.get("x-content-type-options") or "").lower()
    if v == "nosniff":
        return [Finding("hdr-nosniff", C, Severity.PASS, code="ok")]
    return [Finding("hdr-nosniff", C, Severity.LOW, code="absent")]


@check("hdr-referrer", "Referrer-Policy", C)
async def referrer(ctx):
    if ctx.response.headers.get("referrer-policy"):
        return [Finding("hdr-referrer", C, Severity.PASS, code="ok")]
    return [Finding("hdr-referrer", C, Severity.LOW, code="absent")]


@check("hdr-permissions", "Permissions-Policy", C)
async def permissions(ctx):
    if ctx.response.headers.get("permissions-policy"):
        return [Finding("hdr-permissions", C, Severity.PASS, code="ok")]
    return [Finding("hdr-permissions", C, Severity.INFO, code="absent")]


@check("hdr-disclosure", "Divulgation de version serveur", C)
async def disclosure(ctx):
    h = ctx.response.headers
    leaks = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        val = h.get(name)
        # On ne signale que si une version semble présente (un chiffre).
        if val and any(ch.isdigit() for ch in val):
            leaks.append(f"{name}: {val}")
    if leaks:
        return [Finding("hdr-disclosure", C, Severity.LOW, code="leak",
                        evidence="; ".join(leaks))]
    return [Finding("hdr-disclosure", C, Severity.PASS, code="ok")]


@check("hdr-coop", "Cross-Origin-Opener-Policy", C)
async def coop(ctx):
    if ctx.response.headers.get("cross-origin-opener-policy"):
        return [Finding("hdr-coop", C, Severity.PASS, code="ok")]
    return [Finding("hdr-coop", C, Severity.LOW, code="absent")]


@check("hdr-coep", "Cross-Origin-Embedder-Policy", C)
async def coep(ctx):
    if ctx.response.headers.get("cross-origin-embedder-policy"):
        return [Finding("hdr-coep", C, Severity.PASS, code="ok")]
    return [Finding("hdr-coep", C, Severity.INFO, code="absent")]


@check("hdr-corp", "Cross-Origin-Resource-Policy", C)
async def corp(ctx):
    if ctx.response.headers.get("cross-origin-resource-policy"):
        return [Finding("hdr-corp", C, Severity.PASS, code="ok")]
    return [Finding("hdr-corp", C, Severity.INFO, code="absent")]


@check("hdr-cache", "Cache-Control des réponses sensibles", C)
async def cache(ctx):
    """Une réponse qui pose un cookie (souvent authentifiée) ne devrait pas être
    mise en cache. On n'évalue que ce cas ; une page publique cacheable est normale."""
    h = ctx.response.headers
    if not h.get("set-cookie"):
        return [Finding("hdr-cache", C, Severity.PASS, code="not-applicable")]
    cc = (h.get("cache-control") or "").lower()
    if any(d in cc for d in ("no-store", "private", "no-cache")):
        return [Finding("hdr-cache", C, Severity.PASS, code="ok")]
    return [Finding("hdr-cache", C, Severity.LOW, code="sensitive-cacheable",
                    evidence=cc or "(aucun Cache-Control)")]
