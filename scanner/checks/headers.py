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


def _csp_sources(policy: str, directive: str) -> list[str] | None:
    """Sources d'une directive CSP (jetons après le nom), ou None si la directive est
    absente. `policy` doit déjà être en minuscules ; les quotes des mots-clés sont conservées."""
    for part in policy.split(";"):
        toks = part.split()
        if toks and toks[0] == directive:
            return toks[1:]
    return None


# Sources qui rendent la directive de script « grande ouverte » (n'importe quelle origine) :
# une CSP qui les contient n'offre AUCUNE protection XSS réelle.
_CSP_BROAD = {"*", "http:", "https:", "data:", "ws:", "wss:"}


@check("hdr-csp", "Content-Security-Policy", C)
async def csp(ctx):
    v = ctx.response.headers.get("content-security-policy")
    if not v:
        return [Finding("hdr-csp", C, Severity.MEDIUM, code="absent")]
    low = v.lower()
    # Source EFFECTIVE des scripts : script-src, sinon repli sur default-src (sémantique CSP).
    script_src = _csp_sources(low, "script-src")
    if script_src is None:
        script_src = _csp_sources(low, "default-src")
    # Permissive : aucune restriction de script (ni script-src ni default-src), ou une source
    # large (`*`, `http:`/`https:`, `data:`…). Une telle CSP ne protège pas du XSS — c'est le
    # faux négatif n°1 d'une détection par simple présence (`default-src *` passait « ok »).
    if script_src is None or any(s in _CSP_BROAD for s in script_src):
        return [Finding("hdr-csp", C, Severity.MEDIUM, code="permissive", evidence=v[:300])]
    # `unsafe-inline`/`unsafe-eval` : comparaison INSENSIBLE à la casse. `unsafe-inline` est
    # NEUTRALISÉ dès qu'un nonce OU un hash est présent dans la directive : les navigateurs
    # CSP2+ ignorent alors `'unsafe-inline'` (rétro-compat). `strict-dynamic` n'est PAS requis
    # → ne pas pénaliser `script-src 'nonce-xxx' 'unsafe-inline'`, qui est en réalité robuste.
    neutralized = any(
        marker in low for marker in ("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
    weak = []
    if "'unsafe-inline'" in low and not neutralized:
        weak.append("`unsafe-inline`")
    if "'unsafe-eval'" in low:
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
    m = re.search(r"max-age=(\d+)", v, re.I)
    # max-age absent ou =0 : HSTS est DÉSACTIVÉ (les navigateurs n'appliquent rien — et
    # max-age=0 EFFACE une politique précédente). Un en-tête présent mais inopérant ne
    # doit pas être noté « ok » (faux positif : HSTS paraît actif alors qu'il ne l'est pas).
    if not m or int(m.group(1)) == 0:
        return [Finding("hdr-hsts", C, Severity.MEDIUM, code="disabled", evidence=v[:200])]
    findings = [Finding("hdr-hsts", C, Severity.PASS, code="ok", evidence=v)]
    if int(m.group(1)) < 15552000:  # < ~6 mois
        findings.append(Finding("hdr-hsts-maxage", C, Severity.LOW, code="low",
                                params={"maxage": m.group(1)}))
    return findings


@check("hdr-xfo", "Protection clickjacking", C)
async def xfo(ctx):
    h = ctx.response.headers
    xfo_val = (h.get("x-frame-options") or "").strip().lower()
    fa = _csp_sources((h.get("content-security-policy") or "").lower(), "frame-ancestors")
    # frame-ancestors (CSP) fait autorité quand il est présent : on valide ses sources.
    if fa is not None:
        if any(s in ("*", "http:", "https:") for s in fa):
            return [Finding("hdr-xfo", C, Severity.MEDIUM, code="permissive",
                            evidence="frame-ancestors " + " ".join(fa))]
        return [Finding("hdr-xfo", C, Severity.PASS, code="ok")]
    if xfo_val in ("deny", "sameorigin"):
        return [Finding("hdr-xfo", C, Severity.PASS, code="ok")]
    # Présent mais valeur permissive/dépréciée (ALLOWALL, ALLOW-FROM…) — ignorée des
    # navigateurs : la page reste framable, donc ce n'est PAS une protection.
    if xfo_val:
        return [Finding("hdr-xfo", C, Severity.MEDIUM, code="permissive",
                        evidence=h.get("x-frame-options"))]
    return [Finding("hdr-xfo", C, Severity.MEDIUM, code="absent")]


@check("hdr-nosniff", "X-Content-Type-Options", C)
async def nosniff(ctx):
    v = (ctx.response.headers.get("x-content-type-options") or "").lower()
    if v == "nosniff":
        return [Finding("hdr-nosniff", C, Severity.PASS, code="ok")]
    return [Finding("hdr-nosniff", C, Severity.LOW, code="absent")]


# Valeurs de Referrer-Policy qui ne protègent pas (l'URL complète fuit cross-origin).
_REFERRER_WEAK = {"unsafe-url", "no-referrer-when-downgrade"}


@check("hdr-referrer", "Referrer-Policy", C)
async def referrer(ctx):
    v = (ctx.response.headers.get("referrer-policy") or "").strip().lower()
    if not v:
        return [Finding("hdr-referrer", C, Severity.LOW, code="absent")]
    # Les navigateurs retiennent le DERNIER token compris : on ne signale « no-op » que si
    # AUCUN token n'est protecteur (sinon un repli sûr suffit).
    tokens = [t.strip() for t in v.split(",") if t.strip()]
    if tokens and all(t in _REFERRER_WEAK for t in tokens):
        return [Finding("hdr-referrer", C, Severity.LOW, code="weak", evidence=v)]
    return [Finding("hdr-referrer", C, Severity.PASS, code="ok")]


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
    v = (ctx.response.headers.get("cross-origin-opener-policy") or "").strip().lower()
    if not v:
        return [Finding("hdr-coop", C, Severity.LOW, code="absent")]
    # `unsafe-none` est la valeur NO-OP : poser l'en-tête à cette valeur n'isole rien (équivaut
    # à pas de COOP). On ne l'accepte pas comme protection.
    if v == "unsafe-none":
        return [Finding("hdr-coop", C, Severity.LOW, code="weak", evidence=v)]
    return [Finding("hdr-coop", C, Severity.PASS, code="ok")]


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
