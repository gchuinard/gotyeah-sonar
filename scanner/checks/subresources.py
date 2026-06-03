"""En-têtes de sécurité sur les sous-ressources — Phase 2, actif léger.

Le document principal a beau être bien protégé, ses scripts et feuilles de style
sont souvent servis par d'autres routes/`location` qui n'héritent pas forcément
des mêmes en-têtes. On extrait les sous-ressources **même origine** référencées
par la page, on en récupère un échantillon, et on vérifie le seul en-tête qui
compte vraiment sur un script/CSS : `X-Content-Type-Options: nosniff` (sans lui,
un fichier au type MIME ambigu peut être réinterprété par le navigateur).

On ignore volontairement les ressources tierces (CDN…) : on ne peut pas corriger
leurs en-têtes, et le bon réflexe pour elles est plutôt l'intégrité (SRI).
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.SUBRESOURCE

# On reste léger : un échantillon suffit à révéler une config d'en-têtes incohérente.
_MAX_SUBRESOURCES = 6

_SCRIPT_RE = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*[\"']([^\"']+)", re.I)
_LINK_RE = re.compile(r"<link\b[^>]*>", re.I)
_HREF_RE = re.compile(r"\bhref\s*=\s*[\"']([^\"']+)", re.I)
_REL_STYLESHEET_RE = re.compile(r"\brel\s*=\s*[\"'][^\"']*stylesheet", re.I)


def _extract_subresources(html: str, base_url: str, host: str) -> list[str]:
    """URLs absolues, même origine (même hostname), dé-dupliquées : scripts + CSS."""
    raw: list[str] = [m.group(1) for m in _SCRIPT_RE.finditer(html)]
    for tag in _LINK_RE.finditer(html):
        block = tag.group(0)
        if _REL_STYLESHEET_RE.search(block):
            h = _HREF_RE.search(block)
            if h:
                raw.append(h.group(1))

    out: list[str] = []
    seen: set[str] = set()
    for u in raw:
        absolute = urljoin(base_url, u)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.hostname != host:  # même origine seulement (le tiers relève du SRI)
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        out.append(absolute)
    return out


@check("subresources", "En-têtes des sous-ressources", C)
async def subresources(ctx):
    content_type = (ctx.response.headers.get("content-type") or "").lower()
    if "text/html" not in content_type:
        return [Finding("subresources", C, Severity.INFO,
            "Sous-ressources non évaluées",
            "La page principale n'est pas du HTML : il n'y a pas de sous-ressource à analyser.",
            "Aucune action requise pour ce point.")]

    try:
        html = ctx.response.text or ""
    except Exception:
        html = ""

    targets = _extract_subresources(html, ctx.url, ctx.host)
    if not targets:
        return [Finding("subresources", C, Severity.PASS,
            "Aucune sous-ressource même-origine",
            "La page ne charge aucun script ni feuille de style hébergé localement à vérifier.")]

    sampled = targets[:_MAX_SUBRESOURCES]
    missing: list[str] = []
    checked = 0
    for url in sampled:
        try:
            resp = await ctx.client.get(url)
        except Exception:
            continue
        checked += 1
        nosniff = (resp.headers.get("x-content-type-options") or "").strip().lower()
        if nosniff != "nosniff":
            missing.append(url)

    if checked == 0:
        return [Finding("subresources", C, Severity.INFO,
            "Sous-ressources injoignables",
            "Aucune des sous-ressources échantillonnées n'a pu être récupérée pour vérification.",
            "Aucune action requise pour ce point.")]

    note = f" (échantillon de {len(sampled)} sur {len(targets)})" if len(targets) > len(sampled) else ""

    if missing:
        return [Finding("subresources", C, Severity.LOW,
            "Sous-ressources sans `X-Content-Type-Options: nosniff`",
            f"{len(missing)} sur {checked} sous-ressource(s) même-origine (script/CSS) sont "
            f"servies sans `nosniff`{note} : un fichier au type MIME ambigu peut être "
            "réinterprété par le navigateur (MIME sniffing), même quand la page principale "
            "est correctement protégée.",
            "Ajoute `X-Content-Type-Options: nosniff` sur **toutes** les réponses, y compris "
            "les fichiers statiques — configure-le globalement côté serveur plutôt que par route.",
            evidence="; ".join(u[:120] for u in missing[:3]))]

    return [Finding("subresources", C, Severity.PASS,
        "Sous-ressources correctement protégées",
        f"Les {checked} sous-ressource(s) même-origine vérifiées portent toutes "
        "`X-Content-Type-Options: nosniff`.")]
