"""Contenu mixte — ressources `http://` chargées sur une page `https://`.

Détection pure : chaque check ne renvoie qu'un `code` (+ `params`/`evidence`). Le
texte humain (titre, détail, recommandation, remédiation) vit dans
`content/checks/mixed.fr.yaml` et est rendu par `scanner.i18n`.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.CONTENT

# Ressources actives : exécutables ou capables de compromettre la page.
#   <script src="http://...">, <iframe src="http://...">,
#   <link ... href="http://..."> (feuilles de style), <object data="http://...">
_ACTIVE_PATTERNS = [
    ("script", re.compile(r"<script\b[^>]*?\bsrc\s*=\s*[\"'](http://[^\"']+)", re.I)),
    ("iframe", re.compile(r"<iframe\b[^>]*?\bsrc\s*=\s*[\"'](http://[^\"']+)", re.I)),
    ("link", re.compile(r"<link\b[^>]*?\bhref\s*=\s*[\"'](http://[^\"']+)", re.I)),
    ("object", re.compile(r"<object\b[^>]*?\bdata\s*=\s*[\"'](http://[^\"']+)", re.I)),
]

# Ressources passives : affichage uniquement.
#   <img src="http://...">, <audio>, <video>, <source src="http://...">
_PASSIVE_PATTERNS = [
    ("img", re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"'](http://[^\"']+)", re.I)),
    ("audio", re.compile(r"<audio\b[^>]*?\bsrc\s*=\s*[\"'](http://[^\"']+)", re.I)),
    ("video", re.compile(r"<video\b[^>]*?\bsrc\s*=\s*[\"'](http://[^\"']+)", re.I)),
    ("source", re.compile(r"<source\b[^>]*?\bsrc\s*=\s*[\"'](http://[^\"']+)", re.I)),
]

# Faux positifs : namespaces XML/SVG, pas du vrai contenu chargé.
_IGNORE = ("http://www.w3.org/",)


def _collect(text: str, patterns) -> list[str]:
    """Renvoie les URLs http trouvées, sans les faux positifs connus."""
    urls = []
    for _tag, rx in patterns:
        for m in rx.finditer(text):
            url = m.group(1)
            if any(url.lower().startswith(prefix) for prefix in _IGNORE):
                continue
            urls.append(url)
    return urls


def _evidence(urls: list[str]) -> str:
    """2-3 exemples d'URL, tronqués."""
    sample = [u[:120] for u in urls[:3]]
    return "; ".join(sample)


@check("mixed", "Contenu mixte", C)
async def mixed(ctx):
    scheme = urlparse(ctx.url).scheme
    content_type = (ctx.response.headers.get("content-type") or "").lower()

    if scheme != "https" or "text/html" not in content_type:
        raison = ("la page finale n'est pas servie en HTTPS"
                  if scheme != "https"
                  else "la réponse n'est pas du HTML")
        return [Finding("mixed", C, Severity.INFO, code="not-evaluated",
                        params={"reason": raison})]

    try:
        text = ctx.response.text or ""
        active = _collect(text, _ACTIVE_PATTERNS)
        passive = _collect(text, _PASSIVE_PATTERNS)

        # Compte spécifique des scripts pour ajuster la sévérité.
        script_rx = _ACTIVE_PATTERNS[0][1]
        scripts = [m.group(1) for m in script_rx.finditer(text)
                   if not any(m.group(1).lower().startswith(p) for p in _IGNORE)]

        findings = []

        if active:
            sev = Severity.HIGH if len(scripts) >= 2 else Severity.MEDIUM
            findings.append(Finding("mixed-active", C, sev, code="active",
                                    params={"count": len(active)},
                                    evidence=_evidence(active)))

        if passive:
            findings.append(Finding("mixed-passive", C, Severity.LOW, code="passive",
                                    params={"count": len(passive)},
                                    evidence=_evidence(passive)))

        if findings:
            return findings

        return [Finding("mixed", C, Severity.PASS, code="pass")]
    except Exception as exc:  # noqa: BLE001 — un check ne doit jamais faire planter le scan.
        return [Finding("mixed", C, Severity.INFO, code="error",
                        params={"error": str(exc)})]
