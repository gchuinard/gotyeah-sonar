"""Subdomain takeover — CNAME « dangling » vers un service déprovisionné.

Si un sous-domaine pointe (CNAME) vers un hébergement tiers (GitHub Pages, S3,
Heroku, Azure…) mais que la ressource n'y est plus revendiquée, un attaquant peut la
recréer et servir du contenu sous TON domaine. On résout le CNAME de l'hôte cible
(seam `dns._resolve`) et, si la cible correspond à un service connu, on cherche dans
la réponse déjà récupérée (`ctx.response`) la **signature** « ressource introuvable »
propre à ce service.

Catégorie DNS (c'est un défaut de configuration DNS). Pas de scan supplémentaire :
on réutilise la réponse HTTP du moteur.
"""
from __future__ import annotations

import asyncio

from ..finding import Category, Finding, Severity
from ..registry import check
from . import dns as dns_mod

C = Category.DNS

# (service, suffixes CNAME, signatures « non revendiqué » en minuscules)
_FINGERPRINTS: list[tuple[str, list[str], list[str]]] = [
    ("GitHub Pages", ["github.io"], ["there isn't a github pages site here"]),
    ("AWS S3", ["amazonaws.com"], ["nosuchbucket", "the specified bucket does not exist"]),
    ("Heroku", ["herokuapp.com", "herokudns.com"], ["no such app", "no-such-app.herokuapp.com"]),
    ("Azure", ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
               "azureedge.net", "azurefd.net"], ["404 web site not found", "web app - unavailable"]),
    ("Fastly", ["fastly.net"], ["fastly error: unknown domain"]),
    ("Surge.sh", ["surge.sh"], ["project not found"]),
    ("Shopify", ["myshopify.com"], ["sorry, this shop is currently unavailable"]),
    ("Bitbucket", ["bitbucket.io"], ["repository not found"]),
    ("Pantheon", ["pantheonsite.io"], ["the gods are wise", "404 error unknown site"]),
    ("Tumblr", ["domains.tumblr.com"], ["whatever you were looking for doesn't currently exist"]),
    ("Cargo", ["cargocollective.com"], ["404 not found"]),
    ("Netlify", ["netlify.app", "netlify.com"], ["not found - request id"]),
    ("Read the Docs", ["readthedocs.io"], ["unknown to read the docs"]),
]


async def _cname(host: str) -> str | None:
    """Renvoie la cible CNAME de l'hôte (minuscule, sans point final), ou None. Seam mockable."""
    try:
        answers = await asyncio.to_thread(dns_mod._resolve, host, "CNAME")
    except Exception:
        return None
    if not answers:
        return None
    return str(answers[0]).strip().rstrip(".").lower() or None


@check("takeover", "Prise de contrôle de sous-domaine", C)
async def takeover(ctx):
    host = (getattr(ctx, "host", "") or "").rstrip(".").lower()
    cname = await _cname(host)
    if not cname or cname == host:
        return [Finding("takeover", C, Severity.PASS, code="no-cname")]

    try:
        body = (ctx.response.text or "").lower()
    except Exception:
        body = ""
    status = getattr(getattr(ctx, "response", None), "status_code", 0) or 0

    for service, suffixes, sigs in _FINGERPRINTS:
        if not any(cname.endswith(s) for s in suffixes):
            continue
        if any(sig in body for sig in sigs):
            return [Finding("takeover", C, Severity.HIGH, code="vulnerable",
                            params={"service": service, "cname": cname}, evidence=cname)]
        if status in (404, 410) or status >= 500:
            return [Finding("takeover", C, Severity.MEDIUM, code="dangling",
                            params={"service": service, "cname": cname},
                            evidence=f"{cname} (HTTP {status})")]
        # CNAME vers un service connu mais la ressource répond normalement → revendiquée.
        return [Finding("takeover", C, Severity.PASS, code="ok",
                        params={"cname": cname}, evidence=cname)]

    # CNAME vers une cible non « takeover-prone ».
    return [Finding("takeover", C, Severity.PASS, code="ok",
                    params={"cname": cname}, evidence=cname)]
