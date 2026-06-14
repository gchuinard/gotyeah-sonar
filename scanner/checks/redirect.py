"""Redirection HTTP → HTTPS — le trafic en clair (port 80) doit basculer vers HTTPS.

Hygiène de transport majeure, complémentaire de HSTS : si `http://host` sert du contenu (ou
redirige ailleurs qu'en HTTPS), le trafic initial est interceptable (MITM, vol de cookie sur
la 1ʳᵉ requête). On sonde `http://host/` SANS suivre les redirections et on juge la réponse.

Détection pure : seul un `code` est renvoyé ; le texte vit dans content/checks/redirect.*.yaml.
"""
from __future__ import annotations

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.TLS


@check("http-redirect", "Redirection HTTP → HTTPS", C)
async def http_redirect(ctx):
    host = getattr(ctx, "host", "") or ""
    if not host:
        return [Finding("http-redirect", C, Severity.INFO, code="unknown")]

    try:
        # follow_redirects=False : on veut VOIR la redirection, pas la suivre. La garde
        # anti-SSRF du transport s'applique toujours (refus d'une cible interne).
        resp = await ctx.client.get(f"http://{host}/", follow_redirects=False)
    except Exception:
        # Port 80 fermé / pas de service HTTP en clair → bonne hygiène (rien à intercepter).
        return [Finding("http-redirect", C, Severity.PASS, code="no-cleartext",
                        params={"host": host})]

    status = resp.status_code
    loc = (resp.headers.get("location") or "").strip()
    to_https = loc.lower().startswith("https://")

    if status in (301, 308) and to_https:
        return [Finding("http-redirect", C, Severity.PASS, code="ok",
                        evidence=f"{status} → {loc}")]
    if status in (302, 303, 307) and to_https:
        # Redirige bien vers HTTPS, mais en TEMPORAIRE : 301/308 (permanent) est préférable
        # (éligibilité HSTS preload, cache navigateur).
        return [Finding("http-redirect", C, Severity.LOW, code="weak-redirect",
                        evidence=f"{status} → {loc}")]
    # Tout le reste = pas d'upgrade : sert du contenu en clair, ou redirige vers une autre
    # URL http → la 1ʳᵉ requête reste interceptable.
    ev = f"{status} → {loc}" if loc else str(status)
    return [Finding("http-redirect", C, Severity.MEDIUM, code="no-https-redirect",
                    params={"host": host}, evidence=ev)]
