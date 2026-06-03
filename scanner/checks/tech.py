"""Détection de technologies/versions — reconnaissance informative (Phase 2).

On déduit le serveur web, le framework, le CMS à partir des en-têtes, des
cookies et du HTML. C'est passif et surtout informatif (catégorie TECH) : la
pénalisation de la divulgation de version au niveau en-têtes est déjà gérée par
`hdr-disclosure`, donc ici on reste léger pour ne pas doublonner.
"""
from __future__ import annotations

import re

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.TECH

# Détection d'un numéro de version (ex. 8, 8.2, 6.5.1, 2.4.41).
_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")

# <meta name="generator" content="...">
_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Cookies révélateurs : sous-chaîne du nom -> techno.
_COOKIE_HINTS = [
    ("phpsessid", "PHP"),
    ("jsessionid", "Java/JEE"),
    ("asp.net_sessionid", "ASP.NET"),
    ("laravel_session", "Laravel"),
    ("wordpress_", "WordPress"),
    ("wp-settings", "WordPress"),
    ("_shopify", "Shopify"),
]

# Chemins révélateurs dans le HTML -> techno.
_PATH_HINTS = [
    ("/wp-content/", "WordPress"),
    ("/wp-includes/", "WordPress"),
    ("/sites/default/", "Drupal"),
]


def _extract_version(value: str) -> str | None:
    """Renvoie le premier numéro de version trouvé, sinon None."""
    m = _VERSION_RE.search(value or "")
    return m.group(0) if m else None


@check("tech", "Technologies détectées", C)
async def tech(ctx):
    try:
        findings: list[Finding] = []
        seen: set[str] = set()  # dé-duplication par nom de techno (minuscule)

        def add_info(name: str, evidence: str) -> None:
            key = name.lower()
            if key in seen:
                return
            seen.add(key)
            findings.append(Finding("tech", C, Severity.INFO,
                f"Technologie détectée : {name}",
                "Empreinte applicative repérée passivement (en-têtes, cookies ou HTML).",
                evidence=(evidence or "")[:200]))

        def add_version(name: str, version: str, evidence: str) -> None:
            # Le LOW « version exposée » ne s'applique qu'aux sources non couvertes
            # par hdr-disclosure (cookies, meta generator, HTML).
            key = f"version:{name.lower()}"
            if key in seen:
                return
            seen.add(key)
            findings.append(Finding("tech", C, Severity.LOW,
                f"Version exposée : {name} {version}",
                f"La version précise de `{name}` ({version}) est révélée, ce qui "
                "facilite le ciblage de CVE connues.",
                "Masque la version : `server_tokens off`, retire `X-Powered-By`, "
                "supprime la balise `<meta name=\"generator\">`.",
                evidence=(evidence or "")[:200]))

        h = ctx.response.headers

        # --- 1. EN-TÊTES (informatif : la pénalité version est gérée par hdr-disclosure) ---
        for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via"):
            val = h.get(name)
            if not val:
                continue
            add_info(val.split("/")[0].split(",")[0].strip() or val, f"{name}: {val}")

        # --- 2. COOKIES (Set-Cookie) ---
        try:
            cookie_lines = h.get_list("set-cookie")
        except Exception:
            raw = h.get("set-cookie")
            cookie_lines = [raw] if raw else []
        for line in cookie_lines:
            low = (line or "").lower()
            cookie_name = low.split("=", 1)[0].strip()
            for needle, name in _COOKIE_HINTS:
                if needle in cookie_name:
                    add_info(name, f"cookie {line.split('=', 1)[0].strip()}")

        # --- 3. HTML : meta generator + chemins révélateurs ---
        try:
            html = ctx.response.text or ""
        except Exception:
            html = ""

        m = _META_GENERATOR_RE.search(html)
        if m:
            content = m.group(1).strip()
            # Nom = texte avant le numéro de version (ex. "WordPress 6.5" -> "WordPress").
            name = re.split(r"\s*\d", content, 1)[0].strip() or content
            add_info(name, f"meta generator: {content}")
            version = _extract_version(content)
            if version:
                add_version(name, version, f"meta generator: {content}")

        low_html = html.lower()
        for needle, name in _PATH_HINTS:
            if needle in low_html:
                add_info(name, f"chemin `{needle}` présent dans le HTML")

        if not findings:
            return [Finding("tech", C, Severity.PASS,
                "Pas de technologie/version évidente exposée",
                "Aucune empreinte applicative notable n'a été repérée passivement.")]
        return findings
    except Exception:
        # Ne JAMAIS laisser une exception remonter : un check qui plante ne doit
        # pas casser le scan.
        return []
