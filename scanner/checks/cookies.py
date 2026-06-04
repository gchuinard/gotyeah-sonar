"""Attributs de sécurité des cookies (Secure / HttpOnly / SameSite) — scan passif.

On lit les en-têtes `Set-Cookie` bruts de la réponse et on vérifie, cookie par
cookie, la présence des trois garde-fous classiques. On parcourt aussi les
réponses de redirection (`ctx.history`) car un cookie de session est souvent
posé sur le 302 initial, pas sur la page finale ; on dé-duplique par nom de
cookie (premier vu = gardé) pour ne pas signaler deux fois le même.

Détection pure : chaque check ne renvoie qu'un `code` (+ `params`/`evidence`). Le
texte humain (titre, détail, recommandation, remédiation) vit dans
`content/checks/cookies.fr.yaml` et est rendu par `scanner.i18n`.
"""
from __future__ import annotations

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.COOKIES


def _split_cookie(raw: str) -> tuple[str, list[str]]:
    """Sépare un en-tête Set-Cookie en (nom, [attributs]).

    Le 1er segment est `nom=valeur`, le reste sont les attributs. On renvoie le
    nom du cookie et la liste des attributs en minuscules pour les tests.
    """
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return "", []
    name = parts[0].split("=", 1)[0].strip()
    attrs = [p.lower() for p in parts[1:]]
    return name, attrs


def _has_attr(attrs: list[str], name: str) -> bool:
    """True si l'attribut (drapeau ou clé=valeur) est présent, insensible à la casse."""
    name = name.lower()
    return any(a == name or a.startswith(name + "=") for a in attrs)


def _samesite_value(attrs: list[str]) -> str | None:
    """Renvoie la valeur de SameSite en minuscules (ou None si absent)."""
    for a in attrs:
        if a.startswith("samesite="):
            return a.split("=", 1)[1].strip()
    return None


def _collect_raw_cookies(ctx) -> list[str]:
    """Rassemble les Set-Cookie de l'historique de redirection puis de la réponse finale.

    On dé-duplique par nom de cookie en gardant la première occurrence rencontrée.
    """
    raws: list[str] = []
    try:
        for resp in list(ctx.history) + [ctx.response]:
            try:
                raws.extend(resp.headers.get_list("set-cookie"))
            except Exception:
                continue
    except Exception:
        try:
            raws.extend(ctx.response.headers.get_list("set-cookie"))
        except Exception:
            pass

    seen: set[str] = set()
    unique: list[str] = []
    for raw in raws:
        name, _ = _split_cookie(raw)
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(raw)
    return unique


@check("cookies", "Cookies (Secure/HttpOnly/SameSite)", C)
async def cookies(ctx):
    is_https = str(getattr(ctx, "url", "")).lower().startswith("https://")
    raws = _collect_raw_cookies(ctx)

    if not raws:
        return [Finding("cookies", C, Severity.PASS, code="none")]

    findings: list[Finding] = []
    for raw in raws:
        try:
            name, attrs = _split_cookie(raw)
        except Exception:
            # Un Set-Cookie illisible ne doit jamais faire planter le check.
            continue
        if not name:
            continue

        secure = _has_attr(attrs, "secure")
        httponly = _has_attr(attrs, "httponly")
        samesite = _samesite_value(attrs)

        clean = True

        # Secure : sans lui, le cookie repart en clair sur une connexion http.
        if is_https and not secure:
            clean = False
            findings.append(Finding("cookie-secure", C, Severity.MEDIUM,
                code="missing", params={"name": name}, evidence=raw[:300]))

        # HttpOnly : sans lui, le cookie est lisible par du JavaScript (vol via XSS).
        if not httponly:
            clean = False
            findings.append(Finding("cookie-httponly", C, Severity.MEDIUM,
                code="missing", params={"name": name}, evidence=raw[:300]))

        # SameSite : sans lui (ou None sans Secure), risque de CSRF.
        if samesite is None:
            clean = False
            findings.append(Finding("cookie-samesite", C, Severity.LOW,
                code="missing", params={"name": name}, evidence=raw[:300]))
        elif samesite == "none" and not secure:
            clean = False
            findings.append(Finding("cookie-samesite", C, Severity.LOW,
                code="none-insecure", params={"name": name}, evidence=raw[:300]))

        if clean:
            findings.append(Finding("cookie-ok", C, Severity.PASS,
                code="ok", params={"name": name}, evidence=raw[:300]))

    return findings
