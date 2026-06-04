"""Configuration CORS — Phase 2, sonde active légère (un GET avec Origin bidon).

Détection pure : le check ne renvoie qu'un `code` (+ `params`/`evidence`). Le texte
humain (titre, détail, recommandation, remédiation) vit dans
`content/checks/cors.fr.yaml` et est rendu par `scanner.i18n`.
"""
from __future__ import annotations

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.CORS

# Origine de test : un domaine que le serveur ne devrait jamais reconnaître.
PROBE = "https://sonar-cors-probe.example"


@check("cors", "Configuration CORS", C)
async def cors(ctx) -> list[Finding]:
    try:
        resp = await ctx.client.get(ctx.url, headers={"Origin": PROBE})
    except Exception as exc:
        return [Finding("cors", C, Severity.INFO, code="error",
            params={"error_type": type(exc).__name__})]

    acao = resp.headers.get("access-control-allow-origin")
    acac = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()

    evidence = _evidence(acao, acac)
    creds = acac == "true"

    if acao is None:
        return [Finding("cors", C, Severity.PASS, code="pass-none")]

    if acao == PROBE and creds:
        return [Finding("cors", C, Severity.HIGH, code="reflected-creds",
            evidence=evidence)]

    if acao == "*" and creds:
        return [Finding("cors", C, Severity.HIGH, code="wildcard-creds",
            evidence=evidence)]

    if acao == PROBE:
        return [Finding("cors", C, Severity.MEDIUM, code="reflected",
            evidence=evidence)]

    if acao == "null":
        return [Finding("cors", C, Severity.MEDIUM, code="null",
            evidence=evidence)]

    if acao == "*":
        return [Finding("cors", C, Severity.LOW, code="wildcard",
            evidence=evidence)]

    return [Finding("cors", C, Severity.PASS, code="restricted",
        evidence=evidence)]


def _evidence(acao, acac) -> str:
    parts = [f"Access-Control-Allow-Origin: {acao if acao is not None else '(absent)'}"]
    if acac:
        parts.append(f"Access-Control-Allow-Credentials: {acac}")
    return "; ".join(parts)
