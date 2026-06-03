"""Configuration CORS — Phase 2, sonde active légère (un GET avec Origin bidon)."""
from __future__ import annotations

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.CORS

# Origine de test : un domaine que le serveur ne devrait jamais reconnaître.
PROBE = "https://sonar-cors-probe.example"


@check("cors", "Configuration CORS", C)
async def cors(ctx):
    try:
        resp = await ctx.client.get(ctx.url, headers={"Origin": PROBE})
    except Exception as exc:
        return [Finding("cors", C, Severity.INFO,
            "Vérification CORS impossible",
            f"La requête de sonde CORS a échoué ({type(exc).__name__}) : impossible de "
            "conclure sur la politique cross-origin.",
            "Réessaie le scan ; vérifie que l'hôte répond aux requêtes avec en-tête `Origin`.")]

    acao = resp.headers.get("access-control-allow-origin")
    acac = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()

    evidence = _evidence(acao, acac)
    creds = acac == "true"

    if acao is None:
        return [Finding("cors", C, Severity.PASS,
            "Pas d'exposition CORS",
            "Aucun en-tête `Access-Control-Allow-Origin` n'est renvoyé pour une origine "
            "tierce : l'API ne s'ouvre pas aux sites cross-origin.")]

    if acao == PROBE and creds:
        return [Finding("cors", C, Severity.HIGH,
            "Origine reflétée avec credentials",
            "Le serveur reflète à l'identique l'`Origin` envoyé tout en répondant "
            "`Access-Control-Allow-Credentials: true` : n'importe quel site peut lire les "
            "réponses authentifiées (cookies, sessions) de la victime.",
            "Ne reflète jamais l'`Origin` reçu avec `Allow-Credentials: true` ; utilise une "
            "allowlist stricte de domaines de confiance.",
            evidence=evidence)]

    if acao == "*" and creds:
        return [Finding("cors", C, Severity.HIGH,
            "Wildcard CORS avec credentials",
            "La combinaison `Access-Control-Allow-Origin: *` et "
            "`Access-Control-Allow-Credentials: true` est invalide pour les navigateurs, mais "
            "dangereuse selon les implémentations côté serveur/clients non conformes.",
            "Remplace le `*` par une allowlist explicite et limite `Allow-Credentials` aux "
            "origines de confiance.",
            evidence=evidence)]

    if acao == PROBE:
        return [Finding("cors", C, Severity.MEDIUM,
            "Origine arbitraire reflétée",
            "Le serveur reflète n'importe quelle valeur d'`Origin` (ici notre sonde bidon) : "
            "tout site cross-origin peut lire les réponses, même sans credentials.",
            "Ne reflète pas l'`Origin` reçu ; restreins `Access-Control-Allow-Origin` à une "
            "allowlist stricte.",
            evidence=evidence)]

    if acao == "null":
        return [Finding("cors", C, Severity.MEDIUM,
            "Origine `null` autorisée",
            "`Access-Control-Allow-Origin: null` est usurpable : une page sandboxée, un "
            "`data:` URI ou un iframe peut se présenter comme `null` et passer le contrôle.",
            "N'autorise jamais l'origine `null` ; utilise une allowlist de domaines explicites.",
            evidence=evidence)]

    if acao == "*":
        return [Finding("cors", C, Severity.LOW,
            "CORS permissif (wildcard)",
            "`Access-Control-Allow-Origin: *` ouvre l'accès à toutes les origines, mais sans "
            "credentials : les réponses authentifiées restent protégées.",
            "Limite l'accès aux origines réellement nécessaires si la ressource n'est pas "
            "destinée à être publique.",
            evidence=evidence)]

    return [Finding("cors", C, Severity.PASS,
        "Pas d'exposition CORS",
        "L'en-tête `Access-Control-Allow-Origin` renvoyé ne correspond pas à notre origine de "
        "sonde : la politique semble restreinte à une allowlist.",
        evidence=evidence)]


def _evidence(acao, acac) -> str:
    parts = [f"Access-Control-Allow-Origin: {acao if acao is not None else '(absent)'}"]
    if acac:
        parts.append(f"Access-Control-Allow-Credentials: {acac}")
    return "; ".join(parts)
