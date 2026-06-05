"""MCP DISTANT (Streamable HTTP + OAuth) pour claude.ai web.

Contrairement à `sonar_mcp` (stdio, local, lecture via PAT), ce paquet expose un
endpoint MCP DISTANT monté DANS l'app FastAPI de Sonar, derrière OAuth 2.1 — c'est
le seul transport que claude.ai *web* sait utiliser (le stdio est forcément local).

⚠️  C'est une surface PUBLIQUE authentifiée. Elle est DÉSACTIVÉE par défaut : on
l'active avec SONAR_MCP_REMOTE=on (et SONAR_BASE_URL en HTTPS). Ce paquet n'importe
le SDK `mcp` que lorsqu'il est activé, donc l'app démarre normalement sans `mcp`
installé tant que le flag est éteint.

Étape Ph.0 (spike) : transport + métadonnées OAuth seulement. AUCUN token n'est
encore accepté (tout renvoie 401) — le vrai serveur d'autorisation maison (DCR /
PKCE / consentement adossé à la session magic-link) arrive aux phases suivantes.
"""
