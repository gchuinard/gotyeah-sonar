"""Logique MCP PARTAGÉE de Sonar (adaptateurs par-dessus scans/DB/i18n).

Ce paquet ne contient plus que `tools.py` : la logique PURE des outils MCP (identité →
compte, cloisonnement anti-IDOR, lectures et run_scan), testable sans SDK. Elle est
RÉUTILISÉE par le pont de confiance `mcp_bridge` (endpoints /api/mcp/* appelés par le hub
central gotyeah-mcp).

Le MCP DISTANT propre à Sonar (Streamable HTTP + OAuth, ex-`remote.py`) a été DÉCOMMISSIONNÉ :
claude.ai passe désormais par le hub gotyeah-mcp. Le MCP stdio LOCAL (`sonar_mcp`, à base de
PAT) est, lui, un paquet distinct et inchangé.
"""
