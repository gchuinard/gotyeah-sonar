"""Serveur MCP stdio (lecture seule) pour Sonar.

Ce package n'importe PAS le SDK `mcp` au niveau du package : seule la couche client
(httpx) est exposée ici, pour rester testable sans le SDK. Le serveur FastMCP vit dans
`sonar_mcp.server` (importé uniquement quand on lance `python -m sonar_mcp`).
"""
from .client import SonarClient

__all__ = ["SonarClient"]
