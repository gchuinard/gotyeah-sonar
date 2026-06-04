"""Serveur MCP stdio (lecture seule) pour Sonar — 3 outils.

Lance avec :  python -m sonar_mcp   (variables SONAR_TOKEN et SONAR_BASE_URL requises)

Vérifié contre le SDK officiel `mcp` 1.27.x : FastMCP sous mcp.server.fastmcp,
décorateur @mcp.tool(), mcp.run(transport="stdio").
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from sonar_mcp.client import SonarClient

mcp = FastMCP(
    "sonar",
    instructions=(
        "Accès LECTURE SEULE aux rapports de sécurité Sonar de l'utilisateur. "
        "Utilise list_domains pour voir les domaines, list_scans pour l'historique, "
        "et get_report(scan_id) pour le détail rendu d'un scan (findings + remédiation)."
    ),
)


@mcp.tool()
async def list_domains() -> list[dict]:
    """Liste les domaines vérifiés du compte (ceux que l'utilisateur peut scanner)."""
    return await SonarClient().domains()


@mcp.tool()
async def list_scans(domain: str | None = None) -> list[dict]:
    """Scans récents : id, score, note (grade), date, compteurs de sévérité.

    domain : si fourni, ne garde que les scans dont la cible contient ce domaine.
    """
    return await SonarClient().scans(domain)


@mcp.tool()
async def get_report(scan_id: str, lang: str | None = None) -> dict:
    """Rapport complet d'un scan : findings rendus/localisés en JSON.

    scan_id : identifiant renvoyé par list_scans.
    lang    : langue du rendu ('fr', 'en', …) ; défaut = langue du compte.
    """
    return await SonarClient().report(scan_id, lang)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
