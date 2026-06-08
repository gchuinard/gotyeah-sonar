"""Serveur MCP stdio (lecture seule) pour Sonar — 3 outils.

Lance avec :  python -m sonar_mcp   (variables SONAR_TOKEN et SONAR_BASE_URL requises)

Vérifié contre le SDK officiel `mcp` 1.27.x : FastMCP sous mcp.server.fastmcp,
décorateur @mcp.tool(), mcp.run(transport="stdio").
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

import scan_compare
from sonar_mcp.client import SonarClient

# Tous les outils sont en lecture seule, sûrs et idempotents ; ils interrogent un service
# externe (l'API Sonar) → openWorldHint. Les annotations renseignent l'UX du client MCP.
_READ_ANN = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)

mcp = FastMCP(
    "sonar",
    instructions=(
        "Accès LECTURE SEULE aux rapports de sécurité Sonar de l'utilisateur. "
        "Utilise list_domains pour voir les domaines, list_scans pour l'historique, "
        "et get_report(scan_id) pour le détail rendu d'un scan (findings + remédiation)."
    ),
)


@mcp.tool(annotations=_READ_ANN)
async def list_domains() -> list[dict]:
    """Liste les domaines vérifiés du compte (ceux que l'utilisateur peut scanner)."""
    return await SonarClient().domains()


@mcp.tool(annotations=_READ_ANN)
async def list_scans(domain: str | None = None) -> list[dict]:
    """Scans récents : id, score, note (grade), date, compteurs de sévérité.

    domain : si fourni, ne garde que les scans dont la cible contient ce domaine.
    """
    return await SonarClient().scans(domain)


@mcp.tool(annotations=_READ_ANN)
async def get_report(scan_id: str, lang: str | None = None) -> dict:
    """Rapport complet d'un scan : findings rendus/localisés en JSON.

    scan_id : identifiant renvoyé par list_scans.
    lang    : langue du rendu ('fr', 'en', …) ; défaut = langue du compte.
    """
    return await SonarClient().report(scan_id, lang)


@mcp.tool(annotations=_READ_ANN)
async def diff_scans(scan_a: str, scan_b: str, lang: str | None = None) -> dict:
    """Compare deux scans : ce qui a été corrigé, ce qui est nouveau, ce qui persiste.

    scan_a : scan de référence (AVANT) ; scan_b : scan à comparer (APRÈS).
    Renvoie les problèmes `resolved`/`new`/`persistent` et le delta de score — idéal
    pour vérifier qu'une correction a fonctionné.
    """
    c = SonarClient()
    before = await c.report(scan_a, lang)
    after = await c.report(scan_b, lang)
    return scan_compare.diff_reports(before, after)


@mcp.tool(annotations=_READ_ANN)
async def get_fix(scan_id: str, check_id: str | None = None,
                  code: str | None = None, lang: str | None = None) -> list[dict]:
    """Remédiation actionnable des problèmes d'un scan (prompt IA + snippet par stack).

    check_id : optionnel, ne garde que ce check (ex. 'hdr-csp') ; code : affine encore.
    Chaque correctif inclut un `ai_prompt` prêt à coller dans un agent de code.
    """
    report = await SonarClient().report(scan_id, lang)
    return scan_compare.extract_fixes(report, check_id, code)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
