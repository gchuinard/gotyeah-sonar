"""Construction du FastMCP distant (Streamable HTTP) à monter dans l'app Sonar.

Ph.0 (spike) — on prouve UNIQUEMENT la plomberie attendue par claude.ai web :

  • endpoint Streamable HTTP `/mcp` (auth obligatoire → 401 tant qu'aucun token
    valide, avec l'en-tête `WWW-Authenticate: Bearer … resource_metadata="…"`) ;
  • métadonnée RFC 9728 servie sur `/.well-known/oauth-protected-resource/mcp`.

Le FastMCP est ici en mode « Resource Server » (un simple `TokenVerifier` qui
REFUSE tout) : aucune donnée n'est exposée, et le serveur d'autorisation maison
(routes /authorize, /token, /register, métadonnée RFC 8414, PKCE S256, DCR)
n'est PAS encore branché — il arrive avec le provider OAuth aux phases suivantes.

Vérifié contre le SDK officiel `mcp` 1.27.x :
  - FastMCP(token_verifier=…, auth=AuthSettings(issuer_url, resource_server_url,
    required_scopes)) ;
  - `FastMCP.streamable_http_app()` retourne une app ASGI montable et crée
    (paresseusement) le `session_manager` dont le lifespan doit tourner ;
  - en mode verifier-only, l'app expose `/mcp` + `/.well-known/oauth-protected-
    resource/mcp` et renvoie 401 + WWW-Authenticate sur `/mcp` sans token.
"""
from __future__ import annotations

import os

DEFAULT_SCOPE = "scans:read"


def remote_enabled() -> bool:
    """Vrai si le MCP distant est explicitement activé (SONAR_MCP_REMOTE=on).

    Coupe-circuit inversé par rapport aux checks : ici le défaut est ÉTEINT
    (surface publique → opt-in). Seules les valeurs « on/1/true/yes » activent.
    """
    v = (os.environ.get("SONAR_MCP_REMOTE") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def build_remote(base_url: str, *, scope: str = DEFAULT_SCOPE):
    """Construit le FastMCP distant et son app ASGI montable.

    base_url : URL PUBLIQUE HTTPS de Sonar (ex. https://sonar.gautierchuinard.com).
               OAuth exige un `issuer_url` absolu — on le dérive de SONAR_BASE_URL.

    Retourne (mcp, asgi_app). L'appelant doit :
      • monter `asgi_app` en DERNIER sur l'app FastAPI (fallback : /mcp + .well-known) ;
      • faire tourner `mcp.session_manager.run()` dans le lifespan parent.
    """
    from mcp.server.auth.provider import TokenVerifier
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.fastmcp import FastMCP
    from pydantic import AnyHttpUrl

    base = base_url.rstrip("/")

    class _RejectAll(TokenVerifier):
        # Ph.0 : aucun token n'est encore émis (pas de serveur d'autorisation) →
        # on refuse tout. Le SDK répond alors 401 + WWW-Authenticate pointant vers
        # la métadonnée de ressource, ce qui suffit à amorcer la découverte côté
        # claude.ai sans exposer la moindre donnée.
        async def verify_token(self, token: str):  # noqa: D401
            return None

    mcp = FastMCP(
        "sonar",
        instructions=(
            "Accès LECTURE SEULE aux rapports de sécurité Sonar de l'utilisateur "
            "(scope scans:read)."
        ),
        token_verifier=_RejectAll(),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(base),
            resource_server_url=AnyHttpUrl(f"{base}/mcp"),
            required_scopes=[scope],
        ),
    )
    asgi_app = mcp.streamable_http_app()  # crée le session_manager (paresseux)
    return mcp, asgi_app
