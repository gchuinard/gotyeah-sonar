"""Construction du FastMCP distant (Streamable HTTP) à monter dans l'app Sonar.

Le FastMCP est ici notre propre **serveur d'autorisation OAuth** (`SonarOAuthProvider`,
cf. `provider.py`), adossé au modèle utilisateur de Sonar. Une fois monté, l'app
expose, derrière OAuth 2.1 + PKCE S256 :

  • `/mcp` (Streamable HTTP) — 401 + `WWW-Authenticate … resource_metadata="…"` sans
    token valide ;
  • `/.well-known/oauth-protected-resource/mcp` (RFC 9728) et
    `/.well-known/oauth-authorization-server` (RFC 8414, annonce S256) ;
  • `/authorize`, `/token`, `/register` (DCR), `/revoke`.

La route de consentement (`/mcp/consent`), qui relie `/authorize` à la session
magic-link de Sonar, est servie par l'app FastAPI elle-même (voir `app.py`).

Vérifié contre le SDK officiel `mcp` 1.27.x :
  - FastMCP(auth_server_provider=…, auth=AuthSettings(issuer_url, resource_server_url,
    required_scopes, client_registration_options, revocation_options)) ;
  - `FastMCP.streamable_http_app()` retourne une app ASGI montable et crée
    (paresseusement) le `session_manager` dont le lifespan doit tourner.

`build_remote` reste PUR (aucun effet de bord DB) : les tables OAuth sont créées au
démarrage (lifespan de l'app), pas à la construction.
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
    """Construit le FastMCP distant (serveur d'autorisation maison) et son app ASGI.

    base_url : URL PUBLIQUE HTTPS de Sonar (ex. https://sonar.gautierchuinard.com).
               OAuth exige un `issuer_url` absolu — on le dérive de SONAR_BASE_URL.

    PUR : ne touche pas la base (les tables OAuth sont créées par `store.init_store()`
    au démarrage de l'app). Retourne (mcp, asgi_app, provider). L'appelant doit :
      • monter `asgi_app` en DERNIER sur l'app FastAPI (fallback : /mcp + .well-known
        + /authorize + /token + /register + /revoke) ;
      • faire tourner `mcp.session_manager.run()` dans le lifespan parent ;
      • servir la route de consentement `/mcp/consent` (utilise `provider`).
    """
    from mcp.server.auth.settings import (
        AuthSettings,
        ClientRegistrationOptions,
        RevocationOptions,
    )
    from mcp.server.fastmcp import FastMCP
    from pydantic import AnyHttpUrl

    from mcp_remote.provider import SonarOAuthProvider

    base = base_url.rstrip("/")
    provider = SonarOAuthProvider(base, scope=scope)

    mcp = FastMCP(
        "sonar",
        instructions=(
            "Accès LECTURE SEULE aux rapports de sécurité Sonar de l'utilisateur "
            "(scope scans:read)."
        ),
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(base),
            resource_server_url=AnyHttpUrl(f"{base}/mcp"),
            required_scopes=[scope],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[scope], default_scopes=[scope]
            ),
            revocation_options=RevocationOptions(enabled=True),
        ),
    )
    asgi_app = mcp.streamable_http_app()  # crée le session_manager (paresseux)
    return mcp, asgi_app, provider
