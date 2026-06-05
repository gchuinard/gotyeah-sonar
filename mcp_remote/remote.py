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


def metadata_documents(base_url: str, *, scope: str = DEFAULT_SCOPE):
    """Métadonnées OAuth CORRIGÉES pour l'interop claude.ai (RFC 8414 / RFC 9728).

    Le SDK `mcp` sérialise deux défauts qui font échouer claude.ai :

      1. `issuer` (et `authorization_servers`) AVEC un slash final — pydantic
         `AnyHttpUrl` en ajoute un. claude.ai fait une validation RFC 8414 stricte
         (« l'issuer DOIT être identique à l'identifiant sans slash dans lequel le
         well-known a été inséré ») → mismatch → métadonnée rejetée, aucun
         `/register`. Les serveurs MCP qui marchent (ex. Sentry) n'ont pas le slash.
      2. `Cache-Control: public, max-age=3600` → claude.ai met la métadonnée en
         cache 1 h ; une correction côté serveur ne se propage pas avant expiration.

    On reconstruit donc les deux documents proprement (slash retiré) ; l'appelant
    les sert sur les routes `.well-known` AVANT le mount du SDK (priorité Starlette),
    avec un `Cache-Control: no-store`. Renvoie (as_metadata, protected_resource).
    """
    from mcp.server.auth.routes import build_metadata
    from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
    from pydantic import AnyHttpUrl

    base = base_url.rstrip("/")
    md = build_metadata(
        issuer_url=AnyHttpUrl(base),
        service_documentation_url=None,
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[scope, "offline_access"], default_scopes=[scope]
        ),
        revocation_options=RevocationOptions(enabled=True),
    )
    as_meta = md.model_dump(mode="json", exclude_none=True)
    as_meta["issuer"] = base  # sans slash final (cf. défaut #1)
    # `build_metadata` est patché par build_remote pour inclure "none" ; garde-fou
    # au cas où metadata_documents serait appelé avant build_remote.
    methods = as_meta.get("token_endpoint_auth_methods_supported") or []
    if "none" not in methods:
        as_meta["token_endpoint_auth_methods_supported"] = ["none", *methods]

    pr_meta = {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],  # sans slash final
        "scopes_supported": [scope],
        "bearer_methods_supported": ["header"],
    }
    return as_meta, pr_meta


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
            # La RESSOURCE /mcp exige scans:read. On tolère en plus `offline_access`
            # (scope OIDC standard que claude.ai demande au DCR pour obtenir un refresh
            # token — ce qu'on émet de toute façon). Il n'ouvre aucun accès en lecture.
            required_scopes=[scope],
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=[scope, "offline_access"],
                default_scopes=[scope],
            ),
            revocation_options=RevocationOptions(enabled=True),
        ),
    )
    # --- Interop claude.ai : annoncer le mode client PUBLIC `none` ---------- #
    # Le SDK `mcp` code en dur token_endpoint_auth_methods_supported =
    # ["client_secret_post", "client_secret_basic"] (routes.build_metadata) et
    # n'annonce JAMAIS "none". Or claude.ai s'enregistre en client PUBLIC
    # (token_endpoint_auth_method="none", PKCE sans secret) : en lisant la
    # métadonnée du serveur d'autorisation, il voit que "none" n'est pas supporté
    # et abandonne AVANT /authorize → « Couldn't register ». Le /register accepte
    # pourtant ces clients (incohérence du SDK). On ajoute "none" à la métadonnée
    # AVANT streamable_http_app() (qui construit puis met en cache la métadonnée).
    from mcp.server.auth import routes as _auth_routes

    if not getattr(_auth_routes.build_metadata, "_sonar_public_client_patch", False):
        _orig_build_metadata = _auth_routes.build_metadata

        def _build_metadata_with_public_client(*args, **kwargs):
            md = _orig_build_metadata(*args, **kwargs)
            methods = list(md.token_endpoint_auth_methods_supported or [])
            if "none" not in methods:
                md.token_endpoint_auth_methods_supported = ["none", *methods]
            return md

        _build_metadata_with_public_client._sonar_public_client_patch = True
        _auth_routes.build_metadata = _build_metadata_with_public_client

    asgi_app = mcp.streamable_http_app()  # crée le session_manager (paresseux)
    return mcp, asgi_app, provider
