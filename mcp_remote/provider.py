"""Serveur d'autorisation OAuth maison pour le MCP distant de Sonar.

Implémente `OAuthAuthorizationServerProvider` du SDK `mcp` (vérifié contre 1.27.x),
adossé au stockage `mcp_remote.store` et au modèle utilisateur de Sonar.

Répartition du travail avec le SDK :
  • le SDK gère DCR (génère client_id/secret), la métadonnée RFC 8414, la vérif
    PKCE S256, le match redirect_uri et l'expiration côté `/token` ;
  • ici on fournit le STOCKAGE et la logique : enregistrer/charger un client,
    émettre un code lié au propriétaire APRÈS consentement, échanger code→jetons
    (single-use), faire tourner le refresh, et résoudre/révoquer les jetons.

Flux d'autorisation (consentement adossé à la session magic-link) :
  /authorize  → on stocke la requête « en attente » et on REDIRIGE vers notre page
                de consentement (route ajoutée en Ph.2) ; aucun code n'est encore émis.
  consent     → une fois l'utilisateur authentifié (session Sonar) et consentant,
                `complete_consent(rid, user_id)` émet le code lié à ce propriétaire et
                renvoie l'URL de redirection vers le client (claude.ai) avec code+state.

Tant que la route de consentement n'est pas branchée (Ph.2), ce provider n'est PAS
monté dans l'app live : il est testé en isolation.
"""
from __future__ import annotations

import time

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from mcp_remote import store

DEFAULT_SCOPE = "scans:read"


class SonarOAuthProvider(OAuthAuthorizationServerProvider):
    """Serveur d'autorisation self-contained, scope unique `scans:read` (lecture seule)."""

    def __init__(self, base_url: str, *, scope: str = DEFAULT_SCOPE) -> None:
        self.base_url = base_url.rstrip("/")
        self.scope = scope

    # --- URL de la page de consentement (route servie par l'app, Ph.2) ---------
    def consent_url(self, rid: str) -> str:
        return f"{self.base_url}/mcp/consent?rid={rid}"

    # --- Clients (DCR) ---------------------------------------------------------
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return store.load_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # Le SDK a déjà rempli client_id/secret/timestamps. (Durcissement de la
        # liste blanche des redirect_uris : Ph.4.)
        store.save_client(client_info)

    # --- /authorize : stocke la requête et redirige vers le consentement -------
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        requested = params.scopes or [self.scope]
        if any(s != self.scope for s in requested):
            raise AuthorizeError(error="invalid_scope", error_description=f"seul {self.scope} est autorisé")
        rid = store.create_pending(
            client_id=client.client_id,
            redirect_uri=str(params.redirect_uri),
            redirect_uri_explicit=params.redirect_uri_provided_explicitly,
            code_challenge=params.code_challenge,
            scopes=requested,
            state=params.state,
            resource=params.resource,
        )
        return self.consent_url(rid)

    # --- Consentement (appelé par la route Ph.2 une fois l'utilisateur identifié) ---
    def complete_consent(self, rid: str, user_id: str) -> str | None:
        """Émet le code lié au propriétaire et retourne l'URL de retour vers le client.
        None si la demande en attente est absente/expirée. Synchrone (DB only)."""
        pending = store.take_pending(rid)
        if not pending:
            return None
        code = store.create_code(
            client_id=pending["client_id"],
            user_id=user_id,
            redirect_uri=pending["redirect_uri"],
            redirect_uri_explicit=pending["redirect_uri_explicit"],
            code_challenge=pending["code_challenge"],
            scopes=pending["scopes"],
            resource=pending["resource"],
        )
        return construct_redirect_uri(pending["redirect_uri"], code=code, state=pending["state"])

    # --- /token (authorization_code) -------------------------------------------
    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        row = store.peek_code(authorization_code)
        if not row or row["client_id"] != client.client_id:
            return None
        return AuthorizationCode(
            code=row["code"],
            scopes=row["scopes"],
            expires_at=row["expires_at"],
            client_id=row["client_id"],
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=row["redirect_uri_explicit"],
            resource=row["resource"],
            subject=row["user_id"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # single-use : on consomme le code ; s'il a disparu (rejeu), on refuse.
        if not store.consume_code(authorization_code.code):
            raise TokenError(error="invalid_grant", error_description="authorization code does not exist")
        access, refresh = store.issue_token_pair(
            client_id=client.client_id,
            user_id=authorization_code.subject or "",
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=store.ACCESS_TTL,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh,
        )

    # --- /token (refresh_token) — rotation access + refresh --------------------
    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        row = store.load_refresh(refresh_token)
        if not row or row["client_id"] != client.client_id:
            return None
        return RefreshToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=row["scopes"],
            expires_at=row["expires_at"],
            subject=row["user_id"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # On ne peut qu'effacer/réduire le périmètre, jamais l'élargir.
        granted = [s for s in (scopes or refresh_token.scopes) if s in refresh_token.scopes]
        if not granted:
            granted = list(refresh_token.scopes)
        store.revoke_by_raw(refresh_token.token)  # rotation : l'ancien couple est révoqué
        access, refresh = store.issue_token_pair(
            client_id=client.client_id,
            user_id=refresh_token.subject or "",
            scopes=granted,
            resource=None,
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=store.ACCESS_TTL,
            scope=" ".join(granted),
            refresh_token=refresh,
        )

    # --- Résolution / révocation des access tokens (utilisé par /mcp) ----------
    async def load_access_token(self, token: str) -> AccessToken | None:
        row = store.load_access(token)
        if not row:
            return None
        return AccessToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=row["scopes"],
            expires_at=row["expires_at"],
            resource=row["resource"],
            subject=row["user_id"],
        )

    async def revoke_token(self, token) -> None:
        # token est un AccessToken ou un RefreshToken (déjà chargé par le SDK).
        store.revoke_by_raw(token.token)
