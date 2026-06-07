"""MCP DISTANT (Streamable HTTP) pour claude.ai, derrière OAuth 2.1 fédéré vers un IdP.

L'auth n'est PLUS maison : elle est déléguée à un IdP OIDC externe (Pocket ID) via
l'**OIDCProxy** du paquet autonome `fastmcp` (≥ 3.4). Répartition :

  • FastMCP/OIDCProxy agit comme serveur d'autorisation côté claude.ai : il proxifie la
    Dynamic Client Registration (RFC 7591), gère PKCE S256, expose la Protected Resource
    Metadata (RFC 9728) et la metadata du serveur d'autorisation (RFC 8414) ;
  • il fédère le login vers l'IdP avec UN client confidentiel pré-enregistré
    (SONAR_OIDC_CLIENT_ID / _SECRET, callback = {base}/auth/callback) ;
  • il valide les access tokens (JWT signés par l'IdP, JWKS récupéré via la discovery).

Les 3 outils (list_domains / list_scans / get_report) sont en LECTURE SEULE et scopés
à l'utilisateur identifié par l'IdP : on mappe `claims["email"]` du token vers un compte
Sonar (`auth.get_user_by_email`). En mono-utilisateur, c'est le compte admin.

`build_remote` reste PUR (aucun effet de bord). Il retourne `(mcp, http_app)` ; l'appelant
doit monter `http_app` en DERNIER et faire tourner SON lifespan (gestionnaire de sessions
du transport Streamable HTTP).

Config (env) :
  SONAR_MCP_REMOTE       opt-in (on/1/true/yes) — sinon tout est désactivé
  SONAR_BASE_URL         URL publique HTTPS de Sonar (issuer / base de l'OIDCProxy)
  SONAR_OIDC_CONFIG_URL  discovery de l'IdP (ex. https://idp.exemple.com/.well-known/openid-configuration)
                         (ou SONAR_OIDC_ISSUER, auquel on ajoute /.well-known/openid-configuration)
  SONAR_OIDC_CLIENT_ID   client confidentiel pré-enregistré côté IdP
  SONAR_OIDC_CLIENT_SECRET  son secret
"""
from __future__ import annotations

import os

DEFAULT_SCOPE = "scans:read"

# Callbacks OAuth de claude.ai à autoriser explicitement (matching strict côté FastMCP).
# claude.ai et claude.com enregistrent dynamiquement leur client (DCR) ; ces redirect_uris
# sont les seuls acceptés. À NE PAS confondre avec le callback IdP ({base}/auth/callback),
# qui, lui, est le seul redirect_uri du client confidentiel pré-enregistré côté Pocket ID.
CLAUDE_REDIRECT_URIS = [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
]

# Scopes que claude.ai peut demander à la DCR (et que la metadata OAuth annonce).
# `offline_access` débloque le refresh token côté IdP. Ils ne sont PAS imposés au token :
# le JWTVerifier valide signature/issuer/audience, pas les scopes — sinon `offline_access`
# (absent du scope de l'access token Pocket ID) ferait échouer la validation.
OIDC_SCOPES = ["openid", "profile", "email", "offline_access"]


def remote_enabled() -> bool:
    """Vrai si le MCP distant est explicitement activé (SONAR_MCP_REMOTE=on).

    Surface PUBLIQUE → opt-in : défaut ÉTEINT. Seules les valeurs « on/1/true/yes » activent.
    """
    v = (os.environ.get("SONAR_MCP_REMOTE") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def oidc_config_url() -> str:
    """URL de découverte OIDC de l'IdP, depuis SONAR_OIDC_CONFIG_URL ou SONAR_OIDC_ISSUER."""
    raw = (os.environ.get("SONAR_OIDC_CONFIG_URL") or "").strip()
    if raw:
        return raw
    issuer = (os.environ.get("SONAR_OIDC_ISSUER") or "").strip().rstrip("/")
    return f"{issuer}/.well-known/openid-configuration" if issuer else ""


def _resolve_user(userinfo_endpoint: str | None = None):
    """Mappe l'identité de l'IdP (email) vers un compte Sonar.

    L'email est lu dans les claims de l'access token ; si absent (Pocket ID ne le met PAS
    dans l'access token, seulement dans le userinfo), on interroge le userinfo avec le
    token porteur. Retourne le dict utilisateur Sonar, ou None. Imports locaux : le module
    ne dépend pas d'`auth`/`httpx` au chargement.
    """
    import auth as sonar_auth
    from fastmcp.server.dependencies import get_access_token

    tok = get_access_token()
    if not tok:
        return None
    claims = getattr(tok, "claims", None) or {}
    email = (claims.get("email") or "").strip()
    if not email and userinfo_endpoint and getattr(tok, "token", None):
        try:
            import httpx
            r = httpx.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {tok.token}"},
                timeout=10,
            )
            if r.status_code == 200:
                email = (r.json().get("email") or "").strip()
        except Exception:
            pass
    if not email:
        # Diagnostic (clés seulement, pas de valeurs) si l'identité reste introuvable.
        try:
            print(f"[mcp-remote] _resolve_user: email introuvable "
                  f"(claims={sorted(claims)}, userinfo={'oui' if userinfo_endpoint else 'non'})")
        except Exception:
            pass
        return None
    return sonar_auth.get_user_by_email(sonar_auth.normalize_email(email))


def build_remote(base_url: str, *, scope: str = DEFAULT_SCOPE):
    """Construit le FastMCP distant (auth déléguée à l'IdP via OIDCProxy) et son app ASGI.

    base_url : URL PUBLIQUE HTTPS de Sonar (ex. https://sonar.gautierchuinard.com).
    Retourne (mcp, http_app). PUR : aucun effet de bord (pas de réseau hors init OIDCProxy,
    pas de DB). L'appelant monte `http_app` en dernier et exécute son lifespan.
    """
    import httpx
    from fastmcp import FastMCP
    from fastmcp.server.auth import JWTVerifier, OAuthProxy

    base = base_url.rstrip("/")
    config_url = oidc_config_url()
    client_id = (os.environ.get("SONAR_OIDC_CLIENT_ID") or "").strip()
    client_secret = (os.environ.get("SONAR_OIDC_CLIENT_SECRET") or "").strip() or None
    if not (config_url and client_id and client_secret):
        raise RuntimeError(
            "Config OIDC incomplète : SONAR_OIDC_CONFIG_URL (ou SONAR_OIDC_ISSUER) + "
            "SONAR_OIDC_CLIENT_ID + SONAR_OIDC_CLIENT_SECRET sont requis."
        )

    # Découverte OIDC de l'IdP (endpoints + JWKS). On utilise OAuthProxy + JWTVerifier
    # plutôt qu'OIDCProxy : OIDCProxy COUPLE les scopes valides (DCR) avec les scopes
    # EXIGÉS sur le token, ce qui casserait la validation (offline_access n'apparaît pas
    # dans le scope de l'access token Pocket ID). OAuthProxy permet de déclarer valid_scopes
    # séparément, sans enforcement côté token.
    disc = httpx.get(config_url, timeout=15).json()
    userinfo_endpoint = disc.get("userinfo_endpoint")

    # Access tokens Pocket ID = JWT RS256 signés par l'IdP (aud = client_id) → validation
    # locale via JWKS (pas d'introspection), sans required_scopes (cf. OIDC_SCOPES).
    verifier = JWTVerifier(
        jwks_uri=disc["jwks_uri"],
        issuer=disc["issuer"],
        audience=client_id,
    )
    auth_provider = OAuthProxy(
        upstream_authorization_endpoint=disc["authorization_endpoint"],
        upstream_token_endpoint=disc["token_endpoint"],
        upstream_revocation_endpoint=disc.get("revocation_endpoint"),
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        token_verifier=verifier,
        base_url=base,
        valid_scopes=OIDC_SCOPES,
        # claude.ai/claude.com s'enregistrent dynamiquement (DCR) ; seuls leurs callbacks.
        allowed_client_redirect_uris=CLAUDE_REDIRECT_URIS,
    )

    mcp = FastMCP(
        "sonar",
        instructions=(
            "Accès LECTURE SEULE aux rapports de sécurité Sonar de l'utilisateur. "
            "Utilise list_domains pour voir les domaines, list_scans pour l'historique, "
            "et get_report(scan_id) pour le détail rendu d'un scan (findings + remédiation)."
        ),
        auth=auth_provider,
    )

    @mcp.tool
    async def list_domains() -> list[dict]:
        """Liste les domaines vérifiés du compte (ceux que l'utilisateur peut scanner)."""
        import auth as sonar_auth

        user = _resolve_user(userinfo_endpoint)
        if not user:
            raise ValueError("Aucun compte Sonar ne correspond à cette identité.")
        return sonar_auth.list_domains(user["id"])

    @mcp.tool
    async def list_scans(domain: str | None = None) -> list[dict]:
        """Scans récents : id, score, note (grade), date, compteurs de sévérité.

        domain : si fourni, ne garde que les scans dont la cible contient ce domaine.
        """
        import db

        user = _resolve_user(userinfo_endpoint)
        if not user:
            raise ValueError("Aucun compte Sonar ne correspond à cette identité.")
        owner = None if user.get("is_admin") else user["id"]
        scans = db.list_scans(user_id=owner)
        if domain:
            needle = domain.strip().lower()
            scans = [s for s in scans if needle in ((s.get("target") or "").lower())]
        return scans

    @mcp.tool
    async def get_report(scan_id: str, lang: str | None = None) -> dict:
        """Rapport complet d'un scan : findings rendus/localisés en JSON.

        scan_id : identifiant renvoyé par list_scans.
        lang    : langue du rendu ('fr', 'en', …) ; défaut = langue du compte.
        """
        import db
        from scanner import i18n

        user = _resolve_user(userinfo_endpoint)
        if not user:
            raise ValueError("Aucun compte Sonar ne correspond à cette identité.")
        owner = None if user.get("is_admin") else user["id"]
        data = db.get_scan(scan_id, user_id=owner)
        if not data:
            raise ValueError("Scan introuvable (ou n'appartient pas à ce compte).")
        available = set(i18n.available_langs())
        chosen = lang if (lang and lang in available) else (user.get("lang") or "fr")
        data["findings"] = [{**f, **i18n.render_finding(f, chosen)} for f in data.get("findings", [])]
        data["lang"] = chosen
        return data

    http_app = mcp.http_app()  # Streamable HTTP ; expose aussi son lifespan (sessions)
    return mcp, http_app
