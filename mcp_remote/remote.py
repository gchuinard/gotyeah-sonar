"""MCP DISTANT (Streamable HTTP) pour claude.ai, derrière OAuth 2.1 fédéré vers un IdP.

L'auth n'est PLUS maison : elle est déléguée à un IdP OIDC externe (Pocket ID) via
l'**OIDCProxy** du paquet autonome `fastmcp` (≥ 3.4). Répartition :

  • FastMCP/OIDCProxy agit comme serveur d'autorisation côté claude.ai : il proxifie la
    Dynamic Client Registration (RFC 7591), gère PKCE S256, expose la Protected Resource
    Metadata (RFC 9728) et la metadata du serveur d'autorisation (RFC 8414) ;
  • il fédère le login vers l'IdP avec UN client confidentiel pré-enregistré
    (SONAR_OIDC_CLIENT_ID / _SECRET, callback = {base}/auth/callback) ;
  • il valide les access tokens (JWT signés par l'IdP, JWKS récupéré via la discovery).

Les outils sont scopés à l'utilisateur identifié par l'IdP : on mappe `claims["email"]`
du token vers un compte Sonar (`auth.get_user_by_email`). En mono-utilisateur, c'est le
compte admin. Trois lectures (list_domains / list_scans / get_report) + une ACTION :
run_scan, qui lance un scan borné aux domaines VÉRIFIÉS du compte (même garde-fou que
le dashboard) et le persiste de façon asynchrone (cf. `scan_jobs`).

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
    """Mappe l'identité de l'IdP (email du token, ou userinfo en repli) vers un compte Sonar.

    Câblage seulement : on récupère l'access token via fastmcp, la logique de mapping (pure
    et testable) vit dans `mcp_remote.tools.resolve_user_from_token`. Imports locaux : le
    module ne dépend pas de fastmcp au chargement.
    """
    from fastmcp.server.dependencies import get_access_token

    from mcp_remote import tools

    tok = get_access_token()
    user = tools.resolve_user_from_token(tok, userinfo_endpoint)
    if user is None and tok is not None:
        # Diagnostic (clés seulement, pas de valeurs) si l'identité reste introuvable.
        try:
            claims = getattr(tok, "claims", None) or {}
            print(f"[mcp-remote] _resolve_user: identité introuvable "
                  f"(claims={sorted(claims)}, userinfo={'oui' if userinfo_endpoint else 'non'})")
        except Exception:
            pass
    return user


def _persistent_oauth_state():
    """Persiste l'état OAuth du MCP (clients DCR + tokens émis) sur le volume `data`, pour qu'un
    REBUILD du conteneur ne déconnecte plus claude.ai. Sur Linux, FastMCP retombe sinon sur un
    stockage EN MÉMOIRE (perdu au redémarrage) → re-consentement à chaque déploiement.

    Les secrets (clé de signature des tokens + clé de chiffrement du store) doivent être STABLES,
    sinon les tokens émis seraient invalidés à chaque redémarrage. Priorité à l'env
    (`SONAR_MCP_JWT_KEY` / `SONAR_MCP_STORAGE_KEY`, utile en multi-instances) ; à défaut, générés
    une fois et persistés sur le volume. Le store FileTree est chiffré (Fernet) pour ne pas
    écrire les tokens amont en clair.

    Retourne `(jwt_signing_key, client_storage)`. En cas d'échec (volume non inscriptible,
    dépendance absente…) retourne `(None, None)` → comportement FastMCP par défaut (état en
    mémoire), SANS jamais empêcher le MCP de démarrer.
    """
    try:
        import json
        import secrets as _secrets

        import db
        from cryptography.fernet import Fernet
        from key_value.aio.stores.filetree import FileTreeStore
        from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

        base_dir = db.DB_PATH.parent / "mcp-oauth"
        base_dir.mkdir(parents=True, exist_ok=True)

        jwt_key = (os.environ.get("SONAR_MCP_JWT_KEY") or "").strip()
        fernet_key = (os.environ.get("SONAR_MCP_STORAGE_KEY") or "").strip()
        sec_file = base_dir / "secrets.json"
        if (not jwt_key or not fernet_key) and sec_file.exists():
            try:
                cached = json.loads(sec_file.read_text())
                jwt_key = jwt_key or (cached.get("jwt_signing_key") or "")
                fernet_key = fernet_key or (cached.get("fernet_key") or "")
            except Exception:
                pass
        if not jwt_key or not fernet_key:
            jwt_key = jwt_key or _secrets.token_urlsafe(48)
            fernet_key = fernet_key or Fernet.generate_key().decode()
            sec_file.write_text(json.dumps({"jwt_signing_key": jwt_key, "fernet_key": fernet_key}))
            try:
                sec_file.chmod(0o600)
            except OSError:
                pass

        storage = FernetEncryptionWrapper(
            key_value=FileTreeStore(data_directory=str(base_dir / "clients")),
            fernet=Fernet(fernet_key.encode()),
        )
        print(f"[mcp-remote] persistance OAuth activée ({base_dir}) — survit aux rebuilds")
        return jwt_key, storage
    except Exception as exc:
        print(f"[mcp-remote] persistance OAuth indisponible ({type(exc).__name__}: {exc}) "
              "— état en mémoire (re-auth à chaque rebuild)")
        return None, None


def build_remote(base_url: str, *, scope: str = DEFAULT_SCOPE):
    """Construit le FastMCP distant (auth déléguée à l'IdP via OIDCProxy) et son app ASGI.

    base_url : URL PUBLIQUE HTTPS de Sonar (ex. https://sonar.gautierchuinard.com).
    Retourne (mcp, http_app). PUR : aucun effet de bord (pas de réseau hors init OIDCProxy,
    pas de DB). L'appelant monte `http_app` en dernier et exécute son lifespan.
    """
    # Validation de la config AVANT d'importer fastmcp : une config OIDC incomplète doit
    # lever RuntimeError même si la dépendance lourde n'est pas installée (dev local), et
    # c'est ce comportement que teste la suite (sans fastmcp).
    base = base_url.rstrip("/")
    config_url = oidc_config_url()
    client_id = (os.environ.get("SONAR_OIDC_CLIENT_ID") or "").strip()
    client_secret = (os.environ.get("SONAR_OIDC_CLIENT_SECRET") or "").strip() or None
    if not (config_url and client_id and client_secret):
        raise RuntimeError(
            "Config OIDC incomplète : SONAR_OIDC_CONFIG_URL (ou SONAR_OIDC_ISSUER) + "
            "SONAR_OIDC_CLIENT_ID + SONAR_OIDC_CLIENT_SECRET sont requis."
        )

    import httpx
    from fastmcp import FastMCP
    from fastmcp.server.auth import JWTVerifier, OAuthProxy
    from mcp.types import ToolAnnotations

    # Annotations MCP : indiquent au client (claude.ai) la nature de chaque outil pour
    # qu'il affiche la bonne UX (et une confirmation avant une action). Les 3 lectures
    # sont sûres/idempotentes ; run_scan est une ACTION (non lecture seule, non idempotente).
    READ_ANN = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
    ACTION_ANN = ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)

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
    # Persistance de l'état OAuth (clients DCR + tokens) sur le volume `data` → un rebuild du
    # conteneur ne re-déconnecte plus claude.ai (None,None = comportement par défaut si indispo).
    jwt_signing_key, client_storage = _persistent_oauth_state()
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
        jwt_signing_key=jwt_signing_key,
        client_storage=client_storage,
    )

    mcp = FastMCP(
        "sonar",
        instructions=(
            "Accès aux scans de sécurité Sonar de l'utilisateur. Lecture : list_domains "
            "(domaines), list_scans (historique), get_report(scan_id) (détail d'un scan), "
            "get_scan_status(scan_id) (état léger : en cours/progress ou score), "
            "diff_scans(scan_a, scan_b) (compare deux scans : corrigé/nouveau/persistant + delta), "
            "get_fix(scan_id, check_id?) (remédiation actionnable : prompt IA + snippet par stack). "
            "Action : run_scan(domain, profile) lance un scan sur un domaine VÉRIFIÉ du compte "
            "(ou un sous-domaine). profile='full' (défaut) = scan complet asynchrone : s'il renvoie "
            "status='running', suis-le avec get_scan_status puis get_report. profile='fast' = scan "
            "rapide (en-têtes/TLS/DNS, sans nuclei/ZAP/ports), résultat direct. Boucle type : "
            "run_scan → get_fix pour corriger → run_scan → diff_scans pour vérifier le gain. "
            "Si présents, les outils notes_* gèrent l'app de notes gotyeah-notes (même IdP). "
            "Pages/sections : notes_list_workspaces, notes_list_pages, notes_get_page, "
            "notes_create_page, notes_update_page, notes_delete_page, notes_search, "
            "notes_list_sections, notes_create_section. Databases (une database EST une page ; "
            "notes_get_page renvoie database.id) : notes_get_database, notes_create_database, "
            "notes_delete_database, notes_create_property, notes_update_property, "
            "notes_delete_property, notes_list_records, notes_get_record, notes_create_record, "
            "notes_update_record, notes_delete_record, notes_create_view, notes_update_view, "
            "notes_delete_view. Les records se manipulent PAR NOM de propriété "
            "(traduits en ids via le schéma de la database). Modèles : "
            "notes_list_templates (modèles dispo : fournis + workspace), "
            "notes_create_database_from_template (database depuis n'importe quel template), "
            "notes_create_ticket_database / notes_create_bug_database (raccourcis tickets/bugs), "
            "notes_set_record_template (modèle de corps LIBRE des nouveaux records). "
            "Sprints (backlog façon Jira) : notes_list_sprints, notes_create_sprint, "
            "notes_update_sprint (state='active' démarrer / 'completed' terminer ; +database_id "
            "pour renvoyer les issues non terminées au backlog), notes_delete_sprint. Affecter une "
            "issue à un sprint : param `sprint` (par NOM, ou 'backlog') de notes_create_record / "
            "notes_update_record."
        ),
        auth=auth_provider,
    )

    # Les corps des outils vivent dans `mcp_remote.tools` (PURS, testables sans le SDK) ;
    # ici on ne fait que résoudre l'utilisateur (token OAuth) puis déléguer. Les docstrings
    # restent ici car FastMCP en fait la description exposée au client.
    from mcp_remote import tools

    @mcp.tool(annotations=READ_ANN)
    async def list_domains() -> list[dict]:
        """Liste les domaines vérifiés du compte (ceux que l'utilisateur peut scanner)."""
        return await tools.list_domains_logic(_resolve_user(userinfo_endpoint))

    @mcp.tool(annotations=READ_ANN)
    async def list_scans(domain: str | None = None) -> list[dict]:
        """Scans récents : id, score, note (grade), date, compteurs de sévérité.

        domain : si fourni, ne garde que les scans dont la cible contient ce domaine.
        """
        return await tools.list_scans_logic(_resolve_user(userinfo_endpoint), domain)

    @mcp.tool(annotations=READ_ANN)
    async def get_report(scan_id: str, lang: str | None = None) -> dict:
        """Rapport complet d'un scan : findings rendus/localisés en JSON.

        scan_id : identifiant renvoyé par list_scans.
        lang    : langue du rendu ('fr', 'en', …) ; défaut = langue du compte.
        """
        return await tools.get_report_logic(_resolve_user(userinfo_endpoint), scan_id, lang)

    @mcp.tool(annotations=READ_ANN)
    async def diff_scans(scan_a: str, scan_b: str, lang: str | None = None) -> dict:
        """Compare deux scans : ce qui a été corrigé, ce qui est nouveau, ce qui persiste.

        scan_a : scan de référence (AVANT) ; scan_b : scan à comparer (APRÈS).
        Renvoie les problèmes `resolved`/`new`/`persistent` et le delta de score —
        idéal pour vérifier qu'une correction a bien fonctionné entre deux run_scan.
        """
        return await tools.diff_scans_logic(_resolve_user(userinfo_endpoint), scan_a, scan_b, lang)

    @mcp.tool(annotations=READ_ANN)
    async def get_fix(scan_id: str, check_id: str | None = None,
                      code: str | None = None, lang: str | None = None) -> list[dict]:
        """Remédiation actionnable des problèmes d'un scan (prompt IA + snippet par stack).

        scan_id  : scan dont on veut les correctifs.
        check_id : optionnel, ne garde que ce check (ex. 'hdr-csp') ; code : affine encore.
        Pour chaque problème : explication, étapes, variantes par stack (stack détectée
        surlignée) et un `ai_prompt` prêt à coller dans un agent de code (Claude Code).
        """
        return await tools.get_fix_logic(_resolve_user(userinfo_endpoint), scan_id, check_id, code, lang)

    @mcp.tool(annotations=READ_ANN)
    async def get_scan_status(scan_id: str) -> dict:
        """État LÉGER d'un scan (sans les findings) : statut + progression ou score.

        scan_id : identifiant renvoyé par run_scan ou list_scans.
        Renvoie {status:'running', done, total} tant que le scan tourne (idéal pour suivre
        un run_scan sans retélécharger le rapport), sinon {status, score, grade, counts}.
        """
        return await tools.get_scan_status_logic(_resolve_user(userinfo_endpoint), scan_id)

    @mcp.tool(annotations=ACTION_ANN)
    async def run_scan(domain: str, profile: str = "full") -> dict:
        """Lance un scan de sécurité sur un domaine VÉRIFIÉ du compte (action active).

        domain  : domaine à scanner — doit être un domaine vérifié de l'utilisateur, ou
                  un de ses sous-domaines (même garde-fou que le dashboard).
        profile : 'full' (défaut) = scan complet (en-têtes, TLS, DNS, exposition, ports,
                  nuclei, ZAP) ; 'fast' = scan rapide (passif/actif léger seulement, sans
                  nuclei/ZAP/ports) — quelques secondes, résultat direct.

        Le scan tourne en arrière-plan et est persisté quoi qu'il arrive. S'il se termine
        vite (toujours le cas en 'fast'), l'outil renvoie le rapport complet (mêmes champs
        que get_report). Sinon il renvoie {scan_id, status:'running'} : suis-le avec
        get_scan_status(scan_id), puis récupère le rapport via get_report(scan_id).
        """
        return await tools.run_scan_logic(_resolve_user(userinfo_endpoint), domain, profile)

    # ── gotyeah-notes : outils notes_* (pont de confiance vers l'API Next) ──────────
    # Réutilise l'auth IdP de CE MCP : on extrait l'email vérifié du token OAuth et on le
    # transmet à l'API gotyeah-notes (X-MCP-Secret + X-Act-As-Email). Aucune nouvelle
    # plomberie OAuth. Exposé uniquement si NOTES_API_BASE_URL et NOTES_MCP_SECRET sont
    # définis (sinon ce MCP reste strictement Sonar).
    from mcp_remote import notes_tools

    if notes_tools.enabled():

        def _notes_email():
            from fastmcp.server.dependencies import get_access_token

            return notes_tools.resolve_email(get_access_token(), userinfo_endpoint)

        @mcp.tool(annotations=READ_ANN)
        async def notes_list_workspaces() -> list[dict]:
            """Espaces de travail (workspaces) gotyeah-notes de l'utilisateur (id, name)."""
            return await notes_tools.list_workspaces(_notes_email())

        @mcp.tool(annotations=READ_ANN)
        async def notes_list_pages(workspace_id: str) -> list[dict]:
            """Pages d'un workspace (liste plate : id, title, icon, parentId, sectionId…).

            workspace_id : id renvoyé par notes_list_workspaces. parentId/sectionId
            permettent de reconstruire l'arborescence côté client.
            """
            return await notes_tools.list_pages(_notes_email(), workspace_id)

        @mcp.tool(annotations=READ_ANN)
        async def notes_get_page(page_id: str) -> dict:
            """Page complète, dont `content` (document BlockNote sérialisé en JSON)."""
            return await notes_tools.get_page(_notes_email(), page_id)

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_create_page(workspace_id: str, title: str = "Sans titre",
                                    parent_id: str | None = None,
                                    section_id: str | None = None) -> dict:
            """Crée une page. parent_id → sous-page ; section_id → la range dans une section
            (sinon racine). Renvoie la page créée (avec son id)."""
            return await notes_tools.create_page(
                _notes_email(), workspace_id, title, parent_id, section_id
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_update_page(page_id: str, title: str | None = None,
                                    content: str | None = None,
                                    icon: str | None = None) -> dict:
            """Met à jour une page (titre, icône emoji, ou `content` BlockNote JSON).
            Seuls les champs fournis sont modifiés."""
            return await notes_tools.update_page(
                _notes_email(), page_id, title, content, icon
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_delete_page(page_id: str) -> dict:
            """Supprime une page ET ses sous-pages. Irréversible."""
            return await notes_tools.delete_page(_notes_email(), page_id)

        @mcp.tool(annotations=READ_ANN)
        async def notes_search(query: str, workspace_id: str | None = None) -> list[dict]:
            """Recherche plein-texte dans les titres/contenus de pages (max 12 résultats)."""
            return await notes_tools.search(_notes_email(), query, workspace_id)

        @mcp.tool(annotations=READ_ANN)
        async def notes_list_sections(workspace_id: str) -> list[dict]:
            """Sections (conteneurs de la sidebar : 'team'/'private') d'un workspace."""
            return await notes_tools.list_sections(_notes_email(), workspace_id)

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_create_section(workspace_id: str, name: str,
                                       type: str = "team") -> dict:
            """Crée une section. type = 'team' (partagée) ou 'private'."""
            return await notes_tools.create_section(_notes_email(), workspace_id, name, type)

        # ── Databases / properties / records / views (MCP v2) ──────────────────
        # Une database EST une page (relation 1-1). `notes_get_page` renvoie
        # `database: {id}` si la page en est une. À partir de cet id : schéma
        # (properties + views) via notes_get_database, puis CRUD records.

        @mcp.tool(annotations=READ_ANN)
        async def notes_get_database(database_id: str) -> dict:
            """Schéma d'une database : `properties` (colonnes : id, name, type, config)
            et `views`. Indispensable avant d'écrire des records : donne le mapping
            nom→id des propriétés et des options select."""
            return await notes_tools.get_database(_notes_email(), database_id)

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_create_database(page_id: str) -> dict:
            """Transforme une page existante en database (ajoute une propriété titre +
            une vue table par défaut). Renvoie la database créée (avec son id)."""
            return await notes_tools.create_database(_notes_email(), page_id)

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_delete_database(database_id: str) -> dict:
            """Supprime une database (properties, records, views). La page hôte reste.
            Irréversible."""
            return await notes_tools.delete_database(_notes_email(), database_id)

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_create_property(database_id: str, name: str, type: str,
                                        options: list[str] | None = None,
                                        number_format: str | None = None,
                                        date_include_time: bool = False) -> dict:
            """Ajoute une colonne. type ∈ text|number|select|multiselect|date|checkbox|url|email
            (pas 'title' : déjà créée). Pour select/multiselect, `options` = liste de NOMS
            (les ids d'option sont générés). number_format ∈ integer|decimal|currency|percent."""
            return await notes_tools.create_property(
                _notes_email(), database_id, name, type,
                options, number_format, date_include_time
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_update_property(property_id: str, name: str | None = None,
                                        position: float | None = None) -> dict:
            """Renomme/réordonne une colonne. (Changer le type ou éditer les options
            d'un select n'est pas supporté ici — passer par l'UI pour préserver les
            valeurs des records existants.)"""
            return await notes_tools.update_property(
                _notes_email(), property_id, name, position
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_delete_property(property_id: str) -> dict:
            """Supprime une colonne et sa valeur dans tous les records. La colonne titre
            ne peut pas être supprimée. Irréversible."""
            return await notes_tools.delete_property(_notes_email(), property_id)

        @mcp.tool(annotations=READ_ANN)
        async def notes_list_records(database_id: str) -> list[dict]:
            """Lignes (records) d'une database : title, icon, et `properties` indexées
            par id de propriété (résoudre les noms via notes_get_database)."""
            return await notes_tools.list_records(_notes_email(), database_id)

        @mcp.tool(annotations=READ_ANN)
        async def notes_get_record(record_id: str) -> dict:
            """Un record complet (title, properties par id, content BlockNote, databaseId)."""
            return await notes_tools.get_record(_notes_email(), record_id)

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_create_record(database_id: str, title: str | None = None,
                                      icon: str | None = None,
                                      properties: dict | None = None,
                                      sprint: str | None = None) -> dict:
            """Crée une ligne. `properties` est désignée PAR NOM, ex.
            {"Statut": "En cours", "Tags": ["Urgent"]} : l'outil traduit noms→ids et
            options select→ids via le schéma. Le titre passe par `title` (ou la
            propriété "Titre" dans properties). `sprint` = NOM d'un sprint pour y
            rattacher l'issue (vue backlog ; omettre = backlog)."""
            return await notes_tools.create_record(
                _notes_email(), database_id, title, icon, properties, sprint
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_update_record(record_id: str, title: str | None = None,
                                      icon: str | None = None, content: str | None = None,
                                      properties: dict | None = None,
                                      position: float | None = None,
                                      sprint: str | None = None) -> dict:
            """Met à jour une ligne (champs fournis seulement). `properties` PAR NOM,
            fusionnée (une valeur null efface la cellule). content = document BlockNote JSON.
            `sprint` = NOM d'un sprint pour (ré)affecter l'issue, ou "backlog" pour la
            renvoyer au backlog."""
            return await notes_tools.update_record(
                _notes_email(), record_id, title, icon, content, properties, position, sprint
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_delete_record(record_id: str) -> dict:
            """Supprime une ligne. Irréversible."""
            return await notes_tools.delete_record(_notes_email(), record_id)

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_create_view(database_id: str, type: str,
                                    name: str | None = None,
                                    config: dict | None = None) -> dict:
            """Crée une vue. type ∈ table|kanban|calendar|gallery|backlog. `config`
            (optionnel) référence les propriétés par id : visiblePropertyIds, sorts,
            filters, groupByPropertyId (kanban), calendarPropertyId, et pour le
            backlog/board scrum pointsPropertyId/statusPropertyId/epicPropertyId/
            doneStatusOptionId + sprintScope (kanban : "active"|"all"|<sprintId>)."""
            return await notes_tools.create_view(
                _notes_email(), database_id, type, name, config
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_update_view(view_id: str, name: str | None = None,
                                    config: dict | None = None,
                                    position: float | None = None) -> dict:
            """Met à jour une vue. ⚠️ `config` REMPLACE entièrement l'ancien (pas de
            merge) : renvoyer le config complet voulu."""
            return await notes_tools.update_view(
                _notes_email(), view_id, name, config, position
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_delete_view(view_id: str) -> dict:
            """Supprime une vue (impossible si c'est la dernière de la database)."""
            return await notes_tools.delete_view(_notes_email(), view_id)

        # ── Modèles (tickets façon Jira) ───────────────────────────────────────

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_create_ticket_database(page_id: str) -> dict:
            """Transforme une page en database de TICKETS (façon Jira) : colonnes
            Statut / Priorité / Type / Assigné / Échéance + vue kanban par statut +
            modèle de corps (Problème fonctionnel / Résolution technique / Tests à
            faire) appliqué à chaque nouveau ticket. Renvoie la database créée."""
            return await notes_tools.create_ticket_database(_notes_email(), page_id)

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_create_bug_database(page_id: str) -> dict:
            """Transforme une page en database de BUGS : colonnes Statut / Sévérité /
            Assigné / Échéance + vue kanban par statut + modèle de corps (Comment
            reproduire / Résultat attendu / Résultat obtenu / Environnement) appliqué
            à chaque nouveau bug. Renvoie la database créée."""
            return await notes_tools.create_bug_database(_notes_email(), page_id)

        @mcp.tool(annotations=READ_ANN)
        async def notes_list_templates(workspace_id: str) -> list[dict]:
            """Templates disponibles d'un workspace : fournis (id « builtin-* », ex.
            tickets/bugs) + ceux créés par l'utilisateur. Chacun a id, name, builtin,
            columns, kanbanGroupProperty, sections (libellés de corps à libellés fixes)."""
            return await notes_tools.list_templates(_notes_email(), workspace_id)

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_create_database_from_template(page_id: str, template_id: str) -> dict:
            """Transforme une page en database scaffoldée depuis n'importe quel template
            (colonnes + kanban + sections de corps). template_id vient de
            notes_list_templates (« builtin-… » ou id de template du workspace)."""
            return await notes_tools.create_database_from_template(
                _notes_email(), page_id, template_id
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_set_record_template(database_id: str,
                                            content: list | str | None = None) -> dict:
            """Définit le modèle de corps pré-rempli sur les NOUVEAUX records de la
            database (None pour l'effacer). `content` = structure BlockNote (liste de
            blocs) ou string JSON. N'affecte pas les records existants."""
            return await notes_tools.set_record_template(_notes_email(), database_id, content)

        # ── Sprints (backlog façon Jira) ───────────────────────────────────────

        @mcp.tool(annotations=READ_ANN)
        async def notes_list_sprints(database_id: str) -> list[dict]:
            """Sprints d'une database (backlog façon Jira) : id, name, goal, startDate,
            endDate, state (future|active|completed), position. Les issues y sont
            rattachées via leur champ sprintId (null = backlog)."""
            return await notes_tools.list_sprints(_notes_email(), database_id)

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_create_sprint(database_id: str, name: str | None = None,
                                      goal: str | None = None,
                                      start_date: str | None = None,
                                      end_date: str | None = None,
                                      state: str | None = None) -> dict:
            """Crée un sprint dans une database. state par défaut 'future' (planifié).
            start_date/end_date au format ISO (ex. '2026-07-01')."""
            return await notes_tools.create_sprint(
                _notes_email(), database_id, name, goal, start_date, end_date, state
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_update_sprint(sprint_id: str, name: str | None = None,
                                      goal: str | None = None,
                                      start_date: str | None = None,
                                      end_date: str | None = None,
                                      state: str | None = None,
                                      position: float | None = None,
                                      database_id: str | None = None,
                                      move_incomplete_to_backlog: bool = True) -> dict:
            """Met à jour un sprint. state='active' = DÉMARRER (refus 409 si un autre
            sprint est déjà actif), state='completed' = TERMINER. Pour terminer en
            renvoyant les issues non terminées au backlog, passe aussi `database_id`
            (l'outil lit la config de la vue backlog — statut + option « terminé » —
            et demande le déplacement atomique côté serveur)."""
            return await notes_tools.update_sprint(
                _notes_email(), sprint_id, name, goal, start_date, end_date,
                state, position, database_id, move_incomplete_to_backlog
            )

        @mcp.tool(annotations=ACTION_ANN)
        async def notes_delete_sprint(sprint_id: str) -> dict:
            """Supprime un sprint. Ses issues retournent au backlog (sprintId=null)."""
            return await notes_tools.delete_sprint(_notes_email(), sprint_id)

    http_app = mcp.http_app()  # Streamable HTTP ; expose aussi son lifespan (sessions)
    return mcp, http_app
