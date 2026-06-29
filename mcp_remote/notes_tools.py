"""Outils MCP gotyeah-notes — greffés sur le MCP distant Sonar existant.

Le MCP distant (`mcp_remote/remote.py`) authentifie déjà l'utilisateur via l'IdP
(Pocket ID). On ne refait donc AUCUNE auth ici : on extrait l'email vérifié du
token, puis on appelle l'API REST de gotyeah-notes en « sous-système de confiance »
(en-têtes `X-MCP-Secret` + `X-Act-As-Email`). gotyeah-notes mappe l'email -> User
existant (cf. son `lib/session.ts`).

Découplé de Sonar : aucun compte Sonar requis, on n'importe jamais `fastmcp` ici
(donc testable). Config par variables d'environnement :
  NOTES_API_BASE_URL  base interne de l'app, ex. http://gotyeah_notes:3000
  NOTES_MCP_SECRET    secret partagé (== MCP_SHARED_SECRET côté gotyeah-notes)
"""
from __future__ import annotations

import json
import os
import uuid


def enabled() -> bool:
    """Vrai si la config notes est complète → les outils notes_* sont exposés."""
    return bool(
        (os.environ.get("NOTES_API_BASE_URL") or "").strip()
        and (os.environ.get("NOTES_MCP_SECRET") or "").strip()
    )


def _claim_truthy(val) -> bool:
    """`email_verified` (OIDC) est un booléen ; on tolère la string "true" par robustesse."""
    return val is True or (isinstance(val, str) and val.strip().lower() == "true")


def resolve_email(tok, userinfo_endpoint: str | None = None) -> str | None:
    """Email VÉRIFIÉ de l'utilisateur depuis le token IdP.

    Pocket ID ne met pas l'email dans l'access token → repli sur le `userinfo`. On EXIGE
    `email_verified` (anti-usurpation) : sans email vérifié, on renvoie None. Lit l'email
    ET sa vérif à la MÊME source (claims, ou userinfo en repli).
    """
    if tok is None:
        return None
    claims = getattr(tok, "claims", None) or {}
    email = (claims.get("email") or "").strip()
    verified = _claim_truthy(claims.get("email_verified"))
    if not email and userinfo_endpoint and getattr(tok, "token", None):
        try:
            import httpx

            resp = httpx.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {tok.token}"},
                timeout=10,
            )
            if resp.status_code == 200:
                info = resp.json()
                email = (info.get("email") or "").strip()
                verified = _claim_truthy(info.get("email_verified"))
        except Exception:
            return None
    if not email or not verified:
        return None
    return email


class NotesClient:
    """Client de l'API gotyeah-notes via le pont de confiance (secret + email)."""

    def __init__(self):
        self.base = (os.environ.get("NOTES_API_BASE_URL") or "").strip().rstrip("/")
        self.secret = (os.environ.get("NOTES_MCP_SECRET") or "").strip()

    async def _req(self, method: str, path: str, email: str | None,
                   params: dict | None = None, json=None):
        if not self.base or not self.secret:
            raise RuntimeError("NOTES_API_BASE_URL / NOTES_MCP_SECRET manquant.")
        if not email:
            raise RuntimeError("Identité IdP introuvable (email vérifié requis).")
        import httpx

        headers = {
            "X-MCP-Secret": self.secret,
            "X-Act-As-Email": email,
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(base_url=self.base, timeout=httpx.Timeout(20.0)) as c:
            resp = await c.request(method, path, params=params, json=json, headers=headers)
        if resp.status_code == 401:
            raise RuntimeError(
                "401 — secret MCP invalide, ou cet email n'a pas de compte gotyeah-notes."
            )
        if resp.status_code == 404:
            raise RuntimeError("404 — introuvable (ou pas d'accès).")
        resp.raise_for_status()
        ctype = resp.headers.get("content-type", "")
        return resp.json() if ctype.startswith("application/json") else {"ok": True}


# --------------------------------------------------------------------------- #
# Logique des outils. `email` est résolu en amont (remote.py) à chaque appel.
# --------------------------------------------------------------------------- #
async def list_workspaces(email: str | None) -> list[dict]:
    return await NotesClient()._req("GET", "/api/workspaces", email)


async def list_pages(email: str | None, workspace_id: str) -> list[dict]:
    return await NotesClient()._req(
        "GET", "/api/pages", email, params={"workspaceId": workspace_id}
    )


async def get_page(email: str | None, page_id: str) -> dict:
    return await NotesClient()._req("GET", f"/api/pages/{page_id}", email)


async def create_page(email: str | None, workspace_id: str, title: str = "Sans titre",
                      parent_id: str | None = None, section_id: str | None = None) -> dict:
    body = {
        "workspaceId": workspace_id,
        "title": title,
        "parentId": parent_id,
        "sectionId": section_id,
    }
    return await NotesClient()._req("POST", "/api/pages", email, json=body)


async def update_page(email: str | None, page_id: str, title: str | None = None,
                      content: str | None = None, icon: str | None = None) -> dict:
    body: dict = {}
    if title is not None:
        body["title"] = title
    if content is not None:
        body["content"] = content
    if icon is not None:
        body["icon"] = icon
    return await NotesClient()._req("PATCH", f"/api/pages/{page_id}", email, json=body)


async def delete_page(email: str | None, page_id: str) -> dict:
    return await NotesClient()._req("DELETE", f"/api/pages/{page_id}", email)


async def search(email: str | None, query: str, workspace_id: str | None = None) -> list[dict]:
    params = {"q": query}
    if workspace_id:
        params["workspaceId"] = workspace_id
    return await NotesClient()._req("GET", "/api/search", email, params=params)


async def list_sections(email: str | None, workspace_id: str) -> list[dict]:
    return await NotesClient()._req(
        "GET", "/api/sections", email, params={"workspaceId": workspace_id}
    )


async def create_section(email: str | None, workspace_id: str, name: str,
                         type: str = "team") -> dict:
    body = {"workspaceId": workspace_id, "name": name, "type": type}
    return await NotesClient()._req("POST", "/api/sections", email, json=body)


# --------------------------------------------------------------------------- #
# Databases / properties / records / views (MCP v2)
#
# Côté gotyeah-notes, les valeurs d'un record sont indexées par DatabaseProperty.id
# (stable), et un select stocke l'id d'option — JAMAIS les noms (cf. son lib/db.ts).
# Pour rester utilisable par une IA, on expose une API "par nom" : les outils
# traduisent nom de propriété -> id et nom d'option select -> id d'option à partir
# du schéma de la database, et routent la propriété de type "title" vers le champ
# `title` du record. La traduction vit dans `resolve_record_properties` (pure,
# testée). Les fonctions réseau ci-dessous ne font qu'assembler le payload.
# --------------------------------------------------------------------------- #

# Palette utilisée pour colorer les options select créées via le MCP. Les couleurs
# exactes importent peu (l'app sait afficher n'importe quelle string) ; on varie
# juste pour la lisibilité.
_SELECT_COLORS = ["blue", "green", "yellow", "orange", "red", "pink", "purple", "gray"]


def _match_by_name(items: list[dict], name: str, label: str) -> dict:
    """Trouve un item par sa clé `name` : exact d'abord, puis insensible à la casse.

    Lève `ValueError` (message explicite listant les noms valides — utile pour l'IA
    appelante) si le nom est introuvable ou ambigu.
    """
    exact = [it for it in items if it.get("name") == name]
    if len(exact) == 1:
        return exact[0]
    low = (name or "").strip().lower()
    ci = [it for it in items if (it.get("name") or "").strip().lower() == low]
    if len(ci) == 1:
        return ci[0]
    valid = ", ".join(repr(it.get("name")) for it in items) or "(aucun)"
    if exact or ci:
        raise ValueError(f"{label} ambigu·ë : {name!r}. Noms disponibles : {valid}.")
    raise ValueError(f"{label} introuvable : {name!r}. Noms disponibles : {valid}.")


def resolve_record_properties(
    schema_properties: list[dict], props_by_name: dict | None
) -> tuple[str | None, dict]:
    """Traduit des propriétés désignées par NOM en payload API indexé par id.

    schema_properties : `properties` d'une database (cf. get_database), chacune
        ayant {id, name, type, config}.
    props_by_name : {nom_de_propriété: valeur}. Pour un select la valeur est le NOM
        d'une option ; pour un multiselect une liste de noms ; `None` efface la cellule.

    Retourne `(title, properties_by_id)` :
      - title : valeur si une propriété de type "title" est fournie (sinon None) ;
      - properties_by_id : {propertyId: valeur} prêt pour l'API gotyeah-notes.
    Lève `ValueError` si un nom de propriété ou d'option est inconnu.
    """
    title: str | None = None
    out: dict = {}
    for name, value in (props_by_name or {}).items():
        prop = _match_by_name(schema_properties, name, "Propriété")
        ptype = prop.get("type")
        pid = prop.get("id")
        if ptype == "title":
            title = None if value is None else str(value)
            continue
        if value is None:
            out[pid] = None  # sentinelle de suppression (mergeRecordProperties côté API)
            continue
        if ptype in ("select", "multiselect"):
            options = (prop.get("config") or {}).get("options") or []
            if ptype == "select":
                out[pid] = _match_by_name(options, str(value), "Option")["id"]
            else:
                if not isinstance(value, (list, tuple)):
                    raise ValueError(
                        f"La propriété multiselect {name!r} attend une liste de noms d'options."
                    )
                out[pid] = [_match_by_name(options, str(v), "Option")["id"] for v in value]
        else:
            out[pid] = value
    return title, out


def _build_property_config(
    ptype: str,
    options: list[str] | None = None,
    number_format: str | None = None,
    date_include_time: bool = False,
) -> dict:
    """Construit le `config` JSON d'une DatabaseProperty depuis des paramètres simples.

    Pour select/multiselect, `options` est une liste de NOMS → on génère des ids
    d'option stables. Pour number/date, on pose le format/includeTime.
    """
    if ptype in ("select", "multiselect"):
        opts = [
            {"id": uuid.uuid4().hex[:8], "name": str(n),
             "color": _SELECT_COLORS[i % len(_SELECT_COLORS)]}
            for i, n in enumerate(options or [])
        ]
        return {"type": ptype, "options": opts}
    if ptype == "number":
        return {"type": ptype, "format": number_format or "decimal"}
    if ptype == "date":
        return {"type": ptype, "includeTime": bool(date_include_time)}
    return {"type": ptype}


# ── Databases ────────────────────────────────────────────────────────────────
async def get_database(email: str | None, database_id: str) -> dict:
    return await NotesClient()._req("GET", f"/api/databases/{database_id}", email)


async def create_database(email: str | None, page_id: str) -> dict:
    return await NotesClient()._req("POST", "/api/databases", email, json={"pageId": page_id})


async def delete_database(email: str | None, database_id: str) -> dict:
    return await NotesClient()._req("DELETE", f"/api/databases/{database_id}", email)


# ── Properties (colonnes) ────────────────────────────────────────────────────
async def create_property(email: str | None, database_id: str, name: str, type: str,
                          options: list[str] | None = None,
                          number_format: str | None = None,
                          date_include_time: bool = False) -> dict:
    config = _build_property_config(type, options, number_format, date_include_time)
    body = {"name": name, "type": type, "config": config}
    return await NotesClient()._req(
        "POST", f"/api/databases/{database_id}/properties", email, json=body
    )


async def update_property(email: str | None, property_id: str, name: str | None = None,
                          position: float | None = None) -> dict:
    body: dict = {}
    if name is not None:
        body["name"] = name
    if position is not None:
        body["position"] = position
    return await NotesClient()._req("PATCH", f"/api/properties/{property_id}", email, json=body)


async def delete_property(email: str | None, property_id: str) -> dict:
    return await NotesClient()._req("DELETE", f"/api/properties/{property_id}", email)


# ── Records (lignes) ─────────────────────────────────────────────────────────
async def list_records(email: str | None, database_id: str) -> list[dict]:
    return await NotesClient()._req("GET", f"/api/databases/{database_id}/records", email)


async def get_record(email: str | None, record_id: str) -> dict:
    return await NotesClient()._req("GET", f"/api/records/{record_id}", email)


async def create_record(email: str | None, database_id: str, title: str | None = None,
                        icon: str | None = None, properties: dict | None = None) -> dict:
    body: dict = {}
    if properties:
        schema = await get_database(email, database_id)
        title_from_props, props_by_id = resolve_record_properties(
            schema.get("properties") or [], properties
        )
        if props_by_id:
            body["properties"] = props_by_id
        if title is None:
            title = title_from_props
    if title is not None:
        body["title"] = title
    if icon is not None:
        body["icon"] = icon
    return await NotesClient()._req(
        "POST", f"/api/databases/{database_id}/records", email, json=body
    )


async def update_record(email: str | None, record_id: str, title: str | None = None,
                        icon: str | None = None, content: str | None = None,
                        properties: dict | None = None,
                        position: float | None = None) -> dict:
    body: dict = {}
    if properties:
        record = await get_record(email, record_id)
        schema = await get_database(email, record.get("databaseId"))
        title_from_props, props_by_id = resolve_record_properties(
            schema.get("properties") or [], properties
        )
        if props_by_id:
            body["properties"] = props_by_id
        if title is None:
            title = title_from_props
    if title is not None:
        body["title"] = title
    if icon is not None:
        body["icon"] = icon
    if content is not None:
        body["content"] = content
    if position is not None:
        body["position"] = position
    return await NotesClient()._req("PATCH", f"/api/records/{record_id}", email, json=body)


async def delete_record(email: str | None, record_id: str) -> dict:
    return await NotesClient()._req("DELETE", f"/api/records/{record_id}", email)


# ── Views ────────────────────────────────────────────────────────────────────
async def create_view(email: str | None, database_id: str, type: str,
                      name: str | None = None, config: dict | None = None) -> dict:
    body: dict = {"type": type}
    if name is not None:
        body["name"] = name
    if config is not None:
        body["config"] = config
    return await NotesClient()._req(
        "POST", f"/api/databases/{database_id}/views", email, json=body
    )


async def update_view(email: str | None, view_id: str, name: str | None = None,
                      config: dict | None = None, position: float | None = None) -> dict:
    body: dict = {}
    if name is not None:
        body["name"] = name
    if config is not None:
        body["config"] = config
    if position is not None:
        body["position"] = position
    return await NotesClient()._req("PATCH", f"/api/views/{view_id}", email, json=body)


async def delete_view(email: str | None, view_id: str) -> dict:
    return await NotesClient()._req("DELETE", f"/api/views/{view_id}", email)


# ── Modèles (tickets façon Jira) ─────────────────────────────────────────────
async def create_ticket_database(email: str | None, page_id: str) -> dict:
    """Transforme une page en database de tickets (colonnes standard + kanban +
    modèle de corps à 3 zones). Le serveur gère le scaffolding (cf. lib/templates.ts)."""
    return await NotesClient()._req(
        "POST", "/api/databases", email, json={"pageId": page_id, "template": "ticket"}
    )


async def set_record_template(email: str | None, database_id: str, content) -> dict:
    """Définit (ou efface si None) le modèle de corps des nouveaux records.

    `content` peut être la structure BlockNote (liste de blocs) ou une string JSON
    déjà sérialisée. Stocké tel quel dans Database.recordTemplate côté API.
    """
    if content is not None and not isinstance(content, str):
        content = json.dumps(content)
    return await NotesClient()._req(
        "PATCH", f"/api/databases/{database_id}", email, json={"recordTemplate": content}
    )
