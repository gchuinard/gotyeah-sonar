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

import os


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
