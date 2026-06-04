"""Client HTTP de l'API Sonar pour le serveur MCP.

Le MCP est un simple CLIENT de l'API existante : il ne réimplémente AUCUNE logique
métier. Il s'authentifie avec un jeton personnel (PAT) en lecture seule et appelle les
endpoints déjà en place (/api/domains, /api/history, /api/scan/{id}).

Config par variables d'environnement (lues à défaut d'arguments explicites) :
  SONAR_TOKEN     jeton « sonar_pat_… » généré dans l'UI Sonar (obligatoire)
  SONAR_BASE_URL  base de l'instance, ex. https://sonar.gautierchuinard.com (obligatoire)
"""
from __future__ import annotations

import os

import httpx


class SonarClient:
    """Accès lecture seule à l'API Sonar via un PAT.

    `client` (httpx.AsyncClient) est injectable pour les tests ; sinon un client est
    créé/fermé à chaque appel.
    """

    def __init__(self, base_url: str | None = None, token: str | None = None,
                 client: httpx.AsyncClient | None = None, timeout: float = 20.0):
        env_base = os.environ.get("SONAR_BASE_URL") or ""
        env_token = os.environ.get("SONAR_TOKEN") or ""
        self.base_url = (base_url if base_url is not None else env_base).strip().rstrip("/")
        self.token = (token if token is not None else env_token).strip()
        self._client = client
        self._timeout = timeout

    async def _get(self, path: str, params: dict | None = None):
        if not self.base_url:
            raise RuntimeError("SONAR_BASE_URL manquant (ex. https://sonar.exemple.com).")
        if not self.token:
            raise RuntimeError("SONAR_TOKEN manquant — génère un jeton dans l'UI Sonar.")
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        client = self._client or httpx.AsyncClient(
            base_url=self.base_url, timeout=httpx.Timeout(self._timeout))
        owns = self._client is None
        try:
            resp = await client.get(path, params=params, headers=headers)
        finally:
            if owns:
                await client.aclose()
        if resp.status_code == 401:
            raise RuntimeError("401 — jeton invalide ou révoqué ; régénère-en un dans l'UI Sonar.")
        if resp.status_code == 404:
            raise RuntimeError("404 — introuvable (ou n'appartient pas à ce jeton).")
        resp.raise_for_status()
        return resp.json()

    async def domains(self) -> list[dict]:
        data = await self._get("/api/domains")
        if isinstance(data, dict):
            return data.get("domains", [])
        return data or []

    async def scans(self, domain: str | None = None) -> list[dict]:
        data = await self._get("/api/history")
        if isinstance(data, list):
            scans = data
        elif isinstance(data, dict):
            scans = data.get("scans", [])
        else:
            scans = []
        if domain:
            needle = domain.strip().lower()
            scans = [s for s in scans if needle in ((s.get("target") or "").lower())]
        return scans

    async def report(self, scan_id: str, lang: str | None = None) -> dict:
        params = {"lang": lang} if lang else None
        return await self._get(f"/api/scan/{scan_id}", params=params)
