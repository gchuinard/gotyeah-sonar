"""Fuites & well-known — Phase 2 (actif léger), même esprit que `exposed.py`.

Cinq sondes, toutes en LECTURE SEULE et avec **validation de contenu** (jamais sur le
seul code 200, pour résister aux soft-404) :
  - source maps exposés (`*.js.map` → fuite du code source) ;
  - documentation d'API exposée (Swagger / OpenAPI) ;
  - introspection GraphQL activée ;
  - directory listing (autoindex) ;
  - présence de `/.well-known/security.txt` (bonne pratique).

Chaque sonde renvoie exactement un Finding (problème ou conforme). Tout est borné et
protégé par try/except : une sonde qui échoue ne casse jamais le scan.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.EXPOSURE

_SCRIPT_SRC = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*[\"']([^\"']+)", re.I)
_SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", re.I)


async def _get(ctx, url, **kw):
    try:
        return await ctx.client.get(url, **kw)
    except Exception:
        return None


def _same_origin(html: str, base: str, host: str, limit: int = 4) -> list[str]:
    out, seen = [], set()
    for m in _SCRIPT_SRC.finditer(html or ""):
        absolute = urljoin(base, m.group(1))
        parsed = urlparse(absolute)
        if parsed.scheme in ("http", "https") and parsed.hostname == host and absolute not in seen:
            seen.add(absolute)
            out.append(absolute)
            if len(out) >= limit:
                break
    return out


async def _sourcemaps(ctx) -> list[Finding]:
    try:
        html = ctx.response.text or ""
    except Exception:
        html = ""
    for js_url in _same_origin(html, ctx.url, ctx.host):
        resp = await _get(ctx, js_url)
        if not resp or resp.status_code != 200:
            continue
        try:
            body = resp.text or ""
        except Exception:
            continue
        m = _SOURCEMAP.search(body[-2000:])  # le commentaire est en fin de fichier
        if not m:
            continue
        map_url = urljoin(js_url, m.group(1))
        mresp = await _get(ctx, map_url)
        if mresp and mresp.status_code == 200:
            try:
                data = json.loads(mresp.text or "")
            except Exception:
                data = None
            if isinstance(data, dict) and ("sources" in data or "mappings" in data):
                return [Finding("leak-sourcemap", C, Severity.LOW, code="exposed",
                                params={"url": map_url}, evidence=map_url)]
    return [Finding("leak-sourcemap", C, Severity.PASS, code="clean")]


_SWAGGER_PATHS = ["openapi.json", "swagger.json", "api-docs", "v2/api-docs",
                  "swagger/v1/swagger.json", "api/swagger.json"]


async def _swagger(ctx) -> list[Finding]:
    for path in _SWAGGER_PATHS:
        resp = await _get(ctx, urljoin(ctx.url, path))
        if not resp or resp.status_code != 200:
            continue
        try:
            data = json.loads(resp.text or "")
        except Exception:
            continue
        if isinstance(data, dict) and ("openapi" in data or "swagger" in data or "paths" in data):
            return [Finding("leak-swagger", C, Severity.MEDIUM, code="exposed",
                            params={"path": path}, evidence=urljoin(ctx.url, path))]
    return [Finding("leak-swagger", C, Severity.PASS, code="clean")]


_GRAPHQL_PATHS = ["graphql", "api/graphql", "v1/graphql", "query"]
_INTROSPECTION = '{"query":"{__schema{queryType{name}}}"}'


async def _graphql(ctx) -> list[Finding]:
    for path in _GRAPHQL_PATHS:
        url = urljoin(ctx.url, path)
        try:
            resp = await ctx.client.post(url, content=_INTROSPECTION,
                                         headers={"content-type": "application/json"})
        except Exception:
            continue
        if not resp or resp.status_code != 200:
            continue
        try:
            data = json.loads(resp.text or "")
        except Exception:
            continue
        if isinstance(data, dict) and isinstance(data.get("data"), dict) and "__schema" in data["data"]:
            return [Finding("leak-graphql", C, Severity.MEDIUM, code="introspection",
                            params={"path": path}, evidence=url)]
    return [Finding("leak-graphql", C, Severity.PASS, code="clean")]


_AUTOINDEX_DIRS = ["", "uploads/", "files/", "images/", "static/", "assets/"]
_AUTOINDEX_SIG = re.compile(r"<title>\s*Index of /|Directory listing for /", re.I)


async def _autoindex(ctx) -> list[Finding]:
    # On part de la page déjà récupérée, puis on sonde quelques répertoires courants.
    try:
        if _AUTOINDEX_SIG.search(ctx.response.text or ""):
            return [Finding("leak-autoindex", C, Severity.LOW, code="listing",
                            params={"path": "/"}, evidence=ctx.url)]
    except Exception:
        pass
    for d in _AUTOINDEX_DIRS[1:]:
        resp = await _get(ctx, urljoin(ctx.url, d))
        if resp and resp.status_code == 200:
            try:
                if _AUTOINDEX_SIG.search(resp.text or ""):
                    return [Finding("leak-autoindex", C, Severity.LOW, code="listing",
                                    params={"path": "/" + d}, evidence=urljoin(ctx.url, d))]
            except Exception:
                continue
    return [Finding("leak-autoindex", C, Severity.PASS, code="clean")]


async def _securitytxt(ctx) -> list[Finding]:
    for path in (".well-known/security.txt", "security.txt"):
        resp = await _get(ctx, urljoin(ctx.url, path))
        if not resp or resp.status_code != 200:
            continue
        try:
            body = (resp.text or "").lower()
        except Exception:
            body = ""
        if "contact:" in body or "policy:" in body or "expires:" in body:
            return [Finding("leak-securitytxt", C, Severity.PASS, code="present",
                            evidence=urljoin(ctx.url, path))]
    return [Finding("leak-securitytxt", C, Severity.INFO, code="missing")]


@check("leaks", "Fuites & well-known", C)
async def leaks(ctx):
    findings: list[Finding] = []
    if getattr(ctx, "client", None) is None:
        return findings
    for probe in (_sourcemaps, _swagger, _graphql, _autoindex, _securitytxt):
        try:
            findings.extend(await probe(ctx))
        except Exception:
            continue
    return findings
