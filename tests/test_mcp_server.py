"""Outils du serveur MCP : logique client contre une API Sonar mockée (httpx).

On teste la couche `SonarClient` (= la logique des 3 outils) sans dépendre du SDK `mcp`
(non requis pour la suite). Un test optionnel vérifie l'enregistrement des 3 outils si
le SDK est installé.
"""
import httpx
import pytest

from sonar_mcp.client import SonarClient


def _client(handler):
    """SonarClient branché sur un transport httpx mocké (PAT fixe)."""
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://sonar.test")
    return SonarClient(base_url="https://sonar.test", token="sonar_pat_xyz", client=http)


async def test_list_domains_sends_bearer_and_unwraps():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = request.url.path
        return httpx.Response(200, json={"domains": [{"domain": "a.com", "verified": 1}]})

    out = await _client(handler).domains()
    assert seen["auth"] == "Bearer sonar_pat_xyz"      # le PAT est bien envoyé
    assert seen["path"] == "/api/domains"
    assert out == [{"domain": "a.com", "verified": 1}]


async def test_list_scans_domain_filter():
    scans = [{"id": "1", "target": "https://a.com"}, {"id": "2", "target": "https://b.com"}]

    def handler(request):
        assert request.url.path == "/api/history"
        return httpx.Response(200, json=scans)

    c = _client(handler)
    assert len(await c.scans()) == 2                    # sans filtre : tout
    only = await c.scans(domain="a.com")                # filtre côté MCP
    assert [s["id"] for s in only] == ["1"]


async def test_get_report_passes_lang():
    def handler(request):
        assert request.url.path == "/api/scan/abc"
        assert request.url.params.get("lang") == "en"
        return httpx.Response(200, json={"target": "https://a.com", "findings": []})

    out = await _client(handler).report("abc", lang="en")
    assert out["target"] == "https://a.com"


async def test_error_mapping_401_and_404():
    with pytest.raises(RuntimeError, match="401"):
        await _client(lambda r: httpx.Response(401, json={"error": "x"})).domains()
    with pytest.raises(RuntimeError, match="404"):
        await _client(lambda r: httpx.Response(404, json={"error": "x"})).report("nope")


async def test_missing_config_raises():
    with pytest.raises(RuntimeError, match="SONAR_BASE_URL"):
        await SonarClient(base_url="", token="x").domains()
    with pytest.raises(RuntimeError, match="SONAR_TOKEN"):
        await SonarClient(base_url="https://x", token="").domains()


def test_server_registers_three_tools():
    """Si le SDK mcp est installé : le serveur expose bien les 3 outils."""
    pytest.importorskip("mcp")
    import asyncio

    from sonar_mcp import server
    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert {"list_domains", "list_scans", "get_report"} <= names
