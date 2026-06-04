"""En-têtes supplémentaires : COOP / COEP / CORP + Cache-Control des réponses sensibles."""
from types import SimpleNamespace

import httpx

from scanner.checks.headers import cache, coep, coop, corp
from scanner.finding import Severity


def _ctx(headers):
    resp = httpx.Response(200, headers=headers, content=b"", request=httpx.Request("GET", "https://x/"))
    return SimpleNamespace(response=resp)


async def test_coop():
    assert (await coop(_ctx({"cross-origin-opener-policy": "same-origin"})))[0].code == "ok"
    out = await coop(_ctx({}))
    assert out[0].code == "absent" and out[0].severity == Severity.LOW


async def test_coep():
    assert (await coep(_ctx({"cross-origin-embedder-policy": "require-corp"})))[0].code == "ok"
    assert (await coep(_ctx({})))[0].severity == Severity.INFO


async def test_corp():
    assert (await corp(_ctx({"cross-origin-resource-policy": "same-origin"})))[0].code == "ok"
    assert (await corp(_ctx({})))[0].code == "absent"


async def test_cache_not_applicable():
    out = await cache(_ctx({}))
    assert out[0].code == "not-applicable" and out[0].severity == Severity.PASS


async def test_cache_ok():
    out = await cache(_ctx([("set-cookie", "s=1"), ("cache-control", "no-store")]))
    assert out[0].code == "ok"


async def test_cache_sensitive():
    out = await cache(_ctx([("set-cookie", "s=1")]))
    assert out[0].code == "sensitive-cacheable" and out[0].severity == Severity.LOW
