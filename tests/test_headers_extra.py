"""En-têtes supplémentaires : COOP / COEP / CORP + Cache-Control des réponses sensibles."""
from types import SimpleNamespace

import httpx

from scanner.checks.headers import cache, coep, coop, corp, csp, hsts, referrer, xfo
from scanner.finding import Severity


def _ctx(headers):
    resp = httpx.Response(200, headers=headers, content=b"", request=httpx.Request("GET", "https://x/"))
    return SimpleNamespace(response=resp)


# ---- Batch 2 : présence → VALEUR ----

async def test_csp_value_not_just_presence():
    async def code_of(policy):
        return (await csp(_ctx({"content-security-policy": policy})))[0]
    # `default-src *` : présente mais grande ouverte → permissive (plus jamais « ok »).
    f = await code_of("default-src *")
    assert f.code == "permissive" and f.severity == Severity.MEDIUM
    f = await code_of("script-src 'self' https:")
    assert f.code == "permissive"
    # une CSP sans aucune directive de script ne restreint pas les scripts.
    assert (await code_of("upgrade-insecure-requests")).code == "permissive"
    # politique stricte → ok.
    assert (await code_of("default-src 'self'")).code == "ok"
    # unsafe-inline → weak ; insensible à la casse.
    assert (await code_of("default-src 'self' 'unsafe-inline'")).code == "weak"
    assert (await code_of("default-src 'self' 'UNSAFE-INLINE'")).code == "weak"
    # strict-dynamic + nonce neutralise unsafe-inline (CSP en réalité robuste) → ok.
    assert (await code_of("script-src 'self' 'unsafe-inline' 'strict-dynamic' 'nonce-abc'")).code == "ok"


async def test_xfo_value_validated():
    async def f(headers):
        return (await xfo(_ctx(headers)))[0]
    assert (await f({"x-frame-options": "DENY"})).code == "ok"
    assert (await f({"x-frame-options": "ALLOWALL"})).code == "permissive"
    assert (await f({"content-security-policy": "frame-ancestors *"})).code == "permissive"
    assert (await f({"content-security-policy": "frame-ancestors 'self'"})).code == "ok"
    assert (await f({})).code == "absent"


async def test_hsts_disabled_when_maxage_zero_or_missing():
    async def f(v):
        return await hsts(_ctx({"strict-transport-security": v}))
    assert (await f("max-age=0"))[0].code == "disabled"
    assert (await f("includeSubDomains"))[0].code == "disabled"      # pas de max-age
    out = await f("max-age=63072000")
    assert out[0].code == "ok"


async def test_referrer_weak_value():
    async def f(v):
        return (await referrer(_ctx({"referrer-policy": v})))[0]
    assert (await f("unsafe-url")).code == "weak"
    assert (await f("no-referrer")).code == "ok"
    # un repli sûr en fin de liste suffit (le navigateur retient le dernier token compris).
    assert (await f("unsafe-url, strict-origin-when-cross-origin")).code == "ok"


async def test_coop_unsafe_none_is_weak():
    assert (await coop(_ctx({"cross-origin-opener-policy": "unsafe-none"})))[0].code == "weak"


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
