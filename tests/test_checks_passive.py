"""Checks passifs : en-têtes, cookies, contenu mixte, technos (réponses synthétiques)."""
from scanner.checks.cookies import cookies
from scanner.checks.headers import csp, disclosure, hsts, nosniff, xfo
from scanner.checks.mixed import mixed
from scanner.checks.tech import tech
from scanner.finding import Severity

HTML = "text/html"


# ---- headers ----

async def test_csp_absent(make_ctx, make_response):
    out = await csp(make_ctx(response=make_response(headers={})))
    assert out[0].check_id == "hdr-csp" and out[0].severity == Severity.MEDIUM


async def test_csp_unsafe_inline(make_ctx, make_response):
    resp = make_response(headers={"content-security-policy": "default-src 'self' 'unsafe-inline'"})
    out = await csp(make_ctx(response=resp))
    assert out[0].severity == Severity.LOW


async def test_csp_ok(make_ctx, make_response):
    resp = make_response(headers={"content-security-policy": "default-src 'self'"})
    out = await csp(make_ctx(response=resp))
    assert out[0].severity == Severity.PASS


async def test_hsts_absent(make_ctx, make_response):
    out = await hsts(make_ctx(response=make_response(headers={})))
    assert out[0].severity == Severity.MEDIUM


async def test_hsts_low_maxage(make_ctx, make_response):
    resp = make_response(headers={"strict-transport-security": "max-age=100"})
    out = await hsts(make_ctx(response=resp))
    by_id = {f.check_id: f.severity for f in out}
    assert by_id["hdr-hsts"] == Severity.PASS
    assert by_id["hdr-hsts-maxage"] == Severity.LOW


async def test_nosniff_ok(make_ctx, make_response):
    resp = make_response(headers={"x-content-type-options": "nosniff"})
    out = await nosniff(make_ctx(response=resp))
    assert out[0].severity == Severity.PASS


async def test_xfo_present(make_ctx, make_response):
    out = await xfo(make_ctx(response=make_response(headers={"x-frame-options": "DENY"})))
    assert out[0].severity == Severity.PASS


async def test_disclosure_leaks_version(make_ctx, make_response):
    out = await disclosure(make_ctx(response=make_response(headers={"server": "nginx/1.2.3"})))
    assert out[0].check_id == "hdr-disclosure" and out[0].severity == Severity.LOW


# ---- cookies ----

async def test_cookies_none(make_ctx, make_response):
    out = await cookies(make_ctx(response=make_response(headers={})))
    assert len(out) == 1 and out[0].check_id == "cookies" and out[0].severity == Severity.PASS


async def test_cookies_insecure(make_ctx, make_response):
    resp = make_response(headers=[("set-cookie", "sid=abc")])
    out = await cookies(make_ctx(response=resp, url="https://x/"))
    ids = {f.check_id for f in out}
    assert {"cookie-secure", "cookie-httponly", "cookie-samesite"} <= ids


async def test_cookies_well_configured(make_ctx, make_response):
    resp = make_response(headers=[("set-cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")])
    out = await cookies(make_ctx(response=resp, url="https://x/"))
    assert len(out) == 1 and out[0].check_id == "cookie-ok" and out[0].severity == Severity.PASS


# ---- mixed content ----

async def test_mixed_non_https_pass(make_ctx, make_response):
    # Page non-HTTPS → contenu mixte N/A : non-événement (PASS), pas un INFO bruyant.
    resp = make_response(headers={"content-type": HTML}, text="<img src='http://a/x'>")
    out = await mixed(make_ctx(response=resp, url="http://x/"))
    assert out[0].severity == Severity.PASS and out[0].code == "not-evaluated"


async def test_mixed_active_two_scripts_high(make_ctx, make_response):
    html = '<script src="http://a/x.js"></script><script src="http://b/y.js"></script>'
    resp = make_response(headers={"content-type": HTML}, text=html)
    out = await mixed(make_ctx(response=resp, url="https://x/"))
    active = [f for f in out if f.check_id == "mixed-active"]
    assert active and active[0].severity == Severity.HIGH


async def test_mixed_passive_low(make_ctx, make_response):
    resp = make_response(headers={"content-type": HTML}, text='<img src="http://a/i.png">')
    out = await mixed(make_ctx(response=resp, url="https://x/"))
    passive = [f for f in out if f.check_id == "mixed-passive"]
    assert passive and passive[0].severity == Severity.LOW


async def test_mixed_clean_pass(make_ctx, make_response):
    resp = make_response(headers={"content-type": HTML}, text='<img src="https://a/i.png">')
    out = await mixed(make_ctx(response=resp, url="https://x/"))
    assert out[0].check_id == "mixed" and out[0].severity == Severity.PASS


# ---- tech ----

async def test_tech_detection(make_ctx, make_response):
    resp = make_response(
        headers=[("server", "nginx"), ("set-cookie", "PHPSESSID=xyz; path=/")],
        text='<html><head><meta name="generator" content="WordPress 6.5"></head></html>',
    )
    out = await tech(make_ctx(response=resp))
    # Détection structurée : le nom de techno vit dans params, plus dans le title.
    names = {f.params.get("name") for f in out if f.code == "detected"}
    assert "PHP" in names and "WordPress" in names
    assert any(f.code == "version" and f.severity == Severity.LOW
               and f.params.get("name") == "WordPress" and f.params.get("version") == "6.5"
               for f in out)
    assert all(f.category.value == "tech" for f in out)


async def test_tech_nothing(make_ctx, make_response):
    out = await tech(make_ctx(response=make_response(headers={})))
    assert len(out) == 1 and out[0].severity == Severity.PASS
