"""Checks actifs : CORS et fichiers exposés, via un client httpx factice (hors-ligne)."""
from scanner.checks.cors import PROBE, cors
from scanner.checks.exposed import exposed
from scanner.finding import Severity


# ---- CORS ----

async def test_cors_reflected_with_credentials(make_ctx, make_response, fake_client_cls):
    resp = make_response(headers={
        "access-control-allow-origin": PROBE,
        "access-control-allow-credentials": "true",
    })
    out = await cors(make_ctx(client=fake_client_cls(default=resp)))
    assert out[0].check_id == "cors" and out[0].severity == Severity.HIGH


async def test_cors_wildcard_no_creds_low(make_ctx, make_response, fake_client_cls):
    resp = make_response(headers={"access-control-allow-origin": "*"})
    out = await cors(make_ctx(client=fake_client_cls(default=resp)))
    assert out[0].severity == Severity.LOW


async def test_cors_reflected_no_creds_medium(make_ctx, make_response, fake_client_cls):
    resp = make_response(headers={"access-control-allow-origin": PROBE})
    out = await cors(make_ctx(client=fake_client_cls(default=resp)))
    assert out[0].severity == Severity.MEDIUM


async def test_cors_absent_pass(make_ctx, make_response, fake_client_cls):
    resp = make_response(headers={})
    out = await cors(make_ctx(client=fake_client_cls(default=resp)))
    assert out[0].severity == Severity.PASS


# ---- fichiers exposés ----

async def test_exposed_env_critical(make_ctx, make_response, fake_client_cls):
    env = make_response(200, headers={"content-type": "text/plain"},
                        text="SECRET_KEY=abc\nDB_PASSWORD=xyz\n")
    client = fake_client_cls(routes={".env": env})  # tout le reste -> 404
    out = await exposed(make_ctx(client=client, url="https://x/"))
    hits = [f for f in out if f.check_id == "exposed-env"]
    assert hits and hits[0].severity == Severity.CRITICAL


async def test_exposed_soft404_ignored(make_ctx, make_response, fake_client_cls):
    # Site qui répond 200 + HTML à TOUT (y compris .env) : la signature ne matche pas.
    html = make_response(200, headers={"content-type": "text/html"},
                         text="<!doctype html><html><body>page</body></html>")
    out = await exposed(make_ctx(client=fake_client_cls(default=html), url="https://x/"))
    assert len(out) == 1 and out[0].check_id == "exposed" and out[0].severity == Severity.PASS


async def test_exposed_clean_pass(make_ctx, fake_client_cls):
    out = await exposed(make_ctx(client=fake_client_cls(), url="https://x/"))  # tout -> 404
    assert len(out) == 1 and out[0].check_id == "exposed" and out[0].severity == Severity.PASS
