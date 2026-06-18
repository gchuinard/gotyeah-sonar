"""Checks actifs : CORS et fichiers exposés, via un client httpx factice (hors-ligne)."""
from scanner.checks.cors import PROBE, cors
from scanner.checks.exposed import exposed
from scanner.checks.subresources import subresources
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


async def test_exposed_backup_no_false_positive_on_json_api(make_ctx, make_response, fake_client_cls):
    # E4 : une API qui répond 200 + JSON à TOUT (y compris .env.bak, backup.zip…) ne doit
    # plus déclencher de faux HIGH « sauvegarde » — les signatures exigent un contenu réel.
    json_200 = make_response(200, headers={"content-type": "application/json"},
                             text='{"data": [], "ok": true}')
    out = await exposed(make_ctx(client=fake_client_cls(default=json_200), url="https://x/"))
    assert len(out) == 1 and out[0].check_id == "exposed" and out[0].severity == Severity.PASS


async def test_exposed_aws_credentials_critical(make_ctx, make_response, fake_client_cls):
    creds = make_response(200, headers={"content-type": "text/plain"},
                          text="[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = sk")
    client = fake_client_cls(routes={".aws/credentials": creds})
    out = await exposed(make_ctx(client=client, url="https://x/"))
    hits = [f for f in out if f.check_id == "exposed-aws"]
    assert hits and hits[0].severity == Severity.CRITICAL


async def test_exposed_probes_domain_root_after_redirect(make_ctx, make_response):
    # E5 : l'accueil redirige vers /en/ (ctx.url = sous-chemin) ; un .env est servi à la
    # RACINE du domaine. On doit le trouver — sonder la seule URL finale le ratait.
    env = make_response(200, headers={"content-type": "text/plain"}, text="SECRET=1\nDB_PASS=x\n")
    not_found = make_response(404, text="nf")

    class RootOnlyClient:
        """Sert le .env uniquement au chemin racine `/.env`, pas sous `/en/`."""
        def __init__(self):
            self.calls = []
        async def get(self, url, headers=None):
            self.calls.append(str(url))
            from urllib.parse import urlparse
            if urlparse(str(url)).path == "/.env":
                return env
            return not_found

    client = RootOnlyClient()
    out = await exposed(make_ctx(client=client, url="https://x/en/"))
    hits = [f for f in out if f.check_id == "exposed-env"]
    assert hits and hits[0].severity == Severity.CRITICAL
    # On a bien sondé /.env (racine) en plus de /en/.env (URL finale).
    assert any(p.endswith("/.env") and "/en/" not in p for p in client.calls)


# ---- en-têtes des sous-ressources ----

async def test_subresources_missing_nosniff(make_ctx, make_response, fake_client_cls):
    page = make_response(headers={"content-type": "text/html"}, text='<script src="/app.js"></script>')
    asset = make_response(200, headers={"content-type": "application/javascript"})  # pas de nosniff
    ctx = make_ctx(response=page, url="https://example.com/", host="example.com",
                   client=fake_client_cls(routes={"/app.js": asset}))
    out = await subresources(ctx)
    assert out[0].check_id == "subresources" and out[0].severity == Severity.LOW


async def test_subresources_with_nosniff_pass(make_ctx, make_response, fake_client_cls):
    page = make_response(headers={"content-type": "text/html"},
                         text='<link rel="stylesheet" href="/style.css">')
    asset = make_response(200, headers={"content-type": "text/css", "x-content-type-options": "nosniff"})
    ctx = make_ctx(response=page, url="https://example.com/", host="example.com",
                   client=fake_client_cls(routes={"/style.css": asset}))
    out = await subresources(ctx)
    assert out[0].severity == Severity.PASS


async def test_subresources_cross_origin_ignored(make_ctx, make_response, fake_client_cls):
    page = make_response(headers={"content-type": "text/html"},
                         text='<script src="https://cdn.autre.com/x.js"></script>')
    ctx = make_ctx(response=page, url="https://example.com/", host="example.com",
                   client=fake_client_cls())
    out = await subresources(ctx)
    # La ressource tierce est ignorée → branche « aucune sous-ressource même-origine ».
    assert out[0].severity == Severity.PASS and out[0].code == "pass-none"


async def test_subresources_non_html_pass(make_ctx, make_response, fake_client_cls):
    # Page non-HTML → aucune sous-ressource à analyser : non-événement (PASS), pas un INFO.
    page = make_response(headers={"content-type": "application/json"}, text="{}")
    out = await subresources(make_ctx(response=page, client=fake_client_cls()))
    assert out[0].severity == Severity.PASS and out[0].code == "non-html"
