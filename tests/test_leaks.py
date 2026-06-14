"""Fuites & well-known : sondes source map / swagger / graphql / autoindex / security.txt."""
from types import SimpleNamespace

import httpx

from scanner.checks.leaks import leaks

HTML = {"content-type": "text/html"}


def _resp(status=200, headers=None, text="", url="https://x/"):
    return httpx.Response(status, headers=headers or {}, content=text.encode(),
                          request=httpx.Request("GET", url))


class Fake:
    def __init__(self, routes, post_routes=None):
        self.routes = routes
        self.post_routes = post_routes or {}

    async def get(self, url, headers=None):
        for f, r in self.routes.items():
            if str(url).endswith(f):
                return r
        return _resp(404, url=url)

    async def post(self, url, content=None, headers=None):
        for f, r in self.post_routes.items():
            if str(url).endswith(f):
                return r
        return _resp(404, url=url)


def _ctx(page_html, client):
    return SimpleNamespace(url="https://x/", host="x",
                           response=_resp(200, HTML, page_html), client=client)


async def test_all_findings():
    routes = {
        "/app.js.map": _resp(200, {"content-type": "application/json"},
                             '{"version":3,"sources":["a"],"mappings":"A"}'),
        "/app.js": _resp(200, {"content-type": "application/javascript"},
                         "x\n//# sourceMappingURL=app.js.map"),
        "openapi.json": _resp(200, {"content-type": "application/json"}, '{"openapi":"3.0.0"}'),
        "uploads/": _resp(200, HTML, "<title>Index of /uploads</title>"),
        ".well-known/security.txt": _resp(200, {}, "Contact: mailto:a@b.com"),
    }
    post = {"graphql": _resp(200, {"content-type": "application/json"}, '{"data":{"__schema":{}}}')}
    out = await leaks(_ctx('<script src="/app.js"></script>', Fake(routes, post)))
    codes = {f.check_id: f.code for f in out}
    assert codes == {
        "leak-sourcemap": "exposed", "leak-swagger": "exposed",
        "leak-graphql": "introspection", "leak-autoindex": "listing",
        "leak-securitytxt": "present",
    }


async def test_root_probing_when_homepage_is_subpath():
    # Accueil redirigé vers /en/ : swagger + security.txt servis à la RACINE doivent être
    # trouvés (avant : sondés seulement sous /en/ → manqués). Les routes ne matchent que la
    # racine (URL complète), pas le sous-chemin.
    routes = {
        "https://x/openapi.json": _resp(200, {"content-type": "application/json"}, '{"openapi":"3.0.0"}'),
        "https://x/.well-known/security.txt": _resp(200, {}, "Contact: mailto:a@b.com"),
    }
    ctx = SimpleNamespace(url="https://x/en/", host="x",
                          response=_resp(200, HTML, "<html></html>"), client=Fake(routes, {}))
    out = await leaks(ctx)
    codes = {f.check_id: f.code for f in out}
    assert codes["leak-swagger"] == "exposed"
    assert codes["leak-securitytxt"] == "present"


async def test_all_clean():
    out = await leaks(_ctx("<html></html>", Fake({}, {})))
    codes = {f.check_id: f.code for f in out}
    assert codes == {
        "leak-sourcemap": "clean", "leak-swagger": "clean", "leak-graphql": "clean",
        "leak-autoindex": "clean", "leak-securitytxt": "missing",
    }
