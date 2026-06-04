"""Batterie de scénarios déterministes, hors-ligne, partagée capture ↔ régression.

Chaque scénario exécute un check réel sur une entrée synthétique et renvoie les
findings produits (sérialisés). Le **golden** (`golden_fr.json`) est capturé depuis
le code d'ORIGINE (texte FR en dur) ; après le refactor i18n, `test_regression_fr.py`
ré-exécute exactement ces scénarios, rend les findings structurés via `scanner.i18n`
et exige le **même texte FR** — garantie de non-régression.

Tout tourne sans réseau : les checks réseau (`tls`, `dns`) sont pilotés via leurs
*seams* internes (`_connect`, `_resolve`, `_version_findings`, `_expiry_findings`) —
ces noms doivent être préservés par le refactor pour que les scénarios restent valides.
"""
from __future__ import annotations

import asyncio
import ssl
import time
import types

import httpx


# --------------------------------------------------------------------------- #
# Fabriques synthétiques (réponses httpx, ctx, client factice) — autonomes.
# --------------------------------------------------------------------------- #
def mkresp(status=200, headers=None, text="", url="https://example.com/"):
    return httpx.Response(status, headers=headers, content=text.encode("utf-8"),
                          request=httpx.Request("GET", url))


def mkctx(response=None, url="https://example.com/", history=None, client=None, host="example.com"):
    if response is None:
        response = mkresp(url=url)
    return types.SimpleNamespace(url=url, requested_url=url, host=host,
                                 response=response, history=history or [], client=client)


class FakeClient:
    """get(url) → réponse selon le suffixe d'URL (sinon `default`, sinon 404)."""

    def __init__(self, routes=None, default=None):
        self.routes = routes or {}
        self.default = default

    async def get(self, url, headers=None):
        for frag, resp in self.routes.items():
            if str(url).endswith(frag):
                return resp
        return self.default if self.default is not None else mkresp(404, text="not found", url=url)


# --------------------------------------------------------------------------- #
# Scénarios. Chaque entrée : (sid, coroutine renvoyant list[Finding]).
# --------------------------------------------------------------------------- #
async def _collect():
    """Construit et exécute tous les scénarios → {sid: [finding.as_dict(), ...]}."""
    from scanner.checks import headers as H
    from scanner.checks import cookies as CK
    from scanner.checks import mixed as MX
    from scanner.checks import tech as TC
    from scanner.checks import cors as CR
    from scanner.checks import exposed as EX
    from scanner.checks import subresources as SR
    from scanner.checks import tls as TLS
    from scanner.checks import dns as DNS
    from scanner.checks import leaks as LK
    from scanner.checks import ports as PORTS
    from scanner.checks import takeover as TK
    from scanner.checks import nuclei as NU
    from scanner.checks import zap as ZP

    HTML = "text/html"
    out: dict[str, list] = {}

    async def run(sid, coro):
        findings = await coro
        out[sid] = [f.as_dict() for f in (findings or [])]

    # ---- HEADERS ----
    await run("hdr_csp_absent", H.csp(mkctx(response=mkresp(headers={}))))
    await run("hdr_csp_weak_inline", H.csp(mkctx(response=mkresp(
        headers={"content-security-policy": "default-src 'self' 'unsafe-inline'"}))))
    await run("hdr_csp_weak_both", H.csp(mkctx(response=mkresp(
        headers={"content-security-policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'"}))))
    await run("hdr_csp_ok", H.csp(mkctx(response=mkresp(
        headers={"content-security-policy": "default-src 'self'"}))))
    await run("hdr_hsts_absent", H.hsts(mkctx(response=mkresp(headers={}))))
    await run("hdr_hsts_ok", H.hsts(mkctx(response=mkresp(
        headers={"strict-transport-security": "max-age=63072000"}))))
    await run("hdr_hsts_low", H.hsts(mkctx(response=mkresp(
        headers={"strict-transport-security": "max-age=100"}))))
    await run("hdr_xfo_present", H.xfo(mkctx(response=mkresp(headers={"x-frame-options": "DENY"}))))
    await run("hdr_xfo_absent", H.xfo(mkctx(response=mkresp(headers={}))))
    await run("hdr_nosniff_ok", H.nosniff(mkctx(response=mkresp(
        headers={"x-content-type-options": "nosniff"}))))
    await run("hdr_nosniff_absent", H.nosniff(mkctx(response=mkresp(headers={}))))
    await run("hdr_referrer_present", H.referrer(mkctx(response=mkresp(
        headers={"referrer-policy": "no-referrer"}))))
    await run("hdr_referrer_absent", H.referrer(mkctx(response=mkresp(headers={}))))
    await run("hdr_permissions_present", H.permissions(mkctx(response=mkresp(
        headers={"permissions-policy": "geolocation=()"}))))
    await run("hdr_permissions_absent", H.permissions(mkctx(response=mkresp(headers={}))))
    await run("hdr_disclosure_leak", H.disclosure(mkctx(response=mkresp(
        headers={"server": "nginx/1.2.3", "x-powered-by": "PHP/8.1"}))))
    await run("hdr_disclosure_ok", H.disclosure(mkctx(response=mkresp(headers={"server": "nginx"}))))
    await run("hdr_coop_present", H.coop(mkctx(response=mkresp(headers={"cross-origin-opener-policy": "same-origin"}))))
    await run("hdr_coop_absent", H.coop(mkctx(response=mkresp(headers={}))))
    await run("hdr_coep_present", H.coep(mkctx(response=mkresp(headers={"cross-origin-embedder-policy": "require-corp"}))))
    await run("hdr_coep_absent", H.coep(mkctx(response=mkresp(headers={}))))
    await run("hdr_corp_present", H.corp(mkctx(response=mkresp(headers={"cross-origin-resource-policy": "same-origin"}))))
    await run("hdr_corp_absent", H.corp(mkctx(response=mkresp(headers={}))))
    await run("hdr_cache_na", H.cache(mkctx(response=mkresp(headers={}))))
    await run("hdr_cache_ok", H.cache(mkctx(response=mkresp(headers=[("set-cookie", "s=1"), ("cache-control", "no-store")]))))
    await run("hdr_cache_bad", H.cache(mkctx(response=mkresp(headers=[("set-cookie", "s=1")]))))

    # ---- COOKIES ----
    await run("ck_none", CK.cookies(mkctx(response=mkresp(headers={}))))
    await run("ck_insecure", CK.cookies(mkctx(
        response=mkresp(headers=[("set-cookie", "sid=abc")]), url="https://x/")))
    await run("ck_samesite_none_insecure", CK.cookies(mkctx(
        response=mkresp(headers=[("set-cookie", "sid=abc; HttpOnly; SameSite=None")]), url="https://x/")))
    await run("ck_ok", CK.cookies(mkctx(
        response=mkresp(headers=[("set-cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")]), url="https://x/")))

    # ---- MIXED ----
    await run("mx_not_https", MX.mixed(mkctx(
        response=mkresp(headers={"content-type": HTML}, text="<img src='http://a/x'>"), url="http://x/")))
    await run("mx_not_html", MX.mixed(mkctx(
        response=mkresp(headers={"content-type": "application/json"}, text="{}"), url="https://x/")))
    await run("mx_active_2", MX.mixed(mkctx(response=mkresp(headers={"content-type": HTML},
        text='<script src="http://a/x.js"></script><script src="http://b/y.js"></script>'), url="https://x/")))
    await run("mx_active_1", MX.mixed(mkctx(response=mkresp(headers={"content-type": HTML},
        text='<script src="http://a/x.js"></script>'), url="https://x/")))
    await run("mx_passive", MX.mixed(mkctx(response=mkresp(headers={"content-type": HTML},
        text='<img src="http://a/i.png">'), url="https://x/")))
    await run("mx_clean", MX.mixed(mkctx(response=mkresp(headers={"content-type": HTML},
        text='<img src="https://a/i.png">'), url="https://x/")))

    # ---- TECH ----
    await run("tc_detect", TC.tech(mkctx(response=mkresp(
        headers=[("server", "nginx"), ("set-cookie", "PHPSESSID=xyz; path=/")],
        text='<html><head><meta name="generator" content="WordPress 6.5"></head></html>'))))
    await run("tc_none", TC.tech(mkctx(response=mkresp(headers={}))))

    # ---- CORS ----
    PROBE = CR.PROBE
    await run("cors_reflected_creds", CR.cors(mkctx(client=FakeClient(default=mkresp(headers={
        "access-control-allow-origin": PROBE, "access-control-allow-credentials": "true"})))))
    await run("cors_wildcard_creds", CR.cors(mkctx(client=FakeClient(default=mkresp(headers={
        "access-control-allow-origin": "*", "access-control-allow-credentials": "true"})))))
    await run("cors_reflected", CR.cors(mkctx(client=FakeClient(default=mkresp(headers={
        "access-control-allow-origin": PROBE})))))
    await run("cors_null", CR.cors(mkctx(client=FakeClient(default=mkresp(headers={
        "access-control-allow-origin": "null"})))))
    await run("cors_wildcard", CR.cors(mkctx(client=FakeClient(default=mkresp(headers={
        "access-control-allow-origin": "*"})))))
    await run("cors_absent", CR.cors(mkctx(client=FakeClient(default=mkresp(headers={})))))
    await run("cors_restricted", CR.cors(mkctx(client=FakeClient(default=mkresp(headers={
        "access-control-allow-origin": "https://trusted.example"})))))

    # ---- EXPOSED (les 14 chemins, chacun avec une signature valide) ----
    exposed_routes = {
        ".env": mkresp(200, {"content-type": "text/plain"}, "SECRET_KEY=abc\nDB_PASSWORD=xyz\n"),
        ".env.bak": mkresp(200, {"content-type": "text/plain"}, "SECRET_KEY=abc backup"),
        ".git/HEAD": mkresp(200, {"content-type": "text/plain"}, "ref: refs/heads/main"),
        ".git/config": mkresp(200, {"content-type": "text/plain"}, "[core]\n\trepositoryformatversion = 0"),
        ".svn/entries": mkresp(200, {"content-type": "text/plain"}, "12\n"),
        ".hg/requires": mkresp(200, {"content-type": "text/plain"}, "revlogv1\ndotencode\nstore\n"),
        "docker-compose.yml": mkresp(200, {"content-type": "text/plain"}, "services:\n  web:\n    image: x"),
        "Dockerfile": mkresp(200, {"content-type": "text/plain"}, "FROM python:3.12-slim\n"),
        "backup.zip": mkresp(200, {"content-type": "application/zip"}, "PK\x03\x04 binary backup"),
        "backup.sql": mkresp(200, {"content-type": "text/plain"}, "INSERT INTO users VALUES (1)"),
        "database.sql": mkresp(200, {"content-type": "text/plain"}, "CREATE TABLE t (id int)"),
        "config.php.bak": mkresp(200, {"content-type": "text/plain"}, "<?php $db='secret'; ?>"),
        ".DS_Store": mkresp(200, {"content-type": "application/octet-stream"}, "\x00\x00\x00\x01Bud1 stuff"),
        "phpinfo.php": mkresp(200, {"content-type": "text/html"}, "<title>phpinfo()</title>"),
    }
    await run("exposed_all", EX.exposed(mkctx(client=FakeClient(routes=exposed_routes), url="https://x/")))
    await run("exposed_clean", EX.exposed(mkctx(client=FakeClient(), url="https://x/")))

    # ---- SUBRESOURCES ----
    page_js = mkresp(headers={"content-type": HTML}, text='<script src="/app.js"></script>')
    asset_no = mkresp(200, headers={"content-type": "application/javascript"})
    await run("sr_missing", SR.subresources(mkctx(response=page_js, url="https://example.com/",
        host="example.com", client=FakeClient(routes={"/app.js": asset_no}))))
    page_css = mkresp(headers={"content-type": HTML}, text='<link rel="stylesheet" href="/s.css">')
    asset_ok = mkresp(200, headers={"content-type": "text/css", "x-content-type-options": "nosniff"})
    await run("sr_protected", SR.subresources(mkctx(response=page_css, url="https://example.com/",
        host="example.com", client=FakeClient(routes={"/s.css": asset_ok}))))
    page_x = mkresp(headers={"content-type": HTML}, text='<script src="https://cdn.autre.com/x.js"></script>')
    await run("sr_none", SR.subresources(mkctx(response=page_x, url="https://example.com/",
        host="example.com", client=FakeClient())))
    await run("sr_non_html", SR.subresources(mkctx(
        response=mkresp(headers={"content-type": "application/json"}, text="{}"), client=FakeClient())))
    page_unreach = mkresp(headers={"content-type": HTML}, text='<script src="/down.js"></script>')

    class _Boom:
        async def get(self, url, headers=None):
            raise httpx.ConnectError("boom")
    await run("sr_unreachable", SR.subresources(mkctx(response=page_unreach,
        url="https://example.com/", host="example.com", client=_Boom())))

    # ---- TLS (seams internes) ----
    await run("tls_http", TLS.tls(mkctx(url="http://x/", host="x")))
    out["tls_version_obsolete"] = [f.as_dict() for f in TLS._version_findings("TLSv1")]
    out["tls_version_ok"] = [f.as_dict() for f in TLS._version_findings("TLSv1.3")]
    now = time.time()

    def _cert(not_after=None, not_before=None, issuer="Let's Encrypt", subject="x"):
        c = {"issuer": ((("organizationName", issuer),),), "subject": ((("commonName", subject),),)}
        if not_after:
            c["notAfter"] = not_after
        if not_before:
            c["notBefore"] = not_before
        return c

    def _gmt(ts):
        return time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(ts))

    out["tls_cert_expired"] = [f.as_dict() for f in TLS._expiry_findings(_cert(not_after=_gmt(now - 86400)))]
    out["tls_cert_soon"] = [f.as_dict() for f in TLS._expiry_findings(_cert(not_after=_gmt(now + 5 * 86400)))]
    out["tls_cert_ok"] = [f.as_dict() for f in TLS._expiry_findings(_cert(not_after=_gmt(now + 200 * 86400)))]
    out["tls_cert_not_yet"] = [f.as_dict() for f in TLS._expiry_findings(
        _cert(not_after=_gmt(now + 200 * 86400), not_before=_gmt(now + 86400)))]

    # verify-failed : _connect lève SSLCertVerificationError sous verify=True
    def _connect_verifyfail(host, port, verify):
        if verify:
            err = ssl.SSLCertVerificationError("certificate verify failed")
            err.reason = "CERTIFICATE_VERIFY_FAILED"
            err.verify_message = "self signed certificate"
            raise err
        return "TLSv1.3", _cert(not_after=_gmt(now + 200 * 86400))
    _orig = TLS._connect
    TLS._connect = _connect_verifyfail
    try:
        await run("tls_verify_failed", TLS.tls(mkctx(url="https://x/", host="x")))
    finally:
        TLS._connect = _orig

    def _connect_unreachable(host, port, verify):
        raise OSError("connection refused")
    TLS._connect = _connect_unreachable
    try:
        await run("tls_unreachable", TLS.tls(mkctx(url="https://x/", host="x")))
    finally:
        TLS._connect = _orig

    # ---- DNS (seam interne _resolve) ----
    import dns.resolver

    def _dns_resolver(mapping):
        def f(name, rdtype):
            key = (name, rdtype)
            if key in mapping:
                val = mapping[key]
                if isinstance(val, Exception):
                    raise val
                return val
            raise dns.resolver.NoAnswer
        return f

    _orig_resolve = DNS._resolve
    cases = {
        "dns_all_present": {
            ("example.com", "TXT"): ['"v=spf1 include:_spf.example.com -all"'],
            ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:d@example.com"'],
            ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
        },
        "dns_all_absent": {},
        "dns_dmarc_none": {
            ("example.com", "TXT"): ['"v=spf1 -all"'],
            ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none"'],
            ("example.com", "CAA"): dns.resolver.NoAnswer(),
        },
        "dns_dmarc_nopolicy": {
            ("example.com", "TXT"): ['"v=spf1 -all"'],
            ("_dmarc.example.com", "TXT"): ['"v=DMARC1; rua=mailto:d@example.com"'],
        },
    }
    for sid, mapping in cases.items():
        DNS._resolve = _dns_resolver(mapping)
        try:
            await run(sid, DNS.dns_check(mkctx(host="example.com")))
        finally:
            DNS._resolve = _orig_resolve

    # ---- NUCLEI / ZAP : codes d'état maison (les résultats dynamiques sont EN, hors golden FR) ----
    import os

    def _with_env(**env):
        saved = {k: os.environ.get(k) for k in env}

        def restore():
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return restore

    r = _with_env(SONAR_NUCLEI="off")
    try:
        await run("nuclei_off", NU.nuclei(types.SimpleNamespace(url="https://x/")))
    finally:
        r()
    r = _with_env(SONAR_NUCLEI=None, NUCLEI_BIN="nuclei-absent-zzz")
    try:
        await run("nuclei_absent", NU.nuclei(types.SimpleNamespace(url="https://x/")))
    finally:
        r()
    r = _with_env(SONAR_ZAP="off", ZAP_API_URL="http://zap:8090")
    try:
        await run("zap_off", ZP.zap(types.SimpleNamespace(url="https://x/")))
    finally:
        r()
    r = _with_env(SONAR_ZAP=None, ZAP_API_URL=None)
    try:
        await run("zap_not_configured", ZP.zap(types.SimpleNamespace(url="https://x/")))
    finally:
        r()

    # ---- PORTS (seams _resolve_ips / _probe_port ; IP CDN vs non-CDN) ----
    _orig_resolve, _orig_probe = PORTS._resolve_ips, PORTS._probe_port

    def fake_resolve(ips):
        async def f(host):
            return ips
        return f

    def fake_probe(open_ports):
        async def f(ip, port, timeout):
            return (port in open_ports, "")
        return f

    def _ports_ctx():
        return types.SimpleNamespace(host="x.com")

    r = _with_env(SONAR_PORTS="off")
    try:
        await run("ports_off", PORTS.ports(_ports_ctx()))
    finally:
        r()

    for sid, ips, probe, env in [
        ("ports_unresolved", [], None, {}),
        ("ports_behind_cdn", ["104.16.0.1"], None, {}),                       # plage Cloudflare
        ("ports_exposed", ["203.0.113.10"], fake_probe({6379}), {}),          # TEST-NET-3, Redis ouvert
        ("ports_clean", ["203.0.113.10"], fake_probe(set()), {}),
    ]:
        rr = _with_env(SONAR_PORTS=None, SONAR_ORIGIN_IP=None, **env)
        PORTS._resolve_ips = fake_resolve(ips)
        if probe is not None:
            PORTS._probe_port = probe
        try:
            await run(sid, PORTS.ports(_ports_ctx()))
        finally:
            PORTS._resolve_ips, PORTS._probe_port = _orig_resolve, _orig_probe
            rr()

    # ---- TAKEOVER (seam _cname ; signature lue dans ctx.response) ----
    _orig_cname = TK._cname

    def fake_cname(value):
        async def f(host):
            return value
        return f

    _GH_SIG = "There isn't a GitHub Pages site here."
    for sid, cn, status, body in [
        ("takeover_no_cname", None, 200, "ok"),
        ("takeover_vulnerable", "myapp.github.io", 404, "<html>" + _GH_SIG + "</html>"),
        ("takeover_dangling", "myapp.github.io", 404, "<html>generic not found</html>"),
        ("takeover_ok", "myapp.github.io", 200, "<html>live site</html>"),
    ]:
        TK._cname = fake_cname(cn)
        try:
            await run(sid, TK.takeover(mkctx(
                response=mkresp(status, {"content-type": "text/html"}, body), host="blog.x.com")))
        finally:
            TK._cname = _orig_cname

    # ---- TLS-PROTOCOLS (seam _handshake ; garde-fou « moderne d'abord ») ----
    _orig_hs = TLS._handshake

    def fake_hs(modern, old10, old11):
        def f(host, port, vmin, vmax):
            if vmin == ssl.TLSVersion.TLSv1_2:
                return modern
            if vmin == ssl.TLSVersion.TLSv1:
                return old10
            if vmin == ssl.TLSVersion.TLSv1_1:
                return old11
            return False
        return f

    for sid, m, o10, o11 in [
        ("tls_proto_obsolete", True, True, False),
        ("tls_proto_ok", True, False, False),
        ("tls_proto_unverifiable", False, False, False),
    ]:
        TLS._handshake = fake_hs(m, o10, o11)
        try:
            await run(sid, TLS.tls_protocols(mkctx(url="https://x/", host="x")))
        finally:
            TLS._handshake = _orig_hs

    # ---- LEAKS (fake client get + post) ----
    class _LeakFake:
        def __init__(self, routes, post_routes=None):
            self.routes = routes
            self.post_routes = post_routes or {}

        async def get(self, url, headers=None):
            for frag, resp in self.routes.items():
                if str(url).endswith(frag):
                    return resp
            return mkresp(404, text="nf", url=url)

        async def post(self, url, content=None, headers=None):
            for frag, resp in self.post_routes.items():
                if str(url).endswith(frag):
                    return resp
            return mkresp(404, text="nf", url=url)

    _map = '{"version":3,"sources":["a.ts"],"mappings":"AAAA"}'
    find_routes = {
        "/app.js.map": mkresp(200, {"content-type": "application/json"}, _map),
        "/app.js": mkresp(200, {"content-type": "application/javascript"},
                          "console.log(1)\n//# sourceMappingURL=app.js.map"),
        "openapi.json": mkresp(200, {"content-type": "application/json"}, '{"openapi":"3.0.0","paths":{}}'),
        "uploads/": mkresp(200, {"content-type": HTML}, "<title>Index of /uploads</title>"),
        ".well-known/security.txt": mkresp(200, {"content-type": "text/plain"}, "Contact: mailto:sec@x.com"),
    }
    gql_resp = mkresp(200, {"content-type": "application/json"},
                      '{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
    page_f = mkresp(200, {"content-type": HTML}, '<script src="/app.js"></script>', url="https://x/")
    await run("leaks_findings", LK.leaks(mkctx(response=page_f, url="https://x/", host="x",
                                               client=_LeakFake(find_routes, {"graphql": gql_resp}))))
    page_c = mkresp(200, {"content-type": HTML}, "<html>no scripts</html>", url="https://x/")
    await run("leaks_clean", LK.leaks(mkctx(response=page_c, url="https://x/", host="x",
                                            client=_LeakFake({}, {}))))

    return out


def run_all() -> dict:
    """Exécute tous les scénarios (sync wrapper) → {sid: [finding.as_dict(), ...]}."""
    return asyncio.run(_collect())


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # racine du dépôt
    data = run_all()
    dest = Path(__file__).resolve().parent / "golden_fr.json"
    dest.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    n = sum(len(v) for v in data.values())
    print(f"golden capturé : {len(data)} scénarios, {n} findings -> {dest}")
