"""Check redirection HTTP → HTTPS — seam client mocké, hors-ligne."""
from types import SimpleNamespace

import httpx

from scanner.checks.redirect import http_redirect
from scanner.finding import Severity


def _resp(status, location=None):
    headers = {"location": location} if location else {}
    return httpx.Response(status, headers=headers, request=httpx.Request("GET", "http://x/"))


class _Client:
    def __init__(self, resp=None, raise_exc=False):
        self.resp = resp
        self.raise_exc = raise_exc

    async def get(self, url, follow_redirects=True, **kw):
        if self.raise_exc:
            raise httpx.ConnectError("refused", request=httpx.Request("GET", url))
        return self.resp


def _ctx(client, host="x.com"):
    return SimpleNamespace(host=host, client=client)


async def test_redirect_ok_permanent_to_https():
    f = (await http_redirect(_ctx(_Client(_resp(301, "https://x.com/")))))[0]
    assert f.code == "ok" and f.severity == Severity.PASS


async def test_redirect_temporary_is_weak():
    f = (await http_redirect(_ctx(_Client(_resp(302, "https://x.com/")))))[0]
    assert f.code == "weak-redirect" and f.severity == Severity.LOW


async def test_no_https_redirect_serves_cleartext_or_http():
    # sert du contenu en clair (200, pas de redirection)
    f = (await http_redirect(_ctx(_Client(_resp(200)))))[0]
    assert f.code == "no-https-redirect" and f.severity == Severity.MEDIUM
    # redirige mais vers HTTP (pas d'upgrade)
    f2 = (await http_redirect(_ctx(_Client(_resp(301, "http://x.com/foo")))))[0]
    assert f2.code == "no-https-redirect"


async def test_no_cleartext_when_port_closed():
    f = (await http_redirect(_ctx(_Client(raise_exc=True))))[0]
    assert f.code == "no-cleartext" and f.severity == Severity.PASS


async def test_unknown_without_host():
    f = (await http_redirect(_ctx(_Client(_resp(200)), host="")))[0]
    assert f.code == "unknown"
