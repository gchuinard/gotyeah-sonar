"""Méthodes HTTP : TRACE (Allow + actif), méthodes d'écriture, ok — fake client .request."""
from types import SimpleNamespace

import httpx

from scanner.checks.methods import methods
from scanner.finding import Severity


def _resp(status=200, headers=None):
    return httpx.Response(status, headers=headers or {}, content=b"",
                          request=httpx.Request("OPTIONS", "https://x/"))


class Fake:
    def __init__(self, allow="", trace=None):
        self.allow = allow
        self.trace = trace

    async def request(self, method, url, **kw):
        if method == "OPTIONS":
            return _resp(200, {"allow": self.allow})
        if method == "TRACE":
            return self.trace if self.trace is not None else _resp(405)
        return _resp(200)


def _ctx(client):
    return SimpleNamespace(url="https://x/", client=client)


async def test_trace_from_allow():
    out = await methods(_ctx(Fake("GET, POST, TRACE")))
    trace = next(f for f in out if f.code == "trace-enabled")
    assert trace.severity == Severity.LOW


async def test_trace_active_echo():
    out = await methods(_ctx(Fake("GET", trace=_resp(200, {"content-type": "message/http"}))))
    assert any(f.code == "trace-enabled" for f in out)


async def test_dangerous_methods():
    out = await methods(_ctx(Fake("GET, POST, PUT, DELETE")))
    f = next(x for x in out if x.code == "dangerous-methods")
    assert "PUT" in f.params["methods"] and "DELETE" in f.params["methods"]


async def test_ok():
    out = await methods(_ctx(Fake("GET, POST, HEAD, OPTIONS")))
    assert len(out) == 1 and out[0].code == "ok" and out[0].severity == Severity.PASS
