"""Subdomain takeover : fingerprint + codes — seam _cname mocké, ctx.response synthétique."""
from types import SimpleNamespace

import httpx

import scanner.checks.takeover as tkmod
from scanner.checks.takeover import takeover
from scanner.finding import Severity


def _ctx(status=200, text="", host="blog.x.com"):
    resp = httpx.Response(status, headers={"content-type": "text/html"},
                          content=text.encode("utf-8"), request=httpx.Request("GET", "https://" + host))
    return SimpleNamespace(host=host, response=resp)


def _patch_cname(monkeypatch, value):
    async def f(host):
        return value
    monkeypatch.setattr(tkmod, "_cname", f)


async def test_no_cname(monkeypatch):
    _patch_cname(monkeypatch, None)
    out = await takeover(_ctx())
    assert out[0].code == "no-cname" and out[0].severity == Severity.PASS


async def test_vulnerable(monkeypatch):
    _patch_cname(monkeypatch, "myapp.github.io")
    out = await takeover(_ctx(404, "<html>There isn't a GitHub Pages site here.</html>"))
    assert out[0].code == "vulnerable" and out[0].severity == Severity.HIGH
    assert out[0].params["service"] == "GitHub Pages"


async def test_dangling(monkeypatch):
    _patch_cname(monkeypatch, "myapp.github.io")
    out = await takeover(_ctx(404, "<html>nothing here</html>"))
    assert out[0].code == "dangling" and out[0].severity == Severity.MEDIUM


async def test_ok_claimed(monkeypatch):
    _patch_cname(monkeypatch, "myapp.github.io")
    out = await takeover(_ctx(200, "<html>my live blog</html>"))
    assert out[0].code == "ok" and out[0].severity == Severity.PASS


async def test_ok_non_service_cname(monkeypatch):
    _patch_cname(monkeypatch, "internal.mycorp.example")
    out = await takeover(_ctx(200, "<html>hi</html>"))
    assert out[0].code == "ok"
