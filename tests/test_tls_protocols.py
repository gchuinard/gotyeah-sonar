"""TLS en profondeur : énumération des protocoles obsolètes — seam _handshake mocké."""
import ssl
from types import SimpleNamespace

import scanner.checks.tls as tlsmod
from scanner.checks.tls import tls_protocols
from scanner.finding import Severity


def _ctx(url="https://x/", host="x"):
    return SimpleNamespace(url=url, host=host)


def _patch(monkeypatch, modern, old10, old11):
    def f(host, port, vmin, vmax):
        if vmin == ssl.TLSVersion.TLSv1_2:
            return modern
        if vmin == ssl.TLSVersion.TLSv1:
            return old10
        if vmin == ssl.TLSVersion.TLSv1_1:
            return old11
        return False
    monkeypatch.setattr(tlsmod, "_handshake", f)


async def test_non_https_skips():
    assert await tls_protocols(_ctx(url="http://x/")) == []


async def test_obsolete_accepted(monkeypatch):
    _patch(monkeypatch, True, True, True)
    out = await tls_protocols(_ctx())
    assert out[0].code == "obsolete-accepted" and out[0].severity == Severity.MEDIUM
    assert "TLS 1.0" in out[0].params["protocols"] and "TLS 1.1" in out[0].params["protocols"]


async def test_ok(monkeypatch):
    _patch(monkeypatch, True, False, False)
    out = await tls_protocols(_ctx())
    assert out[0].code == "ok" and out[0].severity == Severity.PASS


async def test_unverifiable_when_modern_fails(monkeypatch):
    # Garde-fou : si même un handshake moderne échoue, on ne conclut pas « ok ».
    _patch(monkeypatch, False, True, True)
    out = await tls_protocols(_ctx())
    assert out[0].code == "unverifiable" and out[0].severity == Severity.INFO
