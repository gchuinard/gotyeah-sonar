"""DNS e-mail / PKI : DKIM, MTA-STS, TLS-RPT, DNSSEC — seam _resolve mocké, hors-ligne."""
from types import SimpleNamespace

import dns.resolver

import scanner.checks.dns as dnsmod
from scanner.finding import Severity


def _ctx(host="example.com"):
    return SimpleNamespace(host=host)


def _patch(monkeypatch, mapping):
    def f(name, rdtype):
        if (name, rdtype) in mapping:
            return mapping[(name, rdtype)]
        raise dns.resolver.NoAnswer
    monkeypatch.setattr(dnsmod, "_resolve", f)


async def test_dkim_present(monkeypatch):
    _patch(monkeypatch, {("google._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=ABC"']})
    out = await dnsmod.dkim(_ctx())
    assert out[0].code == "present" and out[0].params["selector"] == "google"


async def test_dkim_none(monkeypatch):
    _patch(monkeypatch, {})
    out = await dnsmod.dkim(_ctx())
    assert out[0].code == "none" and out[0].severity == Severity.INFO


async def test_mtasts(monkeypatch):
    _patch(monkeypatch, {("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=1"']})
    assert (await dnsmod.mtasts(_ctx()))[0].code == "present"
    _patch(monkeypatch, {})
    assert (await dnsmod.mtasts(_ctx()))[0].code == "none"


async def test_tlsrpt(monkeypatch):
    _patch(monkeypatch, {("_smtp._tls.example.com", "TXT"): ['"v=TLSRPTv1; rua=mailto:a@b"']})
    assert (await dnsmod.tlsrpt(_ctx()))[0].code == "present"


async def test_dnssec(monkeypatch):
    _patch(monkeypatch, {("example.com", "DNSKEY"): ["257 3 13 abc"]})
    assert (await dnsmod.dnssec(_ctx()))[0].code == "present"
    _patch(monkeypatch, {})
    out = await dnsmod.dnssec(_ctx())
    assert out[0].code == "absent" and out[0].severity == Severity.LOW
