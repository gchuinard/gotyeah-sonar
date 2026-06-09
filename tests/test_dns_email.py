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


# ---- Batch 3 : valeur SPF/DMARC + domaine d'organisation (eTLD+1) ----

def _spf_finding(out):
    return next(f for f in out if f.check_id == "dns-spf")


def _dmarc_finding(out):
    return next(f for f in out if f.check_id == "dns-dmarc")


async def test_spf_qualifier(monkeypatch):
    async def spf_code(record):
        _patch(monkeypatch, {("example.com", "TXT"): ['"%s"' % record]})
        return _spf_finding(await dnsmod.dns_check(_ctx()))
    # `+all` / `?all` : n'importe qui peut usurper → weak (MEDIUM), plus jamais « present ».
    f = await spf_code("v=spf1 +all")
    assert f.code == "weak" and f.severity == Severity.MEDIUM
    assert (await spf_code("v=spf1 include:x ?all")).code == "weak"
    # `-all` / `~all` restent acceptables → present.
    assert (await spf_code("v=spf1 -all")).code == "present"
    assert (await spf_code("v=spf1 ~all")).code == "present"


async def test_spf_multiple_records(monkeypatch):
    _patch(monkeypatch, {("example.com", "TXT"): ['"v=spf1 include:a -all"', '"v=spf1 -all"']})
    f = _spf_finding(await dnsmod.dns_check(_ctx()))
    assert f.code == "multiple" and f.severity == Severity.MEDIUM and f.params["count"] == 2


async def test_dmarc_pct_zero_and_sp_none(monkeypatch):
    async def dmarc_code(record):
        _patch(monkeypatch, {
            ("example.com", "TXT"): ['"v=spf1 -all"'],
            ("_dmarc.example.com", "TXT"): ['"%s"' % record],
        })
        return _dmarc_finding(await dnsmod.dns_check(_ctx()))
    # p=reject mais pct=0 : appliqué à 0 % → fausse application.
    f = await dmarc_code("v=DMARC1; p=reject; pct=0")
    assert f.code == "pct-zero" and f.severity == Severity.MEDIUM
    # p=reject mais sp=none : sous-domaines non protégés.
    assert (await dmarc_code("v=DMARC1; p=reject; sp=none")).code == "subdomain"
    # p=reject « plein » → enforced (inchangé).
    assert (await dmarc_code("v=DMARC1; p=reject; rua=mailto:d@x")).code == "enforced"


def test_org_domain_etld_plus_one():
    # Un sous-domaine remonte à l'apex (où vivent SPF/DMARC/CAA) → plus de faux « absent ».
    assert dnsmod._org_domain("blog.example.com") == "example.com"
    assert dnsmod._org_domain("api.service.example.com") == "example.com"
    assert dnsmod._org_domain("www.example.com") == "example.com"
    assert dnsmod._org_domain("example.com") == "example.com"
    # Suffixe public à deux niveaux : on garde 3 labels.
    assert dnsmod._org_domain("shop.example.co.uk") == "example.co.uk"
