"""Oracle de justesse (E11) — contrat de sécurité « entrée vulnérable → verdict », INDÉPENDANT
du golden.

Le golden verrouille l'INVARIANCE du texte rendu ; il n'attrape pas une détection devenue plus
permissive. Cet oracle verrouille la CORRECTION : si un changement re-bénissait une config
dangereuse (CSP grande ouverte « ok », HSTS désactivé « ok », SPF `+all` « present »…), ou si la
note cessait de refléter un problème grave, un test ici casse.
"""
from types import SimpleNamespace

import httpx
import pytest

import scanner.checks.dns as dnsmod
from scanner.checks.dns import dns_check
from scanner.checks.exposed import exposed
from scanner.checks.headers import coop, csp, hsts, referrer, xfo
from scanner.finding import Category, Finding, Severity, summarize


def _hctx(headers):
    resp = httpx.Response(200, headers=headers, content=b"", request=httpx.Request("GET", "https://x/"))
    return SimpleNamespace(response=resp, url="https://x/", host="x")


# --------------------------------------------------------------------------- #
# 1. Contrat de DÉTECTION : une protection présente mais INOPÉRANTE n'est jamais « ok »/PASS.
# --------------------------------------------------------------------------- #
_NEVER_BLESS = [
    ("CSP grande ouverte", csp, {"content-security-policy": "default-src *"}),
    ("CSP sans restriction de script", csp, {"content-security-policy": "upgrade-insecure-requests"}),
    ("HSTS désactivé (max-age=0)", hsts, {"strict-transport-security": "max-age=0"}),
    ("clickjacking ALLOWALL", xfo, {"x-frame-options": "ALLOWALL"}),
    ("clickjacking frame-ancestors *", xfo, {"content-security-policy": "frame-ancestors *"}),
    ("Referrer no-op", referrer, {"referrer-policy": "unsafe-url"}),
    ("COOP no-op", coop, {"cross-origin-opener-policy": "unsafe-none"}),
]


@pytest.mark.parametrize("label,check,headers", _NEVER_BLESS, ids=[c[0] for c in _NEVER_BLESS])
async def test_permissive_config_is_never_pass(label, check, headers):
    findings = await check(_hctx(headers))
    assert findings, label
    f = findings[0]
    assert f.severity != Severity.PASS and f.code not in ("ok",), \
        f"{label} : le scanner ne doit pas bénir cette config ({f.code}/{f.severity})"


async def test_spf_plus_all_is_flagged(monkeypatch):
    import dns.resolver
    monkeypatch.setattr(dnsmod, "_resolve",
                        lambda name, rt: ['"v=spf1 +all"'] if rt == "TXT" else
                        (_ for _ in ()).throw(dns.resolver.NoAnswer()))
    spf = next(f for f in await dns_check(SimpleNamespace(host="example.com")) if f.check_id == "dns-spf")
    assert spf.severity != Severity.PASS and spf.code == "weak"


async def test_exposed_no_false_positive_on_json_api():
    # Une API qui répond 200+JSON à TOUT ne doit déclencher AUCUN faux « fichier exposé ».
    json_200 = httpx.Response(200, headers={"content-type": "application/json"},
                              content=b'{"ok":true}', request=httpx.Request("GET", "https://x/"))

    class _AllJson:
        async def get(self, url, headers=None):
            return json_200
    out = await exposed(SimpleNamespace(url="https://x/", host="x", client=_AllJson()))
    assert len(out) == 1 and out[0].code == "clean" and out[0].severity == Severity.PASS


# --------------------------------------------------------------------------- #
# 2. Contrat de NOTATION : la note reflète le PIRE problème et ne ment pas (bout en bout).
# --------------------------------------------------------------------------- #
async def test_vulnerable_headers_site_is_not_graded_A():
    # CSP grande ouverte + HSTS désactivé + clickjacking permissif : aucune protection réelle.
    h = {"content-security-policy": "default-src *",
         "strict-transport-security": "max-age=0",
         "x-frame-options": "ALLOWALL"}
    ctx = _hctx(h)
    findings = []
    for chk in (csp, hsts, xfo):
        findings += await chk(ctx)
    grade = summarize(findings)["grade"]
    assert grade not in ("A+", "A"), f"note trop rassurante ({grade}) pour un site sans protection"


def test_single_critical_exposure_caps_grade():
    # Un seul fichier sensible CRITIQUE (ex. .env) ne peut pas valoir mieux qu'un « E ».
    findings = [Finding("exposed-env", Category.EXPOSURE, Severity.CRITICAL, code="found")]
    score, grade = summarize(findings)["score"], summarize(findings)["grade"]
    assert grade in ("E", "F"), f"un CRITICAL exposé ne doit pas donner {grade}"


def test_incomplete_coverage_blocks_top_grade():
    # Couverture incomplète (pentest non exécuté) → jamais A/A+, même si rien n'a pénalisé.
    findings = [Finding("nuclei", Category.PENTEST, Severity.INFO, code="timeout", unexecuted=True)]
    assert summarize(findings)["grade"] not in ("A+", "A")
