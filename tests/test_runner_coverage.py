"""Batch 0 — sémantique de couverture du moteur : un cert cassé ne perd plus la cible
(C1), et un check non exécuté plafonne la note au lieu de la gonfler (C3)."""
from __future__ import annotations

import httpx
import pytest

from scanner.finding import Category, Finding, Severity, summarize
from scanner.registry import Check
from scanner.runner import _fetch_root, _safe_run


# --------------------------------------------------------------------------- #
# C1 — _build_context ne doit jamais perdre la cible : fallback http si l'HTTPS
# échoue au transport (443 fermé / pas de TLS). Un cert invalide est géré en amont
# par verify=False (testé en intégration au Batch 7).
# --------------------------------------------------------------------------- #
class _HttpsDownClient:
    """https → erreur de transport ; http → 200 (cas d'un site HTTP-only)."""

    def __init__(self):
        self.calls: list[str] = []

    async def get(self, url):
        self.calls.append(url)
        if url.startswith("https://"):
            raise httpx.ConnectError("connection refused")
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"ok")


class _AllDownClient:
    async def get(self, url):
        raise httpx.ConnectError("down")


async def test_fetch_root_falls_back_to_http():
    client = _HttpsDownClient()
    resp = await _fetch_root(client, "https://x.test/")
    assert str(resp.url).startswith("http://")            # on a bien basculé sur http
    assert client.calls == ["https://x.test/", "http://x.test/"]


async def test_fetch_root_raises_when_everything_is_down():
    # Si http échoue aussi, on remonte l'erreur → le scan signalera « cible injoignable »
    # (vrai cas injoignable, pas un cert cassé).
    with pytest.raises(httpx.TransportError):
        await _fetch_root(_AllDownClient(), "https://x.test/")


# --------------------------------------------------------------------------- #
# C3 — « pas exécuté » ≠ « pass ».
# --------------------------------------------------------------------------- #
def _check(fn):
    return Check(id="nuclei", title="Pentest (nuclei)", category=Category.PENTEST, fn=fn)


async def test_absent_tool_caps_grade_via_runner():
    # nuclei renvoie 'not-installed' (binaire absent) : le runner le marque unexecuted →
    # score 100 (rien à pénaliser) MAIS la note plafonne à B, jamais A+.
    async def fake_nuclei(ctx):
        return [Finding("nuclei", Category.PENTEST, Severity.INFO, code="not-installed")]

    _c, findings = await _safe_run(_check(fake_nuclei), ctx=None)
    assert findings[0].unexecuted is True
    s = summarize(findings)
    assert s["score"] == 100 and s["grade"] == "B"
    assert s["incomplete"] is True and s["unexecuted"] == ["nuclei"]


async def test_disabled_tool_is_not_degraded():
    # Couper nuclei VOLONTAIREMENT (code 'off') n'est pas une couverture défaillante :
    # pas de marquage unexecuted, pas de plafond.
    async def fake_nuclei_off(ctx):
        return [Finding("nuclei", Category.PENTEST, Severity.INFO, code="off")]

    _c, findings = await _safe_run(_check(fake_nuclei_off), ctx=None)
    assert findings[0].unexecuted is False
    assert summarize(findings)["grade"] == "A+"


async def test_crash_is_marked_unexecuted_not_pass():
    async def boom(ctx):
        raise RuntimeError("kaboom")

    _c, findings = await _safe_run(
        Check(id="tls", title="TLS / Certificat", category=Category.TLS, fn=boom), ctx=None)
    assert findings[0].unexecuted is True
    assert findings[0].category == Category.TLS          # groupé sous la vraie catégorie
    assert summarize(findings)["grade"] == "B"           # un crash ne donne jamais A+
