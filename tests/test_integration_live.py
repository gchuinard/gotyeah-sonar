"""Tests d'INTÉGRATION réels (réseau) — désactivés par défaut, lancés en CI nocturne avec
SONAR_INTEGRATION=1.

Ils valident, contre de vraies cibles (badssl.com), ce qu'aucun mock ne peut garantir : qu'un
certificat cassé ne fait PLUS avorter le scan (C1, Batch 0) et que la branche verify-failed
remonte réellement le problème en lisant le cert via binary_form (E11/Batch 7, plus de code mort).
"""
import os

import pytest

from scanner.checks.tls import tls, tls_key
from scanner.finding import Severity
from scanner.runner import _build_context

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("SONAR_INTEGRATION"),
                       reason="réseau : définis SONAR_INTEGRATION=1 (lancé en CI nocturne)"),
]


async def _tls_codes(url, check=tls):
    ctx = await _build_context(url)
    try:
        return {f.code for f in await check(ctx)}
    finally:
        await ctx.client.aclose()


async def test_expired_cert_does_not_abort_and_is_reported():
    # C1 : un cert EXPIRÉ ne doit plus faire échouer _build_context (sinon l'appel lèverait)…
    codes = await _tls_codes("https://expired.badssl.com/")
    # …et la branche verify-failed remonte le défaut + confirme l'expiration (via binary_form).
    assert "verify-failed" in codes
    assert "expired" in codes


async def test_self_signed_is_verify_failed():
    codes = await _tls_codes("https://self-signed.badssl.com/")
    assert "verify-failed" in codes


async def test_wrong_host_is_verify_failed():
    codes = await _tls_codes("https://wrong.host.badssl.com/")
    assert "verify-failed" in codes


async def test_no_version_pass_next_to_verify_failed():
    # On ne doit PAS afficher un « version OK » (point vert) à côté d'un certificat refusé.
    ctx = await _build_context("https://self-signed.badssl.com/")
    try:
        out = await tls(ctx)
    finally:
        await ctx.client.aclose()
    assert not any(f.check_id == "tls-version" and f.severity == Severity.PASS for f in out)


async def test_strong_cert_key_is_ok():
    codes = await _tls_codes("https://sha256.badssl.com/", check=tls_key)
    assert "ok" in codes
