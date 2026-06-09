"""TLS en profondeur : protocoles obsolètes, force clé/signature, seuil d'expiration."""
import datetime
import ssl
import time
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

import scanner.checks.tls as tlsmod
from scanner.checks.tls import _cert_strength_findings, _expiry_findings, tls_protocols
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


# ---- Batch 5 : force clé / signature du certificat ----

def _cert_der(key, hash_algo):
    nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (x509.CertificateBuilder()
            .subject_name(nm).issuer_name(nm).public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .sign(key, hash_algo))
    return cert.public_bytes(serialization.Encoding.DER)


def test_cert_strength_weak_key():
    # RSA-1024 → clé faible (HIGH). (On signe en SHA-256 : OpenSSL 3.0 refuse de signer SHA-1.)
    der = _cert_der(rsa.generate_private_key(public_exponent=65537, key_size=1024), hashes.SHA256())
    out = {f.code: f for f in _cert_strength_findings(der)}
    assert "weak-key" in out and out["weak-key"].severity == Severity.HIGH
    assert out["weak-key"].params["bits"] == 1024 and out["weak-key"].params["type"] == "RSA"


def test_cert_strength_weak_sig():
    # weak-sig testé sur un cert mocké (clé forte + signature SHA-1) : impossible de signer un
    # vrai cert en SHA-1 ici, mais le PARSING d'une signature SHA-1 reste à détecter.
    strong = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    fake_cert = SimpleNamespace(
        public_key=lambda: strong,
        signature_hash_algorithm=SimpleNamespace(name="sha1"))
    out = {f.code: f for f in tlsmod._strength_from_cert(fake_cert)}
    assert "weak-sig" in out and out["weak-sig"].severity == Severity.MEDIUM
    assert out["weak-sig"].params["algo"] == "sha1" and "weak-key" not in out


def test_cert_strength_strong_is_ok():
    der = _cert_der(rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256())
    out = [f.code for f in _cert_strength_findings(der)]
    assert out == ["ok"]


def test_cert_strength_ec_p256_ok():
    der = _cert_der(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
    assert [f.code for f in _cert_strength_findings(der)] == ["ok"]


def test_cert_strength_unparseable():
    assert _cert_strength_findings(b"not-a-cert")[0].code == "unparseable"


# ---- Batch 5 : seuil « bientôt expiré » relevé à 30 jours ----

def _cert_dict(days):
    ts = time.time() + days * 86400
    not_after = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(ts))
    return {"issuer": ((("organizationName", "X"),),), "subject": ((("commonName", "x"),),),
            "notAfter": not_after}


def test_expiry_threshold_30_days():
    # 20 j : « soon » avec le nouveau seuil (était « ok » sous l'ancien seuil de 15 j).
    out20 = {f.code for f in _expiry_findings(_cert_dict(20))}
    assert "soon" in out20
    # 45 j : encore « ok ».
    out45 = {f.code for f in _expiry_findings(_cert_dict(45))}
    assert "ok" in out45
