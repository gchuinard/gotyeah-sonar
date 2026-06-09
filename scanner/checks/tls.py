"""Couche TLS / certificat — handshake direct vers la cible (Phase 1).

Détection pure : chaque check ne renvoie qu'un `code` (+ `params`/`evidence`). Le
texte humain (titre, détail, recommandation, remédiation) vit dans
`content/checks/tls.fr.yaml` et est rendu par `scanner.i18n`.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
from urllib.parse import urlparse

from ..finding import Category, Finding, Severity
from ..registry import check

# Import optionnel : sert UNIQUEMENT au check `tls-key` (analyse clé/signature du certificat).
# Absent (dev sans la lib), le check se désactive proprement plutôt que de planter.
try:
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives.asymmetric import dsa as _dsa, ec as _ec, rsa as _rsa
except Exception:  # pragma: no cover
    _x509 = _rsa = _dsa = _ec = None

C = Category.TLS

# Timeout court sur le socket : on ne veut pas pendre le scan sur un port filtré.
_TIMEOUT = 8.0

# Versions négociées considérées comme obsolètes (< TLS 1.2).
_OBSOLETE_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _connect(host: str, port: int, verify: bool) -> tuple[str | None, dict]:
    """Ouvre une connexion TLS et renvoie (version_négociée, certificat).

    Code BLOQUANT — à exécuter via asyncio.to_thread. Avec verify=True on
    valide la chaîne et le hostname ; avec verify=False on lit juste le cert
    pour diagnostiquer (on n'accorde jamais confiance à ce qu'on lit ainsi).
    """
    if verify:
        ssl_ctx = ssl.create_default_context()
    else:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
        with ssl_ctx.wrap_socket(raw, server_hostname=host) as ssock:
            return ssock.version(), (ssock.getpeercert() or {})


def _fmt_name(rdn_seq) -> str:
    """Aplati un subject/issuer (séquence de RDN) en chaîne lisible."""
    parts = []
    try:
        for rdn in rdn_seq:
            for key, value in rdn:
                parts.append(f"{key}={value}")
    except (TypeError, ValueError):
        return ""
    return ", ".join(parts)


def _version_findings(version: str | None) -> list[Finding]:
    """Détection pure de la version TLS négociée → Finding structuré (code/params)."""
    if not version:
        return []
    if version in _OBSOLETE_VERSIONS:
        return [Finding("tls-version", C, Severity.HIGH,
            code="obsolete", params={"version": version}, evidence=version)]
    return [Finding("tls-version", C, Severity.PASS,
        code="ok", params={"version": version}, evidence=version)]


def _expiry_findings(cert: dict) -> list[Finding]:
    """Détection pure de la validité/expiration du certificat → Finding structurés."""
    findings: list[Finding] = []
    issuer = _fmt_name(cert.get("issuer"))
    subject = _fmt_name(cert.get("subject"))

    # notBefore : cert pas encore valide ?
    not_before = cert.get("notBefore")
    if not_before:
        try:
            starts = ssl.cert_time_to_seconds(not_before)
            if starts > time.time():
                findings.append(Finding("tls-cert-validity", C, Severity.CRITICAL,
                    code="not-yet-valid", params={"not_before": not_before},
                    evidence=subject or not_before))
        except (ValueError, TypeError):
            pass

    # notAfter : expiration.
    not_after = cert.get("notAfter")
    if not not_after:
        return findings
    try:
        expires = ssl.cert_time_to_seconds(not_after)
    except (ValueError, TypeError):
        findings.append(Finding("tls-cert-expiry", C, Severity.INFO,
            code="unparseable", params={"not_after": not_after},
            evidence=not_after))
        return findings

    remaining = expires - time.time()
    days = int(remaining // 86400)
    if remaining <= 0:
        findings.append(Finding("tls-cert-expiry", C, Severity.CRITICAL,
            code="expired",
            params={"not_after": not_after, "issuer": issuer or "inconnu"},
            evidence=not_after))
    elif days < 30:  # ~1 mois : fenêtre standard d'alerte de renouvellement (était 15 j, trop court)
        findings.append(Finding("tls-cert-expiry", C, Severity.MEDIUM,
            code="soon", params={"days": days, "not_after": not_after},
            evidence=not_after))
    else:
        findings.append(Finding("tls-cert-expiry", C, Severity.PASS,
            code="ok", params={"days": days, "not_after": not_after},
            evidence=not_after))
    return findings


@check("tls", "TLS / Certificat", Category.TLS)
async def tls(ctx):
    parsed = urlparse(ctx.url)

    # Pas de HTTPS du tout : inutile de tenter un handshake.
    if parsed.scheme != "https":
        return [Finding("tls", C, Severity.HIGH,
            code="http", params={"url": ctx.url})]

    host = ctx.host
    port = parsed.port or 443

    try:
        # 1. Handshake VÉRIFIANT (chaîne + hostname).
        try:
            version, cert = await asyncio.to_thread(_connect, host, port, True)
        except ssl.SSLCertVerificationError as exc:
            # 2. Échec de validation : on lit le cert SANS valider pour confirmer une éventuelle
            #    expiration. `getpeercert(binary_form=True)` FONCTIONNE sous CERT_NONE (la forme
            #    dict, elle, renvoie {} → l'ancienne confirmation par _expiry_findings(dict) était
            #    du CODE MORT). On n'émet PAS de finding « version OK » ici : afficher un point
            #    vert (version moderne) à côté d'un certificat refusé induit en erreur.
            findings: list[Finding] = [Finding("tls", C, Severity.HIGH,
                code="verify-failed",
                params={"error": str(exc.reason or exc)},
                evidence=str(exc.verify_message or exc.reason or exc))]
            der = await asyncio.to_thread(_peer_cert_der, host, port)
            if der:
                findings.extend(_expiry_from_der(der))
            return findings

        # Handshake vérifié OK : on produit les checks détaillés.
        findings = _version_findings(version)
        findings.extend(_expiry_findings(cert))
        return findings

    except (socket.timeout, ssl.SSLError, OSError) as exc:
        # 3. Connexion impossible (timeout, port fermé, pas de TLS…).
        return [Finding("tls", C, Severity.INFO,
            code="unreachable",
            params={"host": host, "port": port, "error_type": type(exc).__name__},
            evidence=str(exc))]
    except Exception as exc:  # filet de sécurité : aucune exception ne remonte.
        return [Finding("tls", C, Severity.INFO,
            code="error", params={"error_type": type(exc).__name__},
            evidence=str(exc))]


def _handshake(host: str, port: int, vmin, vmax) -> bool:
    """True si un handshake bornant le protocole entre `vmin` et `vmax` aboutit.

    Code BLOQUANT (→ asyncio.to_thread). On force `@SECLEVEL=0` pour autoriser les
    vieilles suites côté client, sinon un OpenSSL durci refuserait TLS 1.0/1.1
    lui-même et masquerait ce que le serveur accepte vraiment. Seam mockable.
    """
    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    try:
        sslctx.minimum_version = vmin
        sslctx.maximum_version = vmax
    except (ValueError, OSError):
        return False
    try:
        sslctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
            with sslctx.wrap_socket(raw, server_hostname=host):
                return True
    except Exception:
        return False


@check("tls-protocols", "Protocoles TLS obsolètes acceptés", Category.TLS)
async def tls_protocols(ctx):
    """Le serveur ACCEPTE-t-il encore TLS 1.0 / 1.1 (même s'il négocie ≥1.2 par défaut) ?

    On force des handshakes mono-protocole. Garde-fou anti-faux-positif : un handshake
    moderne (1.2/1.3) doit d'abord réussir, sinon on conclut « non vérifiable » plutôt
    que de prétendre que tout va bien.
    """
    parsed = urlparse(ctx.url)
    if parsed.scheme != "https":
        return []
    host = ctx.host
    port = parsed.port or 443

    modern = await asyncio.to_thread(_handshake, host, port,
                                     ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)
    if not modern:
        return [Finding("tls-protocols", C, Severity.INFO, code="unverifiable",
                        params={"host": host, "port": port})]

    obsolete: list[str] = []
    if await asyncio.to_thread(_handshake, host, port, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1):
        obsolete.append("TLS 1.0")
    if await asyncio.to_thread(_handshake, host, port, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1):
        obsolete.append("TLS 1.1")

    if obsolete:
        joined = ", ".join(obsolete)
        return [Finding("tls-protocols", C, Severity.MEDIUM, code="obsolete-accepted",
                        params={"protocols": joined}, evidence=joined)]
    return [Finding("tls-protocols", C, Severity.PASS, code="ok")]


def _peer_cert_der(host: str, port: int) -> bytes | None:
    """DER du certificat présenté, LU SANS validation (CERT_NONE) : on veut l'analyser même
    s'il est auto-signé/expiré. `getpeercert(binary_form=True)` fonctionne sous CERT_NONE
    (contrairement à la forme dict). Code BLOQUANT → asyncio.to_thread. Seam mockable."""
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
            with sslctx.wrap_socket(raw, server_hostname=host) as ssock:
                return ssock.getpeercert(binary_form=True)
    except Exception:
        return None


def _expiry_from_der(der: bytes) -> list[Finding]:
    """Confirme une éventuelle expiration depuis le DER du certificat. `binary_form=True`
    fonctionne sous CERT_NONE (lecture d'un cert non vérifié), contrairement à la forme dict de
    `getpeercert()` qui renvoie `{}` — d'où l'ancien code mort. Réutilise `_expiry_findings` via
    une forme dict reconstruite."""
    if _x509 is None:
        return []
    try:
        cert = _x509.load_der_x509_certificate(der)
    except Exception:
        return []
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

    def _fmt(dt):
        return dt.strftime("%b %d %H:%M:%S %Y GMT")

    return _expiry_findings({
        "notBefore": _fmt(nb),
        "notAfter": _fmt(na),
        "issuer": ((("organizationName", cert.issuer.rfc4514_string()),),),
        "subject": ((("commonName", cert.subject.rfc4514_string()),),),
    })


def _cert_strength_findings(der: bytes) -> list[Finding]:
    """Analyse la force du certificat : taille de la clé publique et algo de SIGNATURE.

    Détection pure (lib `cryptography`) : une clé RSA/DSA < 2048 bits (ou EC < 256) et une
    signature en SHA-1/MD5 (sujettes aux collisions, bannies des navigateurs) sont signalées."""
    if _x509 is None:
        return [Finding("tls-key", C, Severity.INFO, code="unavailable")]
    try:
        cert = _x509.load_der_x509_certificate(der)
    except Exception:
        return [Finding("tls-key", C, Severity.INFO, code="unparseable")]
    return _strength_from_cert(cert)


# Hachages de signature cassés (collisions) → rejetés par les navigateurs.
_WEAK_SIG_HASHES = {"md5", "sha1"}


def _strength_from_cert(cert) -> list[Finding]:
    """Analyse un objet certificat (cryptography) → findings clé/signature. Séparé de
    `_cert_strength_findings` pour être testable sans générer un vrai cert (impossible de
    signer en SHA-1 sous OpenSSL 3.0)."""
    findings: list[Finding] = []
    pub = cert.public_key()
    if isinstance(pub, _rsa.RSAPublicKey) and pub.key_size < 2048:
        findings.append(Finding("tls-key", C, Severity.HIGH, code="weak-key",
            params={"type": "RSA", "bits": pub.key_size}, evidence=f"RSA-{pub.key_size}"))
    elif isinstance(pub, _dsa.DSAPublicKey) and pub.key_size < 2048:
        findings.append(Finding("tls-key", C, Severity.HIGH, code="weak-key",
            params={"type": "DSA", "bits": pub.key_size}, evidence=f"DSA-{pub.key_size}"))
    elif isinstance(pub, _ec.EllipticCurvePublicKey) and pub.curve.key_size < 256:
        findings.append(Finding("tls-key", C, Severity.HIGH, code="weak-key",
            params={"type": "EC", "bits": pub.curve.key_size}, evidence=f"EC-{pub.curve.key_size}"))

    try:
        algo = cert.signature_hash_algorithm
    except Exception:
        algo = None
    name = (getattr(algo, "name", "") or "").lower()
    if name in _WEAK_SIG_HASHES:
        findings.append(Finding("tls-key", C, Severity.MEDIUM, code="weak-sig",
            params={"algo": name}, evidence=name))

    if not findings:
        findings.append(Finding("tls-key", C, Severity.PASS, code="ok"))
    return findings


@check("tls-key", "Robustesse du certificat (clé / signature)", Category.TLS)
async def tls_key(ctx):
    """Force cryptographique du certificat : taille de clé et algo de signature."""
    parsed = urlparse(ctx.url)
    if parsed.scheme != "https":
        return []
    port = parsed.port or 443
    der = await asyncio.to_thread(_peer_cert_der, ctx.host, port)
    if not der:
        return [Finding("tls-key", C, Severity.INFO, code="unreachable",
                        params={"host": ctx.host, "port": port})]
    return _cert_strength_findings(der)
