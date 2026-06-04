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
    elif days < 15:
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
            # 2. Échec de validation : on reconnecte SANS vérifier, uniquement
            #    pour lire le cert et remonter le problème précis.
            findings: list[Finding] = [Finding("tls", C, Severity.HIGH,
                code="verify-failed",
                params={"error": str(exc.reason or exc)},
                evidence=str(exc.verify_message or exc.reason or exc))]
            try:
                version, cert = await asyncio.to_thread(_connect, host, port, False)
            except Exception:
                version, cert = None, {}
            # Le défaut de validation peut être une expiration : on tente de
            # confirmer en CRITICAL via le cert lu sans vérification.
            findings.extend(_version_findings(version))
            findings.extend(_expiry_findings(cert))
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
