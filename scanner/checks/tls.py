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
