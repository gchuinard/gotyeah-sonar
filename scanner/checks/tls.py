"""Couche TLS / certificat — handshake direct vers la cible (Phase 1)."""
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
    if not version:
        return []
    if version in _OBSOLETE_VERSIONS:
        return [Finding("tls-version", C, Severity.HIGH,
            "Version TLS obsolète négociée",
            f"Le serveur accepte `{version}`, un protocole déprécié et vulnérable "
            "(BEAST, POODLE…).",
            "Désactive tous les protocoles < TLS 1.2 et privilégie TLS 1.3.",
            evidence=version)]
    return [Finding("tls-version", C, Severity.PASS,
        "Version TLS correcte",
        f"La connexion négocie `{version}` (>= TLS 1.2).",
        evidence=version)]


def _expiry_findings(cert: dict) -> list[Finding]:
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
                    "Certificat pas encore valide",
                    f"Le certificat n'entre en vigueur que le `{not_before}` "
                    "(date `notBefore` dans le futur).",
                    "Vérifie l'horloge du serveur ou déploie le bon certificat.",
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
            "Date d'expiration du certificat illisible",
            f"Impossible de parser la date `notAfter` (`{not_after}`).",
            evidence=not_after))
        return findings

    remaining = expires - time.time()
    days = int(remaining // 86400)
    if remaining <= 0:
        findings.append(Finding("tls-cert-expiry", C, Severity.CRITICAL,
            "Certificat expiré",
            f"Le certificat a expiré le `{not_after}` (émis par {issuer or 'inconnu'}).",
            "Renouvelle le certificat immédiatement.",
            evidence=not_after))
    elif days < 15:
        findings.append(Finding("tls-cert-expiry", C, Severity.MEDIUM,
            "Certificat proche de l'expiration",
            f"Le certificat expire dans {days} jour(s) (le `{not_after}`).",
            "Renouvelle-le avant l'échéance ; vise un renouvellement automatique.",
            evidence=not_after))
    else:
        findings.append(Finding("tls-cert-expiry", C, Severity.PASS,
            "Certificat valide",
            f"Le certificat est valide encore {days} jour(s) (jusqu'au `{not_after}`).",
            evidence=not_after))
    return findings


@check("tls", "TLS / Certificat", Category.TLS)
async def tls(ctx):
    parsed = urlparse(ctx.url)

    # Pas de HTTPS du tout : inutile de tenter un handshake.
    if parsed.scheme != "https":
        return [Finding("tls", C, Severity.HIGH,
            "Connexion non chiffrée (HTTP)",
            f"L'URL finale est `{ctx.url}` : le trafic circule en clair, exposé à "
            "l'interception et à la modification.",
            "Sers le site exclusivement en HTTPS et redirige tout HTTP vers HTTPS.")]

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
                "Validation du certificat échouée",
                f"La chaîne ou le hostname n'a pas pu être validé : `{exc.reason or exc}`. "
                "Le navigateur affichera un avertissement de sécurité.",
                "Déploie un certificat de confiance valide pour ce hostname "
                "(chaîne complète, hostname correct, non expiré).",
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
            "TLS non vérifiable",
            f"Impossible d'établir une connexion TLS vers `{host}:{port}` : "
            f"{type(exc).__name__}.",
            "Vérifie que le port est ouvert et qu'un service TLS y répond.",
            evidence=str(exc))]
    except Exception as exc:  # filet de sécurité : aucune exception ne remonte.
        return [Finding("tls", C, Severity.INFO,
            "TLS non vérifiable",
            f"Erreur inattendue lors du test TLS : {type(exc).__name__}.",
            evidence=str(exc))]
