"""Enregistrements DNS de sécurité e-mail / PKI — SPF, DMARC, CAA."""
from __future__ import annotations

import asyncio

import dns.exception
import dns.resolver

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.DNS

# Erreurs dnspython signifiant « pas d'enregistrement » (≠ panne réseau).
_NO_RECORD = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)
# Erreurs signifiant que la résolution elle-même a échoué.
_RESOLVE_FAILED = (dns.resolver.NoNameservers, dns.exception.Timeout)


def _org_domain(host: str) -> str:
    """Domaine d'organisation : retire un éventuel préfixe `www.`."""
    host = (host or "").strip().rstrip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _resolve(name: str, rdtype: str) -> list[str]:
    """Résolution bloquante → liste de valeurs texte. Lève les exceptions dnspython."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 8
    resolver.timeout = 8
    answers = resolver.resolve(name, rdtype)
    return [r.to_text() for r in answers]


def _join_txt(value: str) -> str:
    """Un enregistrement TXT peut être découpé en plusieurs chaînes guillemetées."""
    parts = value.split('" "')
    cleaned = "".join(parts)
    return cleaned.strip('"')


def _resolution_unavailable(label: str, exc: Exception) -> Finding:
    return Finding(
        "dns-resolve",
        C,
        Severity.INFO,
        "Résolution DNS indisponible",
        f"La résolution DNS pour {label} n'a pas pu aboutir "
        f"({type(exc).__name__}). Les enregistrements concernés n'ont pas pu être vérifiés.",
        "Réessaie plus tard ou vérifie la connectivité DNS de l'environnement de scan.",
    )


@check("dns", "DNS (SPF / DMARC / CAA)", Category.DNS)
async def dns_check(ctx):
    findings: list[Finding] = []
    domain = _org_domain(getattr(ctx, "host", "") or "")

    if not domain:
        return [Finding(
            "dns-resolve", C, Severity.INFO,
            "Résolution DNS indisponible",
            "Aucun hôte cible n'a pu être déterminé pour interroger le DNS.",
            "Fournis un hostname valide à scanner.")]

    # --- SPF -----------------------------------------------------------------
    try:
        txts = [_join_txt(v) for v in await asyncio.to_thread(_resolve, domain, "TXT")]
        spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
        if spf:
            findings.append(Finding(
                "dns-spf", C, Severity.PASS,
                "Enregistrement SPF présent",
                "Un enregistrement `v=spf1` déclare les serveurs autorisés à envoyer "
                "du courrier pour ce domaine.",
                evidence=spf[:300]))
        else:
            findings.append(Finding(
                "dns-spf", C, Severity.MEDIUM,
                "Enregistrement SPF absent",
                "Aucun enregistrement `v=spf1` : un tiers peut usurper l'adresse "
                "d'expéditeur du domaine.",
                "Publie un enregistrement TXT SPF, par ex. `v=spf1 include:_spf.exemple.com -all`."))
    except _NO_RECORD:
        findings.append(Finding(
            "dns-spf", C, Severity.MEDIUM,
            "Enregistrement SPF absent",
            "Aucun enregistrement `v=spf1` : un tiers peut usurper l'adresse "
            "d'expéditeur du domaine.",
            "Publie un enregistrement TXT SPF, par ex. `v=spf1 include:_spf.exemple.com -all`."))
    except _RESOLVE_FAILED as exc:
        findings.append(_resolution_unavailable(f"`{domain}` (SPF)", exc))
    except Exception as exc:  # filet de sécurité : jamais de remontée
        findings.append(_resolution_unavailable(f"`{domain}` (SPF)", exc))

    # --- DMARC ---------------------------------------------------------------
    dmarc_name = f"_dmarc.{domain}"
    try:
        txts = [_join_txt(v) for v in await asyncio.to_thread(_resolve, dmarc_name, "TXT")]
        dmarc = next((t for t in txts if t.lower().startswith("v=dmarc1")), None)
        if not dmarc:
            findings.append(Finding(
                "dns-dmarc", C, Severity.MEDIUM,
                "Enregistrement DMARC absent",
                f"Aucune politique `v=DMARC1` sur `{dmarc_name}` : rien n'indique aux "
                "destinataires comment traiter les messages échouant SPF/DKIM.",
                "Publie une politique DMARC, par ex. `v=DMARC1; p=quarantine; rua=mailto:dmarc@exemple.com`."))
        else:
            policy = _dmarc_policy(dmarc)
            if policy == "none":
                findings.append(Finding(
                    "dns-dmarc", C, Severity.LOW,
                    "DMARC en mode surveillance (`p=none`)",
                    "La politique DMARC est en `p=none` : les messages frauduleux sont "
                    "rapportés mais aucune mesure n'est appliquée.",
                    "Passe progressivement à `p=quarantine` puis `p=reject` une fois les flux légitimes validés.",
                    evidence=f"p={policy}"))
            elif policy in ("quarantine", "reject"):
                findings.append(Finding(
                    "dns-dmarc", C, Severity.PASS,
                    "DMARC appliqué",
                    f"La politique DMARC est en `p={policy}`, elle est effectivement appliquée.",
                    evidence=f"p={policy}"))
            else:
                # `v=DMARC1` présent mais `p=` manquant ou invalide : équivaut à pas d'application.
                findings.append(Finding(
                    "dns-dmarc", C, Severity.LOW,
                    "DMARC sans politique d'application",
                    "Un enregistrement `v=DMARC1` existe mais sa balise `p=` est absente ou "
                    "invalide, donc aucune mesure n'est appliquée.",
                    "Définis explicitement `p=quarantine` ou `p=reject`.",
                    evidence=dmarc[:300]))
    except _NO_RECORD:
        findings.append(Finding(
            "dns-dmarc", C, Severity.MEDIUM,
            "Enregistrement DMARC absent",
            f"Aucune politique `v=DMARC1` sur `{dmarc_name}` : rien n'indique aux "
            "destinataires comment traiter les messages échouant SPF/DKIM.",
            "Publie une politique DMARC, par ex. `v=DMARC1; p=quarantine; rua=mailto:dmarc@exemple.com`."))
    except _RESOLVE_FAILED as exc:
        findings.append(_resolution_unavailable(f"`{dmarc_name}` (DMARC)", exc))
    except Exception as exc:
        findings.append(_resolution_unavailable(f"`{dmarc_name}` (DMARC)", exc))

    # --- CAA -----------------------------------------------------------------
    try:
        caa = await asyncio.to_thread(_resolve, domain, "CAA")
        if caa:
            findings.append(Finding(
                "dns-caa", C, Severity.PASS,
                "Enregistrement CAA présent",
                "Un enregistrement CAA restreint les autorités de certification "
                "autorisées à émettre des certificats pour ce domaine.",
                evidence="; ".join(caa)[:300]))
        else:
            findings.append(_caa_absent())
    except _NO_RECORD:
        findings.append(_caa_absent())
    except _RESOLVE_FAILED as exc:
        findings.append(_resolution_unavailable(f"`{domain}` (CAA)", exc))
    except Exception as exc:
        findings.append(_resolution_unavailable(f"`{domain}` (CAA)", exc))

    return findings


def _dmarc_policy(record: str) -> str | None:
    """Extrait la valeur de la balise `p=` d'un enregistrement DMARC (en minuscules)."""
    for tag in record.split(";"):
        tag = tag.strip()
        if tag.lower().startswith("p="):
            return tag[2:].strip().lower()
    return None


def _caa_absent() -> Finding:
    return Finding(
        "dns-caa", C, Severity.LOW,
        "Enregistrement CAA absent",
        "Aucun enregistrement CAA : n'importe quelle autorité de certification peut "
        "émettre un certificat pour ce domaine. Optionnel mais recommandé.",
        "Ajoute un enregistrement CAA, par ex. `0 issue \"letsencrypt.org\"`.")
