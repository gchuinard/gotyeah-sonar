"""Enregistrements DNS de sécurité e-mail / PKI — SPF, DMARC, CAA.

Détection pure : chaque branche ne renvoie qu'un `code` (+ `params`/`evidence`). Le
texte humain (titre, détail, recommandation, remédiation) vit dans
`content/checks/dns.fr.yaml` et est rendu par `scanner.i18n`.
"""
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
    """Finding structuré : la résolution DNS pour `label` n'a pas pu aboutir."""
    return Finding(
        "dns-resolve",
        C,
        Severity.INFO,
        code="unavailable",
        params={"label": label, "error_type": type(exc).__name__},
    )


@check("dns", "DNS (SPF / DMARC / CAA)", Category.DNS)
async def dns_check(ctx):
    findings: list[Finding] = []
    domain = _org_domain(getattr(ctx, "host", "") or "")

    if not domain:
        return [Finding("dns-resolve", C, Severity.INFO, code="no-host")]

    # --- SPF -----------------------------------------------------------------
    try:
        txts = [_join_txt(v) for v in await asyncio.to_thread(_resolve, domain, "TXT")]
        spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
        if spf:
            findings.append(Finding(
                "dns-spf", C, Severity.PASS, code="present", evidence=spf[:300]))
        else:
            findings.append(Finding("dns-spf", C, Severity.MEDIUM, code="absent"))
    except _NO_RECORD:
        findings.append(Finding("dns-spf", C, Severity.MEDIUM, code="absent"))
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
                code="absent", params={"dmarc_name": dmarc_name}))
        else:
            policy = _dmarc_policy(dmarc)
            if policy == "none":
                findings.append(Finding(
                    "dns-dmarc", C, Severity.LOW,
                    code="monitor", evidence=f"p={policy}"))
            elif policy in ("quarantine", "reject"):
                findings.append(Finding(
                    "dns-dmarc", C, Severity.PASS,
                    code="enforced", params={"policy": policy}, evidence=f"p={policy}"))
            else:
                # `v=DMARC1` présent mais `p=` manquant ou invalide : équivaut à pas d'application.
                findings.append(Finding(
                    "dns-dmarc", C, Severity.LOW,
                    code="no-policy", evidence=dmarc[:300]))
    except _NO_RECORD:
        findings.append(Finding(
            "dns-dmarc", C, Severity.MEDIUM,
            code="absent", params={"dmarc_name": dmarc_name}))
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
                code="present", evidence="; ".join(caa)[:300]))
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
    """Finding structuré : aucun enregistrement CAA n'est publié pour le domaine."""
    return Finding("dns-caa", C, Severity.LOW, code="absent")


# Sélecteurs DKIM courants (on ne peut pas tous les énumérer → sondage best-effort).
_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2",
                   "mail", "dkim", "s1", "s2", "mandrill", "sendgrid"]


@check("dns-dkim", "DKIM (sélecteurs courants)", C)
async def dkim(ctx):
    domain = _org_domain(getattr(ctx, "host", "") or "")
    if not domain:
        return []
    for sel in _DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        try:
            txts = [_join_txt(v) for v in await asyncio.to_thread(_resolve, name, "TXT")]
        except Exception:
            continue
        if any("v=dkim1" in t.lower() or ("p=" in t.lower() and "k=" in t.lower()) for t in txts):
            return [Finding("dns-dkim", C, Severity.PASS, code="present",
                            params={"selector": sel}, evidence=name)]
    return [Finding("dns-dkim", C, Severity.INFO, code="none")]


@check("dns-mtasts", "MTA-STS", C)
async def mtasts(ctx):
    domain = _org_domain(getattr(ctx, "host", "") or "")
    if not domain:
        return []
    name = f"_mta-sts.{domain}"
    try:
        txts = [_join_txt(v) for v in await asyncio.to_thread(_resolve, name, "TXT")]
    except _NO_RECORD:
        return [Finding("dns-mtasts", C, Severity.INFO, code="none")]
    except _RESOLVE_FAILED as exc:
        return [_resolution_unavailable(f"`{name}` (MTA-STS)", exc)]
    except Exception as exc:
        return [_resolution_unavailable(f"`{name}` (MTA-STS)", exc)]
    if any("v=stsv1" in t.lower() for t in txts):
        return [Finding("dns-mtasts", C, Severity.PASS, code="present", evidence=name)]
    return [Finding("dns-mtasts", C, Severity.INFO, code="none")]


@check("dns-tlsrpt", "TLS-RPT", C)
async def tlsrpt(ctx):
    domain = _org_domain(getattr(ctx, "host", "") or "")
    if not domain:
        return []
    name = f"_smtp._tls.{domain}"
    try:
        txts = [_join_txt(v) for v in await asyncio.to_thread(_resolve, name, "TXT")]
    except _NO_RECORD:
        return [Finding("dns-tlsrpt", C, Severity.INFO, code="none")]
    except _RESOLVE_FAILED as exc:
        return [_resolution_unavailable(f"`{name}` (TLS-RPT)", exc)]
    except Exception as exc:
        return [_resolution_unavailable(f"`{name}` (TLS-RPT)", exc)]
    if any("v=tlsrptv1" in t.lower() for t in txts):
        return [Finding("dns-tlsrpt", C, Severity.PASS, code="present", evidence=name)]
    return [Finding("dns-tlsrpt", C, Severity.INFO, code="none")]


@check("dns-dnssec", "DNSSEC", C)
async def dnssec(ctx):
    domain = _org_domain(getattr(ctx, "host", "") or "")
    if not domain:
        return []
    try:
        keys = await asyncio.to_thread(_resolve, domain, "DNSKEY")
    except _NO_RECORD:
        keys = []
    except _RESOLVE_FAILED as exc:
        return [_resolution_unavailable(f"`{domain}` (DNSSEC)", exc)]
    except Exception:
        keys = []
    if keys:
        return [Finding("dns-dnssec", C, Severity.PASS, code="present")]
    return [Finding("dns-dnssec", C, Severity.LOW, code="absent")]
