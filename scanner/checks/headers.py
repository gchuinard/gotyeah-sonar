"""En-têtes de sécurité HTTP — le gros du scan passif."""
from __future__ import annotations

import re

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.HEADERS


@check("hdr-csp", "Content-Security-Policy", C)
async def csp(ctx):
    v = ctx.response.headers.get("content-security-policy")
    if not v:
        return [Finding("hdr-csp", C, Severity.MEDIUM,
            "Content-Security-Policy absent",
            "Aucune CSP n'est envoyée : la première ligne de défense contre le XSS "
            "et l'injection de contenu manque.",
            "Définis une CSP, même restrictive au départ (`default-src 'self'`), puis affine.")]
    weak = []
    if "unsafe-inline" in v:
        weak.append("`unsafe-inline`")
    if "unsafe-eval" in v:
        weak.append("`unsafe-eval`")
    if weak:
        return [Finding("hdr-csp", C, Severity.LOW,
            "CSP présente mais permissive",
            "La CSP autorise " + ", ".join(weak) + ", ce qui réduit fortement sa protection.",
            "Supprime ces directives en passant aux nonces/hashes pour tes scripts.",
            evidence=v[:300])]
    return [Finding("hdr-csp", C, Severity.PASS,
        "Content-Security-Policy présente",
        "Une CSP est définie, sans directive notoirement dangereuse.",
        evidence=v[:300])]


@check("hdr-hsts", "Strict-Transport-Security", C)
async def hsts(ctx):
    v = ctx.response.headers.get("strict-transport-security")
    if not v:
        return [Finding("hdr-hsts", C, Severity.MEDIUM,
            "HSTS absent",
            "Sans HSTS, un visiteur peut être rétrogradé en HTTP par un attaquant réseau.",
            "Ajoute `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.")]
    findings = [Finding("hdr-hsts", C, Severity.PASS,
        "HSTS présent",
        "L'en-tête Strict-Transport-Security est envoyé.",
        evidence=v)]
    m = re.search(r"max-age=(\d+)", v)
    if m and int(m.group(1)) < 15552000:  # < ~6 mois
        findings.append(Finding("hdr-hsts-maxage", C, Severity.LOW,
            "HSTS max-age faible",
            f"max-age={m.group(1)} s, en dessous du seuil recommandé (~6 mois).",
            "Monte max-age à 63072000 (2 ans) une fois sûr de ton HTTPS."))
    return findings


@check("hdr-xfo", "Protection clickjacking", C)
async def xfo(ctx):
    h = ctx.response.headers
    csp = (h.get("content-security-policy") or "").lower()
    if h.get("x-frame-options") or "frame-ancestors" in csp:
        return [Finding("hdr-xfo", C, Severity.PASS,
            "Protection clickjacking présente",
            "X-Frame-Options ou CSP frame-ancestors est défini.")]
    return [Finding("hdr-xfo", C, Severity.MEDIUM,
        "Protection clickjacking absente",
        "Ni X-Frame-Options ni frame-ancestors : la page peut être embarquée en iframe.",
        "Ajoute `X-Frame-Options: DENY` ou `frame-ancestors 'none'` dans la CSP.")]


@check("hdr-nosniff", "X-Content-Type-Options", C)
async def nosniff(ctx):
    v = (ctx.response.headers.get("x-content-type-options") or "").lower()
    if v == "nosniff":
        return [Finding("hdr-nosniff", C, Severity.PASS,
            "X-Content-Type-Options: nosniff",
            "Le navigateur ne devinera pas le type MIME.")]
    return [Finding("hdr-nosniff", C, Severity.LOW,
        "X-Content-Type-Options absent",
        "Le MIME sniffing peut transformer un upload anodin en script exécutable.",
        "Ajoute `X-Content-Type-Options: nosniff`.")]


@check("hdr-referrer", "Referrer-Policy", C)
async def referrer(ctx):
    if ctx.response.headers.get("referrer-policy"):
        return [Finding("hdr-referrer", C, Severity.PASS,
            "Referrer-Policy présente",
            "La politique de Referer est définie.")]
    return [Finding("hdr-referrer", C, Severity.LOW,
        "Referrer-Policy absente",
        "Sans politique, des URLs internes peuvent fuiter vers des sites tiers.",
        "Ajoute `Referrer-Policy: strict-origin-when-cross-origin`.")]


@check("hdr-permissions", "Permissions-Policy", C)
async def permissions(ctx):
    if ctx.response.headers.get("permissions-policy"):
        return [Finding("hdr-permissions", C, Severity.PASS,
            "Permissions-Policy présente",
            "L'accès aux API navigateur (caméra, micro, géoloc…) est cadré.")]
    return [Finding("hdr-permissions", C, Severity.INFO,
        "Permissions-Policy absente",
        "Optionnel mais recommandé pour désactiver les API navigateur inutiles.",
        "Ex. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.")]


@check("hdr-disclosure", "Divulgation de version serveur", C)
async def disclosure(ctx):
    h = ctx.response.headers
    leaks = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        val = h.get(name)
        # On ne signale que si une version semble présente (un chiffre).
        if val and any(ch.isdigit() for ch in val):
            leaks.append(f"{name}: {val}")
    if leaks:
        return [Finding("hdr-disclosure", C, Severity.LOW,
            "Version logicielle exposée",
            "Des en-têtes révèlent des versions précises, utiles pour cibler des CVE connues.",
            "Masque ou raccourcis ces en-têtes (`proxy_hide_header`, `server_tokens off`…).",
            evidence="; ".join(leaks))]
    return [Finding("hdr-disclosure", C, Severity.PASS,
        "Pas de version logicielle évidente",
        "Aucun en-tête ne divulgue de numéro de version exploitable.")]
