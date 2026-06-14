"""Garde réseau anti-SSRF — partagée par le moteur httpx ET les checks à sockets bruts.

Module SANS dépendance interne (ni `runner`, ni `checks`) pour rester importable partout
sans cycle. Centralise : la détection d'IP interne, la politique `SONAR_ALLOW_PRIVATE`,
la résolution, et le verdict « hôte interne ».

Anti-SSRF strict : un hôte est considéré interne dès qu'il résout vers **au moins une** IP
interne (et pas seulement si TOUTES le sont) — sinon un hôte à résolution mixte
`[1.2.3.4, 127.0.0.1]` contournerait la garde et exposerait la ressource interne.
"""
from __future__ import annotations

import ipaddress
import os
import socket


def is_blocked_ip(ip_str: str) -> bool:
    """True si l'IP est interne/non routable : privée (RFC1918), loopback, lien-local
    (169.254/16 → endpoint de métadonnées cloud 169.254.169.254), réservée, multicast…"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def allow_private() -> bool:
    """`SONAR_ALLOW_PRIVATE=on` lève la garde (homelab : scanner une IP interne explicitement)."""
    return (os.environ.get("SONAR_ALLOW_PRIVATE") or "").strip().lower() == "on"


def resolve_ips(host: str) -> list[str]:
    """Résout A/AAAA via getaddrinfo (BLOQUANT → appeler en thread). Liste vide si échec."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []
    seen: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    return seen


def host_is_internal(host: str) -> bool:
    """True si `host` résout vers AU MOINS UNE IP interne (anti-SSRF strict, anti IP mixte).
    Bloquant (getaddrinfo) → à appeler via to_thread. Irrésoluble → False (on laisse échouer
    normalement, ce n'est pas le rôle de la garde de juger l'injoignabilité)."""
    if not host:
        return False
    ips = resolve_ips(host)
    return any(is_blocked_ip(ip) for ip in ips)
