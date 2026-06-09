"""Ports / services exposés — connect-scan async, borné et défensif.

On résout l'hôte cible et on teste une **liste curée** de services qui ne devraient
jamais être exposés publiquement (bases de données, caches, API d'admin…). C'est un
*connect-scan* (TCP, sans root) avec banner-grab passif : ouvrir une connexion suffit
à signaler le service ; on ne lit que ce que le serveur envoie spontanément (lecture
seule, aucune charge utile envoyée).

**Garde-fou CDN** : si l'IP résolue appartient à un CDN connu (Cloudflare), on ne
scanne PAS — cette IP est l'edge du tiers, pas ton origine — et on émet un INFO. Pour
viser ta propre origine derrière le proxy, renseigne `SONAR_ORIGIN_IP`.

Réglable par variables d'environnement :
  SONAR_PORTS            "off" pour désactiver le check
  SONAR_PORTS_TIMEOUT    délai par port en secondes (défaut 2)
  SONAR_PORTS_CONCURRENCY  nb de sondes simultanées (défaut 12)
  SONAR_PORTS_LIST       liste de ports à scanner (override, ex. "6379,3306,22")
  SONAR_ORIGIN_IP        IP d'origine à scanner (bypass de la résolution/CDN)
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.PORTS

# Service attendu par port + sévérité si exposé. L'ouverture du port est le signal ;
# la sévérité reflète la sensibilité du service typiquement à l'écoute là.
_PORTS: list[tuple[int, str, Severity]] = [
    (6379, "Redis", Severity.CRITICAL),
    (27017, "MongoDB", Severity.CRITICAL),
    (9200, "Elasticsearch", Severity.CRITICAL),
    (2375, "Docker API", Severity.CRITICAL),
    (11211, "Memcached", Severity.CRITICAL),
    (5984, "CouchDB", Severity.CRITICAL),
    (3306, "MySQL", Severity.HIGH),
    (5432, "PostgreSQL", Severity.HIGH),
    (1433, "MSSQL", Severity.HIGH),
    (3389, "RDP", Severity.HIGH),
    (5900, "VNC", Severity.HIGH),
    (23, "Telnet", Severity.HIGH),
    (21, "FTP", Severity.HIGH),
    (9000, "Portainer/PHP-FPM", Severity.MEDIUM),
    (5601, "Kibana", Severity.MEDIUM),
    (15672, "RabbitMQ (management)", Severity.MEDIUM),
    (8080, "HTTP-alt / admin", Severity.MEDIUM),
    (8443, "HTTPS-alt / admin", Severity.MEDIUM),
    (9090, "Admin / metrics", Severity.MEDIUM),
    (22, "SSH", Severity.INFO),
    (25, "SMTP", Severity.INFO),
    (587, "SMTP (submission)", Severity.INFO),
]

# Plages CDN connues (Cloudflare) — scanner cette IP scannerait l'edge du tiers, pas
# l'origine. Source : cloudflare.com/ips (stables).
_CDN_RANGES = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ],
}
_CDN_NETS = {name: [ipaddress.ip_network(c) for c in cidrs] for name, cidrs in _CDN_RANGES.items()}


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _port_list() -> list[tuple[int, str, Severity]]:
    """Liste de ports à scanner ; restreinte par SONAR_PORTS_LIST si fourni."""
    override = _env("SONAR_PORTS_LIST")
    if not override:
        return _PORTS
    wanted = {int(p) for p in override.replace(";", ",").split(",") if p.strip().isdigit()}
    return [t for t in _PORTS if t[0] in wanted]


def _is_cdn_ip(ip: str) -> str | None:
    """Renvoie le nom du CDN si l'IP est dans une plage connue, sinon None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, nets in _CDN_NETS.items():
        if any(addr in net for net in nets):
            return name
    return None


async def _resolve_ips(host: str) -> list[str]:
    """Résout A/AAAA (bloquant → thread). Seam mockable. Liste vide si échec."""
    def query() -> list[str]:
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
    return await asyncio.to_thread(query)


async def _probe_port(ip: str, port: int, timeout: float) -> tuple[bool, str]:
    """Connexion TCP + banner-grab PASSIF (on n'envoie rien). Seam mockable."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except Exception:
        return False, ""
    banner = ""
    try:
        data = await asyncio.wait_for(reader.read(200), min(timeout, 1.5))
        banner = data.decode("latin-1", "replace").strip()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return True, banner


@check("ports", "Ports / services exposés", C)
async def ports(ctx):
    if _env("SONAR_PORTS").lower() == "off":
        return [Finding("ports", C, Severity.INFO, code="off")]

    host = getattr(ctx, "host", "") or ""
    if not host:
        return [Finding("ports", C, Severity.INFO, code="unresolved")]

    timeout = float(_env("SONAR_PORTS_TIMEOUT", "2") or "2")
    concurrency = int(_env("SONAR_PORTS_CONCURRENCY", "12") or "12")
    origin = _env("SONAR_ORIGIN_IP")

    if origin:
        scan_ips = [origin]
    else:
        ips = await _resolve_ips(host)
        if not ips:
            return [Finding("ports", C, Severity.INFO, code="unresolved", params={"host": host})]
        cdn = next((c for ip in ips if (c := _is_cdn_ip(ip))), None)
        # On scanne TOUTES les IP non-CDN (et pas seulement la première) : un host multi-A
        # ou mixte CDN+origine exposait son origine sur une 2ᵉ IP, jamais sondée.
        scan_ips = [ip for ip in ips if not _is_cdn_ip(ip)]
        if not scan_ips:
            # Toutes les IP sont derrière un CDN → on ne scanne pas l'edge du tiers.
            return [Finding("ports", C, Severity.INFO, code="behind-cdn",
                            params={"cdn": cdn, "host": host})]

    sem = asyncio.Semaphore(max(1, concurrency))

    async def scan(ip: str, port: int, service: str, severity: Severity):
        async with sem:
            is_open, banner = await _probe_port(ip, port, timeout)
        return (ip, port, service, severity, banner) if is_open else None

    results = await asyncio.gather(
        *[scan(ip, p, s, sev) for ip in scan_ips for p, s, sev in _port_list()])

    findings: list[Finding] = []
    for r in results:
        if not r:
            continue
        ip, port, service, severity, banner = r
        evidence = f"{ip}:{port}" + (f" — {banner[:120]}" if banner else "")
        findings.append(Finding("ports", C, severity, code="service-exposed",
                                params={"service": service, "port": port, "ip": ip},
                                evidence=evidence))
    if findings:
        return findings
    return [Finding("ports", C, Severity.PASS, code="clean", params={"ip": ", ".join(scan_ips)})]
