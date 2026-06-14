"""Moteur de scan.

`run_scan(target)` est un générateur asynchrone : il lance tous les checks
enregistrés en parallèle et émet des événements (dict) au fur et à mesure que
chaque check se termine. La couche web n'a plus qu'à transformer ces événements
en SSE.

Événements émis :
  - started     {target, total_checks, categories}
  - finding     {<un Finding sérialisé>}
  - progress    {done, total, category}
  - done        {score, grade, counts, total, target}   (+ clé interne _findings)
  - scan_error  {message}
"""
from __future__ import annotations

import asyncio
import os
import time
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from . import checks as _checks  # noqa: F401  -> importe les modules = enregistre les checks
from .finding import Category, Finding, Severity, summarize
from .netguard import allow_private
from .netguard import host_is_internal as _host_is_internal
from .netguard import is_blocked_ip as _is_blocked_ip  # noqa: F401 (ré-export, tests)
from .registry import Check, all_checks

USER_AGENT = "Sonar/0.1 (+homelab; authorized use only)"

# Plafond de durée du scan complet (s) : si un check se bloque malgré ses propres timeouts,
# le scan ne reste pas « en cours » indéfiniment. > NUCLEI_TIMEOUT/ZAP_TIMEOUT (240) + marge.
_SCAN_DEADLINE = float(os.environ.get("SONAR_SCAN_DEADLINE") or "300")

# Plafond de scans SIMULTANÉS (web + MCP, tous deux passent par run_scan). Anti-DoS : un scan
# `full` fork nuclei/ZAP + ouvre des dizaines de sockets ; sans borne, N scans concurrents
# saturent l'hôte. Les scans en excès attendent un créneau (le flux SSE émet des heartbeats).
_MAX_CONCURRENT_SCANS = max(1, int(os.environ.get("SONAR_MAX_CONCURRENT_SCANS") or "4"))
_SCAN_SEMAPHORE = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)


class _SSRFGuardTransport(httpx.AsyncHTTPTransport):
    """Transport httpx qui REFUSE toute requête (cible initiale OU saut de redirection) vers
    un hôte résolvant en IP interne — protection anti-SSRF. Sans ça, un site externe pouvait
    rediriger vers `http://169.254.169.254/` (métadonnées cloud) ou `127.0.0.1`, et tous les
    checks tournaient alors contre la ressource interne (avec la cible persistée écrasée)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache: dict[str, bool] = {}

    async def handle_async_request(self, request):
        host = request.url.host
        if host not in self._cache:
            self._cache[host] = await asyncio.to_thread(_host_is_internal, host)
        if self._cache[host]:
            raise httpx.ConnectError(f"cible interne bloquée ({host})", request=request)
        return await super().handle_async_request(request)

# Catégories des checks « lents » (Phase 3 pentest + scan réseau) : exclues du profil
# rapide, qui ne garde que le passif/actif léger (quelques secondes, retour synchrone).
_SLOW_CATEGORIES = {Category.PENTEST, Category.ZAP, Category.PORTS}


def checks_for(fast: bool = False):
    """Checks à exécuter pour ce scan. `fast=True` exclut nuclei/ZAP/ports (en-têtes,
    TLS, DNS, cookies, exposition passive… seulement) pour un scan de quelques secondes."""
    checks = all_checks()
    if fast:
        checks = [c for c in checks if c.category not in _SLOW_CATEGORIES]
    return checks


@dataclass
class Context:
    """Tout ce qu'un check peut avoir besoin de connaître sur la cible."""
    url: str            # URL finale, après redirections
    requested_url: str  # URL demandée au départ
    host: str
    response: httpx.Response
    history: list
    client: httpx.AsyncClient


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


async def _fetch_root(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """GET la racine. Si l'HTTPS échoue au niveau TRANSPORT (443 fermé / pas de TLS),
    on retombe sur http:// : un site HTTP-only doit quand même être scanné — le check
    `tls` émettra alors le finding « http » (trafic en clair) au lieu que TOUT le scan
    échoue en « cible injoignable »."""
    try:
        return await client.get(url)
    except httpx.TransportError:
        if url.startswith("https://"):
            return await client.get("http://" + url[len("https://"):])
        raise


def _make_client() -> httpx.AsyncClient:
    """Client httpx partagé par tous les checks.

    verify=False À DESSEIN : un certificat invalide (expiré, auto-signé, mauvais hôte, chaîne
    cassée) ne doit PAS faire échouer la construction du contexte et perdre la cible — c'est le
    check `tls` qui rejoue un handshake VÉRIFIANT et fait autorité sur la validité du cert.

    Sauf `SONAR_ALLOW_PRIVATE=on` (utile en homelab pour scanner une IP interne explicitement),
    on enrobe le transport d'une garde anti-SSRF qui bloque les cibles/redirections internes.
    """
    transport = None if allow_private() else _SSRFGuardTransport(verify=False)
    return httpx.AsyncClient(
        transport=transport,
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
        headers={"User-Agent": USER_AGENT},
        verify=False,
    )


async def _build_context(target: str) -> Context:
    requested = normalize_target(target)
    client = _make_client()
    try:
        resp = await _fetch_root(client, requested)
    except Exception:
        await client.aclose()
        raise
    parsed = urlparse(str(resp.url))
    return Context(
        url=str(resp.url),
        requested_url=requested,
        host=parsed.hostname or "",
        response=resp,
        history=list(resp.history),
        client=client,
    )


# (check_id, code) qu'un check émet pour dire « je n'ai PAS pu m'exécuter » (outil absent,
# timeout, hôte injoignable) — à distinguer d'un vrai PASS. Marqués `unexecuted` → plafond
# de grade. NB : les codes « off »/« not-configured » (désactivation VOLONTAIRE) n'y sont
# pas : couper nuclei/ZAP exprès n'est pas une couverture défaillante.
_UNEXECUTED_CODES = {
    ("nuclei", "not-installed"), ("nuclei", "unavailable"),
    ("nuclei", "timeout"), ("nuclei", "incomplete"),
    ("zap", "timeout"), ("zap", "unreachable"),
    ("tls", "unreachable"), ("tls", "error"),
    ("tls-key", "unreachable"), ("tls-key", "unavailable"),
}


async def _safe_run(chk: Check, ctx: Context):
    """Un check qui plante ne doit jamais casser le scan entier — mais son échec est TRACÉ
    (`unexecuted`) pour que le score n'en tire pas un faux bon point (couverture réduite)."""
    try:
        findings = await chk.fn(ctx) or []
    except Exception as exc:
        return chk, [Finding(
            check_id=chk.id,
            category=chk.category,
            severity=Severity.INFO,
            title=f"Check « {chk.title} » indisponible",
            detail=f"{type(exc).__name__}: {exc}",
            unexecuted=True,
        )]
    for f in findings:
        if (f.check_id, f.code) in _UNEXECUTED_CODES:
            f.unexecuted = True
    return chk, findings


def _deadline_finding(chk: Check, deadline: float) -> Finding:
    """Check non terminé avant la deadline globale : interrompu, marqué `unexecuted` (la note
    est plafonnée et le scan ne reste pas « en cours » indéfiniment)."""
    return Finding(
        check_id=chk.id, category=chk.category, severity=Severity.INFO,
        title=f"Check « {chk.title} » interrompu (délai global dépassé)",
        detail=f"Le scan a dépassé {int(deadline)} s ; ce check n'a pas pu terminer.",
        unexecuted=True,
    )


async def _stream_results(ctx: Context, checks, deadline: float):
    """Lance les checks en // et émet les events au fil de l'eau, sous une DEADLINE globale :
    les checks non terminés à temps sont annulés et signalés (jamais de scan figé)."""
    total = len(checks)
    yield {"event": "started", "data": {
        "target": ctx.url,
        "total_checks": total,
        "categories": dict(Counter(c.category for c in checks)),
    }}

    collected: list[Finding] = []
    done = 0
    task_check = {asyncio.create_task(_safe_run(c, ctx)): c for c in checks}
    pending = set(task_check)
    end_at = time.monotonic() + deadline
    try:
        while pending:
            remaining = end_at - time.monotonic()
            if remaining <= 0:
                break
            finished, pending = await asyncio.wait(
                pending, timeout=remaining, return_when=asyncio.FIRST_COMPLETED)
            if not finished:                       # deadline atteinte sans nouveau résultat
                break
            for fut in finished:
                chk, findings = await fut
                done += 1
                for f in findings:
                    collected.append(f)
                    yield {"event": "finding", "data": f.as_dict()}
                yield {"event": "progress", "data": {
                    "done": done, "total": total, "category": chk.category}}

        # Reste des checks non terminés (deadline) : on annule et on les signale dégradés.
        for fut in pending:
            fut.cancel()
            chk = task_check[fut]
            f = _deadline_finding(chk, deadline)
            collected.append(f)
            done += 1
            yield {"event": "finding", "data": f.as_dict()}
            yield {"event": "progress", "data": {
                "done": done, "total": total, "category": chk.category}}
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    finally:
        await ctx.client.aclose()

    summary = summarize(collected)
    summary["target"] = ctx.url
    yield {"event": "done", "data": summary,
           "_findings": [f.as_dict() for f in collected]}


async def run_scan(target: str, fast: bool = False):
    # Sémaphore global : borne le nombre de scans simultanés (web + MCP). Acquis au 1er
    # `__anext__`, libéré à l'épuisement OU à l'aclose (déconnexion client) du générateur.
    async with _SCAN_SEMAPHORE:
        try:
            ctx = await _build_context(target)
        except Exception as exc:
            yield {"event": "scan_error", "data": {"message": f"Cible injoignable : {exc}"}}
            return
        async for ev in _stream_results(ctx, checks_for(fast), _SCAN_DEADLINE):
            yield ev
