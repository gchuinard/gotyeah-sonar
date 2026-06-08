"""Scans ASYNCHRONES persistés — pour déclencher un scan depuis le MCP.

Un scan complet (nuclei/ZAP) peut durer plusieurs minutes, soit plus que le délai d'un
appel MCP/HTTP. On découple donc le lancement du résultat :

  1. `start_scan` crée tout de suite une ligne 'running' (id immédiat) et lance le scan
     dans une tâche de fond qui FINALISE la ligne quand c'est terminé ;
  2. l'appelant peut attendre un court instant (`wait_for_completion`) puis, si le scan
     dure, récupérer le rapport plus tard via get_report(scan_id).

Le résultat est ainsi persisté quoi qu'il arrive (même si l'appel MCP a expiré ou si le
client s'est déconnecté). Pas de logique métier ici : on réutilise le moteur de scan et
la couche `db`. Le contrôle « domaine vérifié » reste à la charge de l'appelant (le MCP
applique `auth.user_can_scan_target` AVANT d'appeler `start_scan`).
"""
from __future__ import annotations

import asyncio
import os

import db
from scanner.runner import run_scan as _engine_run_scan

# Réf. fortes aux tâches de fond : sans ça, asyncio peut les garbage-collecter en plein vol.
_BG_TASKS: set[asyncio.Task] = set()


def scan_wait_secs() -> float:
    """Délai d'attente synchrone côté MCP avant de rendre la main (env, défaut 25 s).

    Volontairement court (sous les timeouts proxy ~60-100 s) : si le scan dure plus, on
    renvoie l'`scan_id` et le rapport se récupère ensuite."""
    raw = (os.environ.get("SONAR_MCP_SCAN_WAIT") or "").strip()
    try:
        v = float(raw) if raw else 25.0
    except ValueError:
        v = 25.0
    return max(0.0, v)


def start_scan(target: str, user_id: str | None) -> str:
    """Crée la ligne 'running' et lance le scan en tâche de fond. Retourne l'`scan_id`."""
    scan_id = db.create_running_scan(target, user_id=user_id)
    task = asyncio.create_task(_run_to_completion(scan_id, target))
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)
    return scan_id


async def _run_to_completion(scan_id: str, target: str) -> None:
    """Consomme le générateur du moteur et finalise (ou marque en échec) la ligne."""
    summary = None
    findings: list = []
    try:
        async for ev in _engine_run_scan(target):
            if ev["event"] == "done":
                summary = ev["data"]
                findings = ev.get("_findings", [])
            elif ev["event"] == "scan_error":
                db.fail_scan(scan_id, ev["data"].get("message", "Scan en échec."))
                return
        if summary is not None:
            db.finalize_scan(scan_id, summary, findings)
        else:
            db.fail_scan(scan_id, "Scan interrompu sans résultat.")
    except Exception as exc:  # le scan ne doit jamais laisser la ligne en 'running'
        db.fail_scan(scan_id, f"{type(exc).__name__}: {exc}")


async def wait_for_completion(scan_id: str, wait_secs: float | None = None,
                              interval: float = 2.0) -> dict | None:
    """Attend (au plus `wait_secs`) que le scan ne soit plus 'running'.

    Renvoie le scan complet s'il s'est terminé (ou a échoué) dans le délai, sinon None
    (toujours en cours). On interroge la même base que la tâche de fond (boucle d'événements
    partagée : `asyncio.sleep` laisse le scan progresser)."""
    budget = scan_wait_secs() if wait_secs is None else max(0.0, wait_secs)
    step = max(0.1, interval)
    waited = 0.0
    while waited < budget:
        await asyncio.sleep(step)
        waited += step
        data = db.get_scan(scan_id)
        if data and data.get("status") != "running":
            return data
    return None
