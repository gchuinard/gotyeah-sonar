"""Comparaison de scans + extraction de remédiation — logique PURE et partagée.

Les deux serveurs MCP (distant in-process, local stdio) exposent `diff_scans` et `get_fix` ;
la logique vit ici, en une seule copie. Tout opère sur des rapports DÉJÀ RENDUS (findings
avec `title`/`severity`/`remediation`, tels que les renvoie get_report / l'API /api/scan) :
aucun accès DB, réseau ou i18n ici — uniquement de la stdlib. Donc importable côté client
local (PYTHONPATH sur le dépôt) comme côté serveur, sans tirer le moteur de scan.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

# Sévérités qui pénalisent le score = « problèmes ». info/pass = bruit pour un diff/fix.
ISSUE_SEVERITIES = {"critical", "high", "medium", "low"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "pass": 5}

# Nom de techno détectée (finding tech/detected) -> clé de stack du catalogue. Miroir de
# la détection du dashboard (templates/index.html : detectedStack()).
_STACK_MAP = {
    "nginx": "nginx", "apache": "apache", "cloudflare": "cloudflare",
    "wordpress": "wordpress", "next.js": "nextjs", "nextjs": "nextjs",
    "express": "express", "caddy": "caddy",
}


def _is_issue(f: dict) -> bool:
    return (f.get("severity") or "").lower() in ISSUE_SEVERITIES


def _key(f: dict):
    """Identité d'un finding pour le diff : (check_id, code, signature des params).

    Les params distinguent plusieurs findings d'un même check (fichier exposé, template
    nuclei…) ; l'evidence (volatile) est volontairement exclue."""
    params = f.get("params")
    sig = json.dumps(params, sort_keys=True, ensure_ascii=False) if params else ""
    return (f.get("check_id"), f.get("code") or "", sig)


def finding_key(f: dict) -> str:
    """Clé STABLE et sérialisable (string) d'un finding — MÊME identité que le diff (`_key`).

    Sert à rattacher une annotation qui se reporte de scan en scan : l'evidence (volatile) est
    exclue, donc l'annotation suit le finding même si sa preuve change d'un scan à l'autre."""
    return json.dumps(list(_key(f)), ensure_ascii=False)


def target_domain(target: str | None) -> str:
    """Hôte normalisé (minuscules) d'une cible de scan — clé de domaine des annotations."""
    return (urlparse(target or "").hostname or (target or "")).strip().lower()


def _sev_key(d: dict):
    return (_SEV_ORDER.get((d.get("severity") or "").lower(), 9), d.get("check_id") or "")


def _brief(f: dict) -> dict:
    return {
        "check_id": f.get("check_id"),
        "code": f.get("code") or "",
        "category": f.get("category"),
        "severity": f.get("severity"),
        "title": f.get("title") or "",
    }


def detected_stack(findings: list) -> str | None:
    """Clé de stack détectée pour ce scan (via le finding tech/detected), ou None."""
    for f in findings or []:
        if f.get("category") == "tech" and f.get("code") == "detected":
            name = ((f.get("params") or {}).get("name") or "").lower()
            if name in _STACK_MAP:
                return _STACK_MAP[name]
    return None


def diff_reports(before: dict, after: dict) -> dict:
    """Compare deux rapports rendus (`before` = base, `after` = nouveau).

    On compare les PROBLÈMES (non info/pass) par (check_id, code, params) : un finding
    qui disparaît = `resolved`, qui apparaît = `new`, présent des deux côtés = `persistent`.
    Plus le delta de score. Lève si un des scans est encore en cours.

    Garde-fou (couverture) : si un check a ÉCHOUÉ dans le scan `after` (`unexecuted`), ses
    problèmes « disparus » ne sont PAS comptés « corrigés » — on ne sait pas, le check n'a
    pas tourné. Ils basculent dans `uncertain` pour éviter une fausse remédiation."""
    for label, r in (("scan_a", before), ("scan_b", after)):
        if (r.get("status") or "done") == "running":
            raise ValueError(f"{label} est encore en cours — attends la fin avant de comparer.")

    issues_a = {_key(f): f for f in before.get("findings", []) if _is_issue(f)}
    issues_b = {_key(f): f for f in after.get("findings", []) if _is_issue(f)}
    # Catégories dont un check n'a pas pu s'exécuter dans `after` → leurs « disparitions »
    # sont suspectes (le problème peut toujours être là, simplement non testé).
    degraded_cats = {f.get("category") for f in after.get("findings", []) if f.get("unexecuted")}

    resolved, uncertain = [], []
    for k in issues_a.keys() - issues_b.keys():
        f = issues_a[k]
        (uncertain if f.get("category") in degraded_cats else resolved).append(_brief(f))
    resolved.sort(key=_sev_key)
    uncertain.sort(key=_sev_key)
    new = sorted((_brief(issues_b[k]) for k in issues_b.keys() - issues_a.keys()), key=_sev_key)
    persistent = sorted((_brief(issues_b[k]) for k in issues_a.keys() & issues_b.keys()), key=_sev_key)

    sa, sb = before.get("score"), after.get("score")
    delta = (sb - sa) if isinstance(sa, int) and isinstance(sb, int) else None
    return {
        "from": {"scan_id": before.get("id"), "target": before.get("target"),
                 "score": sa, "grade": before.get("grade"), "created_at": before.get("created_at")},
        "to": {"scan_id": after.get("id"), "target": after.get("target"),
               "score": sb, "grade": after.get("grade"), "created_at": after.get("created_at")},
        "score_delta": delta,
        "summary": {"resolved": len(resolved), "new": len(new),
                    "persistent": len(persistent), "uncertain": len(uncertain)},
        "resolved": resolved,
        "new": new,
        "persistent": persistent,
        "uncertain": uncertain,
    }


def extract_fixes(report: dict, check_id: str | None = None, code: str | None = None) -> list:
    """Remédiation actionnable des problèmes d'un rapport rendu (filtrable par check_id/code).

    Surligne la stack détectée (snippet prêt) et interpole l'`ai_prompt` ({host}/{stack})
    comme le fait le dashboard, pour qu'il soit directement collable dans un agent de code."""
    findings = report.get("findings", [])
    stack = detected_stack(findings)
    host = urlparse(report.get("target") or "").hostname or (report.get("target") or "")
    stack_name = stack or "ton serveur"

    out = []
    for f in findings:
        if not _is_issue(f):
            continue
        if check_id and f.get("check_id") != check_id:
            continue
        if code and (f.get("code") or "") != code:
            continue
        rem = f.get("remediation") or {}
        stacks = rem.get("stacks") or {}
        prompt = (rem.get("ai_prompt") or "").replace("{host}", host).replace("{stack}", stack_name)
        out.append({
            "check_id": f.get("check_id"),
            "code": f.get("code") or "",
            "severity": f.get("severity"),
            "title": f.get("title") or "",
            "recommendation": f.get("recommendation") or "",
            "explanation": rem.get("explanation") or "",
            "why": rem.get("why") or "",
            "steps": rem.get("steps") or [],
            "stacks": stacks,
            "detected_stack": stack if stack in stacks else None,
            "suggested_snippet": stacks.get(stack) if stack in stacks else None,
            "ai_prompt": prompt,
            "refs": rem.get("refs") or [],
        })
    return sorted(out, key=_sev_key)
