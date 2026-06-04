"""Phase 3 — wrapper nuclei : un vrai moteur de pentest, branché comme un check.

Le principe directeur du projet tient ici tout entier : nuclei n'est qu'une source
de `Finding` de plus. On lance le binaire, on lit sa sortie JSON ligne par ligne,
on mappe chaque résultat vers notre format commun. Le dashboard, le score et
l'historique fonctionnent déjà — rien d'autre à écrire.

Dégradation propre : si `nuclei` n'est pas installé (ex. dev en local sans
l'outil), le check renvoie un simple Finding INFO au lieu d'échouer. Dans l'image
Docker, nuclei et ses templates sont présents (voir le Dockerfile).

Réglable par variables d'environnement :
  NUCLEI_BIN       chemin/nom du binaire        (défaut : "nuclei")
  NUCLEI_SEVERITY  filtre de sévérité           (défaut : "medium,high,critical")
  NUCLEI_TIMEOUT   délai global en secondes     (défaut : "240")
  NUCLEI_ARGS      arguments supplémentaires bruts (défaut : "")
  SONAR_NUCLEI     "off" pour désactiver même si le binaire est présent
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.PENTEST

# Sévérité nuclei -> notre échelle. Tout ce qu'on ne connaît pas retombe en INFO.
_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def _env(name: str, default: str) -> str:
    return (os.environ.get(name) or default).strip()


def _build_args(exe: str, url: str) -> list[str]:
    args = [
        exe,
        "-target", url,
        "-jsonl",                 # une ligne JSON par résultat (sortie machine)
        "-silent",                # pas de bannière/log sur stdout
        "-no-color",
        "-disable-update-check",
        "-timeout", "10",         # par requête
        "-rate-limit", "50",
    ]
    severity = _env("NUCLEI_SEVERITY", "medium,high,critical")
    if severity:
        args += ["-severity", severity]
    extra = _env("NUCLEI_ARGS", "")
    if extra:
        args += extra.split()
    return args


def _to_finding(obj: dict, idx: int, fallback_url: str) -> Finding:
    """Mappe un résultat nuclei vers un Finding structuré EXTERNE.

    Le texte de nuclei (souvent anglais, propre à ses templates) n'est pas figé en
    `title`/`detail` : il part dans `source_text` et sert de *fallback* si aucune
    entrée traduite n'existe (`content/nuclei/<template-id>.<lang>.yaml`). La clé de
    contenu est `(catalog="nuclei", entry_id=template-id, code="result")`.
    """
    info = obj.get("info") or {}
    sev = _SEV.get(str(info.get("severity") or "info").lower(), Severity.INFO)
    name = info.get("name") or obj.get("template-id") or "Résultat nuclei"
    tid = obj.get("template-id") or ""
    matched = obj.get("matched-at") or obj.get("host") or fallback_url

    detail = info.get("description") or ""
    refs = info.get("reference")
    refs_list = [str(r) for r in refs[:4]] if isinstance(refs, list) else []
    if refs_list:
        detail = (detail + "\n" if detail else "") + "Références : " + ", ".join(refs_list)

    reco = info.get("remediation") or ""

    evidence = str(matched)
    extracted = obj.get("extracted-results")
    if isinstance(extracted, list) and extracted:
        evidence += " | " + ", ".join(str(e) for e in extracted)

    # check_id unique (idx) : plusieurs résultats peuvent partager le même template.
    return Finding(
        check_id=f"nuclei-{idx}-{tid}" if tid else f"nuclei-{idx}",
        category=C,
        severity=sev,
        code="result",
        catalog="nuclei",
        entry_id=tid or "_",
        params={"template_id": tid, "name": name},
        evidence=evidence[:400],
        source_text={
            "title": f"[{tid}] {name}" if tid else name,
            "detail": detail,
            "recommendation": reco,
            "refs": refs_list,
        },
    )


@check("nuclei", "Pentest (nuclei)", C)
async def nuclei(ctx):
    if _env("SONAR_NUCLEI", "").lower() == "off":
        return [Finding("nuclei", C, Severity.INFO, code="off")]

    exe = shutil.which(_env("NUCLEI_BIN", "nuclei"))
    if not exe:
        return [Finding("nuclei", C, Severity.INFO, code="not-installed")]

    timeout = int(_env("NUCLEI_TIMEOUT", "240") or "240")
    args = _build_args(exe, ctx.url)

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as exc:  # binaire illisible, etc.
        return [Finding("nuclei", C, Severity.INFO, code="unavailable",
                        params={"error": f"{type(exc).__name__}: {exc}"})]

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return [Finding("nuclei", C, Severity.INFO, code="timeout",
                        params={"timeout": timeout})]

    findings: list[Finding] = []
    for i, line in enumerate(stdout.decode("utf-8", "replace").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            findings.append(_to_finding(obj, i, ctx.url))

    if findings:
        return findings

    # Rien remonté : soit tout est clean, soit une erreur d'exécution.
    if proc.returncode not in (0, None):
        msg = stderr.decode("utf-8", "replace").strip().splitlines()
        tail = msg[-1] if msg else f"code de sortie {proc.returncode}"
        return [Finding("nuclei", C, Severity.INFO, code="incomplete",
                        params={"tail": tail})]
    return [Finding("nuclei", C, Severity.PASS, code="pass")]
