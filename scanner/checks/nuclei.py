"""Phase 3 — wrapper nuclei : un vrai moteur de pentest, branché comme un check.

Le principe directeur du projet tient ici tout entier : nuclei n'est qu'une source
de `Finding` de plus. On lance le binaire, on lit sa sortie JSON ligne par ligne,
on mappe chaque résultat vers notre format commun. Le dashboard, le score et
l'historique fonctionnent déjà — rien d'autre à écrire.

Dégradation propre : si `nuclei` n'est pas installé (ex. dev en local sans
l'outil), le check renvoie un simple Finding INFO au lieu d'échouer. Dans l'image
Docker, nuclei et ses templates sont présents (voir le Dockerfile).

Réglable par variables d'environnement :
  NUCLEI_BIN        chemin/nom du binaire       (défaut : "nuclei")
  NUCLEI_SEVERITY   filtre de sévérité          (défaut : "medium,high,critical")
  NUCLEI_TAGS       familles de templates
                    (défaut : "cve,misconfig,exposure,exposed-panels,default-login,takeover")
                    -> cible les classes exploitables, borné par la sévérité (medium+).
                       Mets NUCLEI_TAGS=all pour lever le filtre (tous les templates).
  NUCLEI_RATE_LIMIT requêtes/seconde max        (défaut : "50")
  NUCLEI_TIMEOUT    délai global en secondes    (défaut : "240")
  NUCLEI_ARGS       arguments supplémentaires bruts (défaut : "")
  SONAR_NUCLEI      "off" pour désactiver même si le binaire est présent
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.PENTEST

# Familles de templates lancées par défaut : les classes réellement exploitables, pas
# seulement les mauvaises configs. Bornées par NUCLEI_SEVERITY (medium+) pour le volume.
_DEFAULT_TAGS = "cve,misconfig,exposure,exposed-panels,default-login,takeover"

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
        "-rate-limit", _env("NUCLEI_RATE_LIMIT", "50"),
    ]
    severity = _env("NUCLEI_SEVERITY", "medium,high,critical")
    if severity:
        args += ["-severity", severity]
    # Cantonne nuclei aux familles de templates les plus PERTINENTES pour la sécurité : on
    # cible les classes réellement exploitables (CVE, panels exposés, identifiants par défaut,
    # takeover) en plus des mauvaises configs/expositions. Borné par la sévérité (medium+),
    # ça reste raisonnable en volume sans amputer la valeur du pentest. Échappatoire :
    # NUCLEI_TAGS=all (ou *) lève le filtre et lance tout. (Sentinel plutôt que vide : une
    # valeur vide retombe sur le défaut — et Docker Compose passe « vide » quand non défini.)
    tags = _env("NUCLEI_TAGS", _DEFAULT_TAGS)
    if tags and tags.lower() not in ("all", "*", "off", "none"):
        args += ["-tags", tags]
    extra = _env("NUCLEI_ARGS", "")
    if extra:
        args += extra.split()
    return args


def _to_finding(obj: dict, idx: int, fallback_url: str, count: int = 1) -> Finding:
    """Mappe un résultat nuclei vers un Finding structuré EXTERNE.

    Le texte de nuclei (souvent anglais, propre à ses templates) n'est pas figé en
    `title`/`detail` : il part dans `source_text` et sert de *fallback* si aucune
    entrée traduite n'existe (`content/nuclei/<template-id>.<lang>.yaml`). La clé de
    contenu est `(catalog="nuclei", entry_id=template-id, code="result")`. `count` est le
    nombre d'URL où ce template a matché (dédup) — un seul Finding, pas N.
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
    if count > 1:
        detail = (detail + "\n" if detail else "") + f"{count} occurrence(s) détectée(s)."

    reco = info.get("remediation") or ""

    evidence = str(matched)
    extracted = obj.get("extracted-results")
    if isinstance(extracted, list) and extracted:
        evidence += " | " + ", ".join(str(e) for e in extracted)

    # check_id unique (idx) : plusieurs templates différents peuvent coexister.
    return Finding(
        check_id=f"nuclei-{idx}-{tid}" if tid else f"nuclei-{idx}",
        category=C,
        severity=sev,
        code="result",
        catalog="nuclei",
        entry_id=tid or "_",
        params={"template_id": tid, "name": name, "count": count},
        evidence=evidence[:400],
        source_text={
            "title": f"[{tid}] {name}" if tid else name,
            "detail": detail,
            "recommendation": reco,
            "refs": refs_list,
        },
    )


def _dedup_to_findings(results: list[dict], fallback_url: str) -> list[Finding]:
    """Regroupe les résultats par (template-id, sévérité) et compte les occurrences.

    Sans ça, un template « en-tête manquant » qui matche 40 pages produirait 40 Finding
    (et 40× la pénalité) : on n'en garde qu'UN, avec le nombre d'URL touchées.
    """
    grouped: dict = {}
    order: list = []
    for obj in results:
        tid = obj.get("template-id") or ""
        sev = str((obj.get("info") or {}).get("severity") or "info").lower()
        gkey = (tid, sev)
        if gkey not in grouped:
            grouped[gkey] = {"sample": obj, "count": 0}
            order.append(gkey)
        grouped[gkey]["count"] += 1
    return [_to_finding(grouped[k]["sample"], i, fallback_url, count=grouped[k]["count"])
            for i, k in enumerate(order)]


async def _read_results(stream, out: list) -> None:
    """Lit la sortie JSONL de nuclei LIGNE PAR LIGNE et accumule les objets dans `out`.

    Lecture incrémentale (et non un `communicate()` final) : si le scan est interrompu au
    timeout, `out` contient déjà tout ce qui a été remonté jusque-là — rien n'est perdu.
    """
    while True:
        line = await stream.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)


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

    # Draine stderr en parallèle (évite que son tampon plein ne bloque la lecture stdout).
    stderr_chunks: list[bytes] = []

    async def _drain_stderr():
        try:
            stderr_chunks.append(await proc.stderr.read())
        except Exception:
            pass

    stderr_task = asyncio.create_task(_drain_stderr()) if proc.stderr else None

    results: list[dict] = []
    timed_out = False
    try:
        # Lecture incrémentale bornée : au timeout, on GARDE ce qui a déjà été remonté.
        await asyncio.wait_for(_read_results(proc.stdout, results), timeout=timeout)
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass
    except asyncio.TimeoutError:
        timed_out = True
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
    if stderr_task:
        try:
            await asyncio.wait_for(stderr_task, timeout=2)
        except Exception:
            stderr_task.cancel()

    findings = _dedup_to_findings(results, ctx.url)

    if timed_out:
        # On a peut-être trouvé des choses avant la coupure : on les remonte, ET on signale
        # que le scan n'a pas fini (couverture incomplète → la note est plafonnée côté runner).
        findings.append(Finding("nuclei", C, Severity.INFO, code="timeout",
                                params={"timeout": timeout}))
        return findings

    if findings:
        return findings

    # Rien remonté : soit tout est clean, soit une erreur d'exécution.
    if proc.returncode not in (0, None):
        stderr = b"".join(stderr_chunks)
        msg = stderr.decode("utf-8", "replace").strip().splitlines()
        tail = msg[-1] if msg else f"code de sortie {proc.returncode}"
        return [Finding("nuclei", C, Severity.INFO, code="incomplete",
                        params={"tail": tail})]
    return [Finding("nuclei", C, Severity.PASS, code="pass")]
