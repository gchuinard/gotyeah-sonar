#!/usr/bin/env python3
"""Outillage build-time du catalogue de contenu (i18n) — paramétré par langue.

AUCUN LLM au runtime : ce script ne fait que VALIDER, mesurer la COUVERTURE et
SCAFFOLDER des squelettes ; le contenu réel (transformé en FR à partir des sources
ZAP) est produit hors-ligne (agents/relecteurs) puis commité.

Sous-commandes :
  validate    — schéma de tous les content/**/*.<lang>.yaml (title requis, types ok)
  coverage    — (check_id, code) maison émis par les checks sans entrée de catalogue
  zap         — alertes ZAP de tools/zap_sources sans content/zap/<id>.<lang>.yaml
  scaffold    — écrit un squelette content/zap/<id>.<lang>.yaml (a_verifier: true) pour
                chaque alerte ZAP source manquante (à enrichir ensuite)

Exemples :
  python3 tools/gen_content.py validate --lang fr
  python3 tools/gen_content.py coverage --lang fr
  python3 tools/gen_content.py zap --lang fr
  python3 tools/gen_content.py scaffold --lang fr
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTENT = ROOT / "content"
ZAP_SOURCES = ROOT / "tools" / "zap_sources" / "zap_alerts.json"

REQUIRED = ("title",)
TYPED = {"steps": list, "refs": list, "stacks": dict}


def _load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data if isinstance(data, dict) else {}


def _iter_entries(lang: str):
    """Itère (chemin, scope, key, code, entry) sur tout le catalogue d'une langue."""
    for path in sorted((CONTENT / "checks").glob(f"*.{lang}.yaml")):
        for check_id, codes in _load_yaml(path).items():
            if isinstance(codes, dict):
                for code, entry in codes.items():
                    if isinstance(entry, dict):
                        yield path, "checks", str(check_id), str(code), entry
    for scope in ("zap", "nuclei"):
        for path in sorted((CONTENT / scope).glob(f"*.{lang}.yaml")):
            entry_id = path.name[: -len(f".{lang}.yaml")]
            for code, entry in _load_yaml(path).items():
                if isinstance(entry, dict):
                    yield path, scope, entry_id, str(code), entry


def cmd_validate(lang: str) -> int:
    problems = []
    n = 0
    for path, scope, key, code, entry in _iter_entries(lang):
        n += 1
        tag = f"{path.name}:{scope}/{key}/{code}"
        for field in REQUIRED:
            if not isinstance(entry.get(field), str) or not entry[field]:
                problems.append(f"{tag}: champ requis « {field} » manquant")
        for field, typ in TYPED.items():
            if field in entry and not isinstance(entry[field], typ):
                problems.append(f"{tag}: « {field} » doit être un {typ.__name__}")
        if "a_verifier" in entry and not isinstance(entry["a_verifier"], bool):
            problems.append(f"{tag}: « a_verifier » doit être un booléen")
    print(f"[validate:{lang}] {n} entrées vérifiées, {len(problems)} problème(s).")
    for p in problems:
        print("  -", p)
    return 1 if problems else 0


def cmd_coverage(lang: str) -> int:
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "tests"))
    try:
        import scenarios  # noqa: E402
    except Exception as exc:  # pragma: no cover
        print(f"[coverage] impossible de charger les scénarios : {exc}")
        return 2
    have = {(scope, key, code) for _p, scope, key, code, _e in _iter_entries(lang)}
    missing = set()
    for findings in scenarios.run_all().values():
        for f in findings:
            code = f.get("code")
            if not code or f.get("catalog"):
                continue
            key = ("checks", f["check_id"], code)
            if key not in have:
                missing.add(key)
    print(f"[coverage:{lang}] {len(missing)} (check_id, code) maison sans entrée.")
    for m in sorted(missing):
        print("  -", "/".join(m))
    return 1 if missing else 0


def _zap_sources() -> list[dict]:
    if not ZAP_SOURCES.is_file():
        return []
    return json.loads(ZAP_SOURCES.read_text(encoding="utf-8")).get("alerts", [])


def cmd_zap(lang: str) -> int:
    missing = []
    for a in _zap_sources():
        pid = str(a["pluginId"])
        if not (CONTENT / "zap" / f"{pid}.{lang}.yaml").is_file():
            missing.append((pid, a["name"]))
    total = len(_zap_sources())
    print(f"[zap:{lang}] {total - len(missing)}/{total} alertes ZAP couvertes, "
          f"{len(missing)} manquante(s) :")
    for pid, name in missing:
        print(f"  - {pid}  {name}")
    return 0


def cmd_scaffold(lang: str) -> int:
    (CONTENT / "zap").mkdir(parents=True, exist_ok=True)
    written = 0
    for a in _zap_sources():
        pid = str(a["pluginId"])
        dest = CONTENT / "zap" / f"{pid}.{lang}.yaml"
        if dest.is_file():
            continue
        skeleton = {
            "alert": {
                "title": f"TODO ({lang}) — {a['name']}",
                "detail": f"TODO ({lang}) : transformer la description ZAP.",
                "explanation": "TODO",
                "why": "TODO",
                "steps": ["TODO"],
                "stacks": {},
                "refs": list(a.get("refs", [])) + [f"https://cwe.mitre.org/data/definitions/{a.get('cwe','')}.html"],
                "a_verifier": True,
            }
        }
        dest.write_text(
            f"# Squelette généré pour ZAP pluginId {pid} ({a['name']}). À enrichir (transform, pas trad).\n"
            f"# Source : tools/zap_sources/zap_alerts.json — CWE-{a.get('cwe','')}\n"
            + yaml.safe_dump(skeleton, allow_unicode=True, sort_keys=False),
            encoding="utf-8")
        written += 1
    print(f"[scaffold:{lang}] {written} squelette(s) écrit(s).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Outillage build-time du catalogue i18n.")
    ap.add_argument("command", choices=["validate", "coverage", "zap", "scaffold"])
    ap.add_argument("--lang", default="fr")
    args = ap.parse_args()
    return {
        "validate": cmd_validate,
        "coverage": cmd_coverage,
        "zap": cmd_zap,
        "scaffold": cmd_scaffold,
    }[args.command](args.lang)


if __name__ == "__main__":
    raise SystemExit(main())
