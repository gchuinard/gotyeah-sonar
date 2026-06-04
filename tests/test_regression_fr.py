"""Garde anti-régression FR : le refactor i18n doit rendre EXACTEMENT le texte d'avant.

On ré-exécute la même batterie de scénarios que celle ayant servi à capturer
`golden_fr.json` (depuis le code d'origine), on rend chaque finding via
`scanner.i18n.render_finding(..., "fr")`, et on exige le même `title`/`detail`/
`recommendation` (à la normalisation des tokens volatils près : dates de certificat,
nombres de jours). `check_id`, `severity` et l'ordre/le nombre des findings doivent
aussi coïncider — c'est la preuve que la détection n'a pas bougé.

Tant qu'une famille n'est pas migrée, le rendu passe par le *passthrough* legacy et
le test reste vert ; une fois migrée, il passe par le catalogue YAML et doit toujours
reproduire le golden.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import scenarios

from scanner import i18n

GOLDEN = json.loads((Path(__file__).resolve().parent / "golden_fr.json").read_text(encoding="utf-8"))

# Tokens volatils (le certificat de test est daté relativement à « maintenant »).
_DATE = re.compile(r"\b\w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4} GMT\b")
_DAYS = re.compile(r"\d+ jour\(s\)")


def _norm(s: str) -> str:
    s = _DATE.sub("<DATE>", s or "")
    s = _DAYS.sub("<N> jour(s)", s)
    return s


def test_no_regression_fr():
    fresh = scenarios.run_all()
    assert set(fresh) == set(GOLDEN), "la liste des scénarios a changé"

    diffs: list[str] = []
    for sid, golden_findings in GOLDEN.items():
        got = fresh[sid]
        if len(got) != len(golden_findings):
            diffs.append(f"{sid}: {len(got)} findings vs {len(golden_findings)} attendus")
            continue
        for gf, ff in zip(golden_findings, got):
            r = i18n.render_finding(ff, "fr")
            for field in ("check_id", "severity"):
                if r[field] != gf[field]:
                    diffs.append(f"{sid}/{gf['check_id']}: {field} {r[field]!r} != {gf[field]!r}")
            for field in ("title", "detail", "recommendation"):
                if _norm(r[field]) != _norm(gf[field]):
                    diffs.append(
                        f"{sid}/{gf['check_id']}: {field}\n   rendu  : {r[field]!r}\n   golden : {gf[field]!r}")

    assert not diffs, "Régression de texte FR :\n" + "\n".join(diffs[:40])
