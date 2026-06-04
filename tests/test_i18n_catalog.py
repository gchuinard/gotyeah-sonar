"""Validation du catalogue de contenu FR : schéma + couverture.

- **Schéma** : chaque entrée a un `title`, et les types optionnels sont corrects.
  Politique `ai_prompt` : interdit sur DNS / expiration de certificat (corrigeables
  par une valeur/commande exacte, pas par un agent de code → on met l'info dans `steps`).
- **Couverture** : tout `(check_id, code)` réellement émis par un check *migré*
  (code non vide, source maison) possède une entrée. Les familles non encore migrées
  (texte legacy, code vide) et les résultats externes ZAP/nuclei sont ignorés
  (ces derniers retombent sur leur `source_text`).
"""
from __future__ import annotations

import scenarios

from scanner.i18n import loader

# Familles dont le correctif est une valeur/commande exacte (pas un agent de code).
_NO_AI_PROMPT_PREFIXES = ("dns-", "tls-cert")


def _all_fr_entries():
    """Itère ((scope, key, code), entrée) sur tout le catalogue FR chargé."""
    cat = loader.content_catalog("fr")
    return list(cat.items())


def test_catalog_schema_fr():
    entries = _all_fr_entries()
    assert entries, "catalogue FR vide — aucun content/**/*.fr.yaml chargé ?"
    problems = []
    for (scope, key, code), entry in entries:
        tag = f"{scope}/{key}/{code}"
        if not isinstance(entry.get("title"), str) or not entry["title"]:
            problems.append(f"{tag}: title manquant")
        for field, typ in (("steps", list), ("refs", list), ("stacks", dict)):
            if field in entry and not isinstance(entry[field], typ):
                problems.append(f"{tag}: {field} doit être un {typ.__name__}")
        if "a_verifier" in entry and not isinstance(entry["a_verifier"], bool):
            problems.append(f"{tag}: a_verifier doit être un booléen")
        if scope == "checks" and key.startswith(_NO_AI_PROMPT_PREFIXES) and entry.get("ai_prompt"):
            problems.append(f"{tag}: ai_prompt interdit pour cette famille")
    assert not problems, "Schéma de catalogue invalide :\n" + "\n".join(problems)


def test_catalog_covers_migrated_codes():
    fresh = scenarios.run_all()
    cat = loader.content_catalog("fr")
    missing = set()
    for findings in fresh.values():
        for f in findings:
            code = f.get("code")
            if not code or f.get("catalog"):   # legacy/non migré, ou externe → ignoré
                continue
            key = ("checks", f["check_id"], code)
            if key not in cat:
                missing.add(key)
    assert not missing, f"entrées de catalogue manquantes : {sorted(missing)}"
