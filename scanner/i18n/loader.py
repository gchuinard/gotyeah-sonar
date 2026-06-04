"""Chargement + cache des fichiers de locale (contenu de remédiation et chrome UI).

Deux familles de fichiers, séparées exprès :

* **Contenu** (remédiation par résultat) — du YAML, sous ``content/`` :
    - ``content/checks/<famille>.<lang>.yaml`` → ``{check_id: {code: entrée}}``
      (un fichier par famille de checks, plusieurs `check_id` dedans) ;
    - ``content/<scope>/<entry_id>.<lang>.yaml`` → ``{code: entrée}`` pour les
      sources externes (``scope`` = ``zap`` / ``nuclei``, le nom de fichier porte le
      `pluginId` / `template-id`).
* **Chrome UI** (boutons, libellés, bannières) — du JSON, sous ``locales/ui/<lang>.json``.

Le catalogue est indexé à plat par clé ``(scope, key, code)`` :
    - maison  : ``("checks", check_id, code)`` ;
    - externe : ``("zap"|"nuclei", entry_id, code)``.

**Ajouter une langue = déposer des fichiers, zéro code** : les langues disponibles
sont *découvertes* en listant ``locales/ui/*.json``.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import yaml

# Racine du dépôt : scanner/i18n/loader.py -> parents[2] == racine.
_BASE = Path(__file__).resolve().parents[2]

# Surchargeables dans les tests (penser à appeler clear_cache() après).
CONTENT_DIR = _BASE / "content"
UI_DIR = _BASE / "locales" / "ui"

DEFAULT_LANG = "fr"

_lock = threading.Lock()
_content_cache: dict[str, dict] = {}   # lang -> {(scope, key, code): entrée}
_ui_cache: dict[str, dict] = {}        # lang -> dict UI


def clear_cache() -> None:
    """Vide les caches (à appeler quand on modifie CONTENT_DIR/UI_DIR, ex. en test)."""
    with _lock:
        _content_cache.clear()
        _ui_cache.clear()


def available_langs() -> list[str]:
    """Langues proposées par l'UI = un fichier ``locales/ui/<lang>.json`` existe.

    `fr` est toujours présent (langue de référence / fallback).
    """
    langs = {DEFAULT_LANG}
    if UI_DIR.is_dir():
        for path in UI_DIR.glob("*.json"):
            langs.add(path.stem)
    return sorted(langs)


def _load_yaml(path: Path) -> dict:
    """Charge un YAML en dict (jamais d'exception : un fichier cassé = {})."""
    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def content_catalog(lang: str) -> dict:
    """Catalogue de contenu d'une langue : ``{(scope, key, code): entrée}`` (caché)."""
    with _lock:
        cached = _content_cache.get(lang)
    if cached is not None:
        return cached

    catalog: dict = {}

    # Maison : content/checks/<famille>.<lang>.yaml -> {check_id: {code: entrée}}
    checks_dir = CONTENT_DIR / "checks"
    if checks_dir.is_dir():
        for path in sorted(checks_dir.glob(f"*.{lang}.yaml")):
            for check_id, codes in _load_yaml(path).items():
                if not isinstance(codes, dict):
                    continue
                for code, entry in codes.items():
                    if isinstance(entry, dict):
                        catalog[("checks", str(check_id), str(code))] = entry

    # Externe : content/<scope>/<entry_id>.<lang>.yaml -> {code: entrée}
    suffix = f".{lang}.yaml"
    for scope in ("zap", "nuclei"):
        sdir = CONTENT_DIR / scope
        if not sdir.is_dir():
            continue
        for path in sorted(sdir.glob(f"*{suffix}")):
            entry_id = path.name[: -len(suffix)]
            for code, entry in _load_yaml(path).items():
                if isinstance(entry, dict):
                    catalog[(scope, str(entry_id), str(code))] = entry

    with _lock:
        _content_cache[lang] = catalog
    return catalog


def ui_catalog(lang: str) -> dict:
    """Dict chrome UI d'une langue (caché). Absent → {} (le render fera le fallback)."""
    with _lock:
        cached = _ui_cache.get(lang)
    if cached is not None:
        return cached

    data: dict = {}
    path = UI_DIR / f"{lang}.json"
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            data = {}

    with _lock:
        _ui_cache[lang] = data
    return data
