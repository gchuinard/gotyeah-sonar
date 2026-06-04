"""Rendu d'un finding structuré → texte localisé (+ carte de remédiation).

C'est le pendant « présentation » de la détection : on prend un finding sérialisé
(``Finding.as_dict()``) et une langue, on résout l'entrée de catalogue
correspondante, on interpole les `params`/`evidence` et on renvoie un dict prêt à
afficher.

**Chaîne de fallback stricte** (jamais de clé brute affichée, couverture toujours
complète) :

    langue demandée → fr → (externe : `source_text` d'origine, ex. EN ZAP) → défaut sûr.

Interpolation : on remplace les placeholders ``{nom}`` par `params[nom]` (ou
`evidence`). On utilise une regex stricte ``\\{(\\w+)\\}`` — et **pas**
``str.format`` — pour ne JAMAIS toucher aux accolades littérales présentes dans le
contenu (snippets nginx ``add_header ...``, Next.js ``headers(): { ... }``…). Un
placeholder inconnu (ex. ``{stack}``, choisi côté UI) est laissé tel quel.
"""
from __future__ import annotations

import re
from typing import Optional

from . import loader

# Placeholder = {motInProgress} strict : ni espace, ni ponctuation → on n'attrape
# jamais une accolade de code (`{ key: ... }`).
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def available_langs() -> list[str]:
    return loader.available_langs()


def _fallback_langs(lang: str) -> list[str]:
    """[langue demandée, fr] dédupliqué (l'ordre porte la priorité)."""
    seq = [lang]
    if loader.DEFAULT_LANG not in seq:
        seq.append(loader.DEFAULT_LANG)
    return seq


def _interp(template, ctx: dict) -> str:
    """Remplace les ``{nom}`` connus ; laisse intact tout le reste (y compris les
    accolades de code et les placeholders non fournis)."""
    if not template or not isinstance(template, str):
        return template or ""
    return _PLACEHOLDER.sub(lambda m: str(ctx.get(m.group(1), m.group(0))), template)


def _interp_ctx(params: Optional[dict], evidence) -> dict:
    ctx = dict(params or {})
    ctx.setdefault("evidence", evidence or "")
    return ctx


def _resolve_entry(f: dict, lang: str) -> Optional[dict]:
    """Cherche l'entrée de catalogue selon la chaîne de fallback de langue."""
    if f.get("catalog"):
        scope, key = str(f["catalog"]), str(f.get("entry_id"))
    else:
        scope, key = "checks", str(f.get("check_id"))
    code = str(f.get("code") or "")
    for lng in _fallback_langs(lang):
        entry = loader.content_catalog(lng).get((scope, key, code))
        if entry:
            return entry
    return None


def _build_remediation(entry: dict, ctx: dict) -> dict:
    """Construit le bloc remédiation (façon GTmetrix) interpolé."""
    return {
        "explanation": _interp(entry.get("explanation", ""), ctx),
        "why": _interp(entry.get("why", ""), ctx),
        "steps": [_interp(s, ctx) for s in (entry.get("steps") or [])],
        "stacks": {k: _interp(v, ctx) for k, v in (entry.get("stacks") or {}).items()},
        "ai_prompt": _interp(entry.get("ai_prompt", ""), ctx) if entry.get("ai_prompt") else "",
        "refs": list(entry.get("refs") or []),
        "a_verifier": bool(entry.get("a_verifier", False)),
    }


def _from_source(base: dict, src: dict) -> dict:
    """Fallback externe : on rend le texte d'origine (ex. anglais ZAP) tel quel,
    marqué `untranslated` pour que l'UI puisse le signaler discrètement."""
    base.update(
        title=src.get("title") or "",
        detail=src.get("detail") or "",
        recommendation=src.get("recommendation") or "",
        remediation={
            "explanation": "", "why": "", "steps": [], "stacks": {},
            "ai_prompt": "", "refs": list(src.get("refs") or []),
            "a_verifier": False, "untranslated": True,
        },
    )
    return base


def _safe_default(base: dict, lang: str) -> dict:
    """Dernier recours : un texte générique localisé, jamais une clé brute."""
    ui = loader.ui_catalog(lang) or loader.ui_catalog(loader.DEFAULT_LANG)
    fb = (ui.get("fallback") if isinstance(ui, dict) else None) or {}
    base.update(
        title=fb.get("title") or "Résultat sans description",
        detail=fb.get("detail") or "",
        recommendation="",
        remediation=None,
    )
    return base


def render_finding(f: dict, lang: str = "fr") -> dict:
    """Rend un finding sérialisé dans `lang`. Ne lève jamais : couverture garantie."""
    base = {
        "check_id": f.get("check_id"),
        "category": f.get("category"),
        "severity": f.get("severity"),
        "code": f.get("code") or "",
        "evidence": f.get("evidence"),
    }

    # 1) Legacy / non structuré (ancien historique, check non migré) : passthrough.
    if not f.get("code") and (f.get("title") or f.get("detail") or f.get("recommendation")):
        base.update(
            title=f.get("title") or "",
            detail=f.get("detail") or "",
            recommendation=f.get("recommendation") or "",
            remediation=None,
        )
        return base

    # 2) Structuré : résoudre l'entrée de catalogue.
    entry = _resolve_entry(f, lang)
    ctx = _interp_ctx(f.get("params"), f.get("evidence"))

    if entry is None:
        # 2b) externe sans entrée traduite → texte d'origine ; sinon défaut sûr.
        src = f.get("source_text")
        return _from_source(base, src) if src else _safe_default(base, lang)

    # 3) interpolation.
    base.update(
        title=_interp(entry.get("title", ""), ctx),
        detail=_interp(entry.get("detail", ""), ctx),
        recommendation=_interp(entry.get("recommendation", ""), ctx),
        remediation=_build_remediation(entry, ctx),
    )
    return base


def render_ui(lang: str = "fr") -> dict:
    """Dict chrome UI : base `fr` surchargée par la langue demandée (clé à clé)."""
    merged = dict(loader.ui_catalog(loader.DEFAULT_LANG))
    if lang != loader.DEFAULT_LANG:
        for key, value in (loader.ui_catalog(lang) or {}).items():
            merged[key] = value
    return merged
