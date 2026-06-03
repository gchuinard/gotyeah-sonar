"""Registre des checks : le décorateur `@check` et l'inventaire global.

Chaque fonction décorée avec `@check(id, titre, catégorie)` est enregistrée ici.
Le runner appelle `all_checks()` pour récupérer tout ce qui a été déclaré — il
suffit donc d'importer le module d'un check (via `scanner/checks/__init__.py`)
pour qu'il soit automatiquement pris en compte.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable

from .finding import Category, Finding

# Signature d'un check : `async def fn(ctx) -> list[Finding]`
CheckFn = Callable[..., Awaitable["list[Finding]"]]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    category: Category
    fn: CheckFn


# Ordre d'insertion préservé (dict ordonné) → l'affichage reste stable.
_REGISTRY: dict[str, Check] = {}


def check(check_id: str, title: str, category: Category):
    """Décorateur d'enregistrement.

    Usage :
        @check("hdr-csp", "Content-Security-Policy", Category.HEADERS)
        async def csp(ctx): ...
    """
    def decorator(fn: CheckFn) -> CheckFn:
        if check_id in _REGISTRY:
            raise ValueError(f"check id en double : {check_id!r}")
        _REGISTRY[check_id] = Check(id=check_id, title=title, category=category, fn=fn)
        return fn
    return decorator


def all_checks() -> list[Check]:
    """Tous les checks enregistrés, dans l'ordre de déclaration."""
    return list(_REGISTRY.values())
