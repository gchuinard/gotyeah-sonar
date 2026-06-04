"""Couche de présentation i18n : détection structurée → texte localisé.

Point d'entrée unique pour la couche web et les tests. Les checks produisent des
findings *structurés* (``code`` + ``params``) ; ici on les *rend* dans la langue
voulue à partir des fichiers de ``content/`` et ``locales/ui/`` — aucun texte humain
n'est figé dans le code des checks.
"""
from __future__ import annotations

from .loader import available_langs, clear_cache
from .render import render_finding, render_ui

__all__ = ["render_finding", "render_ui", "available_langs", "clear_cache"]
