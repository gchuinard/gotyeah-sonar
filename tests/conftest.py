"""Outils partagés par les tests : réponses httpx synthétiques, ctx factice, client factice.

Tout est hors-ligne : les checks reçoivent des réponses fabriquées à la main, et
les checks actifs (cors, exposed) reçoivent un `FakeClient` qui renvoie des
réponses préprogrammées. Aucun test ne touche le réseau.
"""
from __future__ import annotations

import types

import httpx
import pytest


def _make_response(status=200, headers=None, text="", url="https://example.com/"):
    """Construit une httpx.Response réaliste (en-têtes + corps maîtrisés).

    On passe le corps en `content=` (bytes) pour garder un contrôle total sur le
    Content-Type : httpx ne l'ajoute pas tout seul, contrairement à `text=`.
    """
    return httpx.Response(
        status,
        headers=headers,
        content=text.encode("utf-8"),
        request=httpx.Request("GET", url),
    )


def _make_ctx(response=None, url="https://example.com/", history=None,
              client=None, host="example.com"):
    """Reproduit l'interface de scanner.runner.Context attendue par les checks."""
    if response is None:
        response = _make_response(url=url)
    return types.SimpleNamespace(
        url=url,
        requested_url=url,
        host=host,
        response=response,
        history=history or [],
        client=client,
    )


class FakeClient:
    """Client httpx factice : `get()` renvoie une réponse selon l'URL.

    routes  : {suffixe_d_url: réponse}  (match par `url.endswith(suffixe)`)
    default : réponse renvoyée sinon (par défaut : 404).
    """

    def __init__(self, routes=None, default=None):
        self.routes = routes or {}
        self.default = default
        self.calls = []

    async def get(self, url, headers=None):
        self.calls.append((str(url), headers))
        for frag, resp in self.routes.items():
            if str(url).endswith(frag):
                return resp
        if self.default is not None:
            return self.default
        return _make_response(404, text="not found", url=url)


@pytest.fixture
def make_response():
    return _make_response


@pytest.fixture
def make_ctx():
    return _make_ctx


@pytest.fixture
def fake_client_cls():
    return FakeClient
