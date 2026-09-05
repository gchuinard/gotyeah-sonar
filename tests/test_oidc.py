"""OIDC : le comparateur de secrets, qui ne doit jamais lever sur une entrée du dehors.

Aucun test ne joint l'IdP. Le flux OIDC n'est pas simulable sans Keycloak, et prétendre le
simuler donnerait une suite verte qui ne prouve rien. Ce qui est verrouillé ici, c'est le
seul endroit du module où une valeur venue d'une requête est comparée à un secret.

`secrets.compare_digest`, alias de `hmac.compare_digest`, **lève `TypeError`** quand l'une
des deux chaînes n'est pas ASCII, au lieu de rendre False. Le `state` du retour de l'IdP est
fabriqué par qui appelle le callback, et le cookie `oidc_tx` n'est pas signé : un octet non
ASCII, ou une valeur qui n'est pas une chaîne, faisait rendre 500 au lieu de la page de
connexion. Ça échouait du bon côté, personne n'ouvrait de session, mais une exception non
rattrapée dans le chemin qui décide qui entre est un défaut.

`mcp_bridge.py` évitait déjà le piège en comparant des bytes ; la leçon n'avait pas été
propagée ici. Trouvé le 05/09/2026, corrigé en même temps dans `radar-prospects/auth.py`.
"""
from __future__ import annotations

import base64
import json

import pytest

import oidc

# L'accent est construit à l'exécution et n'apparaît dans aucun littéral de ce fichier.
# Chaque test qui s'en sert pose en plus un `assert not ....isascii()` sur sa propre matière :
# sur cap-ia, deux tests écrits pour ce même défaut sont passés au vert avec comme sans la
# correction, un « é » s'étant perdu à la génération du fichier. Ils comparaient de l'ASCII.
# Le garde-fou les rend rouges au lieu de les laisser passer pour la mauvaise raison.
NON_ASCII = chr(0xE9)


def test_equal_rend_faux_au_lieu_de_lever():
    assert not ("ab" + NON_ASCII).isascii()  # garde-fou, voir l'en-tête du fichier

    assert oidc._equal("abc", "abc") is True
    assert oidc._equal("abc", "abd") is False
    assert oidc._equal("", "") is True
    assert oidc._equal("ab" + NON_ASCII, "abc") is False
    assert oidc._equal("abc", "ab" + NON_ASCII) is False
    # Pas seulement du non-ASCII : `state` et `nonce` sortent d'un `json.loads` du cookie
    # `oidc_tx`, qui n'est pas signé, donc ils peuvent n'être pas des chaînes du tout.
    assert oidc._equal(None, "abc") is False
    assert oidc._equal("abc", None) is False
    assert oidc._equal(5, "abc") is False
    assert oidc._equal("abc", []) is False
    assert oidc._equal({}, {}) is False
    assert oidc._equal(b"abc", "abc") is False


@pytest.fixture
def oidc_actif(monkeypatch):
    """Le module lit sa configuration à l'IMPORT, dans des constantes (oidc.py:36-39).

    `monkeypatch.setenv` n'a donc aucun effet ici, contrairement au reste de la suite : il
    faut remplacer les attributs du module. Sans ça, `oidc_enabled()` reste faux, le callback
    sort tout de suite par `_fail("disabled")`, et le test rendrait un 303 avec comme sans la
    correction. C'est pour ça que les tests ci-dessous vérifient le `location` exact et pas
    seulement le code de statut : tous les échecs de ce module rendent 303.
    """
    monkeypatch.setattr(oidc, "OIDC_ISSUER", "https://idp.invalid/realms/gotyeah")
    monkeypatch.setattr(oidc, "OIDC_CLIENT_ID", "sonar")
    monkeypatch.setattr(oidc, "OIDC_CLIENT_SECRET", "secret-de-test")
    monkeypatch.setattr(oidc, "OIDC_REDIRECT_URI", "https://exemple.invalid/auth/oidc/callback")
    assert oidc.oidc_enabled()


def _tx(charge: bytes) -> list[tuple[bytes, bytes]]:
    """L'en-tête `Cookie` en OCTETS BRUTS, tel que curl ou une socket l'enverraient.

    Le bocal à cookies de httpx refuse de fabriquer une valeur non-ASCII : un test qui passe
    par `client.cookies` passe à côté du défaut.
    """
    valeur = base64.urlsafe_b64encode(charge).decode()
    return [(b"cookie", f"{oidc._STATE_COOKIE}={valeur}".encode("latin-1"))]


BON_COOKIE = json.dumps({"state": "abc", "nonce": "n", "cv": "v"}).encode()


def test_un_state_non_ascii_rend_la_page_de_connexion_pas_500(client, oidc_actif):
    """Le `state` vient de la chaîne de requête, donc de n'importe qui.

    Il suffit d'appeler `/auth/oidc/login` pour obtenir le cookie de transaction, puis
    d'appeler le callback avec ce qu'on veut. Un état QUI NE CORRESPOND PAS sort avant tout
    appel réseau, ce qui isole le comparateur du reste du flux : aucun test ici ne sort.
    """
    c, _ = client
    assert not ("zz" + NON_ASCII).isascii()  # garde-fou, voir l'en-tête du fichier

    temoin = c.get(
        "/auth/oidc/callback",
        params={"code": "x", "state": "zzz"},
        headers=_tx(BON_COOKIE),
        follow_redirects=False,
    )
    assert temoin.status_code == 303
    assert temoin.headers["location"] == "/login?sso_error=state"

    non_ascii = c.get(
        "/auth/oidc/callback",
        params={"code": "x", "state": "zz" + NON_ASCII},
        headers=_tx(BON_COOKIE),
        follow_redirects=False,
    )
    assert non_ascii.status_code == 303
    assert non_ascii.headers["location"] == "/login?sso_error=state"


def test_un_cookie_de_transaction_qui_n_est_pas_un_objet_rend_303(client, oidc_actif):
    """`json.loads` rend n'importe quel JSON valide, pas forcément un objet.

    Le cookie `oidc_tx` est du base64url d'un JSON, sans HMAC : son contenu est entièrement
    choisi par qui appelle le callback. Un cookie portant `[]` ou `42` passait le décodage,
    puis levait `AttributeError` sur `.get`, et `{"state": 5}` levait dans le comparateur.
    Les deux rendaient 500 sur une route ouverte.
    """
    c, _ = client
    for charge in (b"[]", b"42", b'"texte"', b'{"state": 5}', b'{"state": []}'):
        r = c.get(
            "/auth/oidc/callback",
            params={"code": "x", "state": "zzz"},
            headers=_tx(charge),
            follow_redirects=False,
        )
        assert r.status_code == 303, f"charge {charge!r} a rendu {r.status_code}"
        assert r.headers["location"] == "/login?sso_error=state"
