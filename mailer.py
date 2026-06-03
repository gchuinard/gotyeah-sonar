"""Envoi des liens magiques par email.

Stratégie configurable par env, sans dépendance dure : si `BREVO_API_KEY` est
défini, on passe par l'API transactionnelle Brevo ; sinon (dev / self-host pas
encore configuré) on se contente de **logger le lien** — l'auth reste
fonctionnelle, tu récupères le lien dans les logs du conteneur.

Variables d'environnement :
  BREVO_API_KEY        clé API Brevo (vide -> fallback log)
  SONAR_MAIL_FROM      email expéditeur (ex. sonar@tondomaine.com)
  SONAR_MAIL_FROM_NAME nom expéditeur affiché (défaut: Sonar)
"""
from __future__ import annotations

import logging
import os

import httpx

log = logging.getLogger("sonar.mail")

BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _bodies(link: str) -> tuple[str, str, str]:
    subject = "Ton lien de connexion Sonar"
    text = (
        "Connecte-toi à Sonar en ouvrant ce lien (valable ~15 min, à usage unique) :\n\n"
        f"{link}\n\n"
        "Si tu n'as pas demandé ce lien, ignore simplement cet email."
    )
    html = (
        "<p>Connecte-toi à <strong>Sonar</strong> :</p>"
        f'<p><a href="{link}">Ouvrir ma session</a></p>'
        "<p style=\"color:#888;font-size:13px\">Lien valable ~15 min, à usage unique. "
        "Si tu n'as rien demandé, ignore cet email.</p>"
    )
    return subject, text, html


async def send_magic_link(to_email: str, link: str) -> bool:
    """Envoie le lien magique. Retourne True si réellement remis à Brevo, False si
    on a seulement loggé. L'appelant traite les deux cas comme un succès côté
    utilisateur (réponse générique) — on ne révèle jamais l'état d'envoi.
    """
    subject, text, html = _bodies(link)

    api_key = _env("BREVO_API_KEY")
    if not api_key:
        log.warning("BREVO_API_KEY absent — lien magique NON envoyé par email. Lien : %s", link)
        return False

    payload = {
        "sender": {"email": _env("SONAR_MAIL_FROM", "sonar@localhost"),
                   "name": _env("SONAR_MAIL_FROM_NAME", "Sonar")},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": text,
        "htmlContent": html,
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            resp = await client.post(BREVO_ENDPOINT, json=payload,
                                     headers={"api-key": api_key, "accept": "application/json"})
            resp.raise_for_status()
        log.info("Lien magique envoyé à %s via Brevo.", to_email)
        return True
    except Exception as exc:  # noqa: BLE001 — un échec d'email ne doit pas casser l'auth
        log.error("Échec d'envoi Brevo (%s). Lien : %s", exc, link)
        return False
