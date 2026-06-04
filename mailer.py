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

import html as _html
import logging
import os

import httpx

from scanner import i18n

log = logging.getLogger("sonar.mail")

BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="__LANG__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark only">
<meta name="supported-color-schemes" content="dark">
<title>Sonar</title>
</head>
<body style="margin:0; padding:0; background:#070b10; -webkit-font-smoothing:antialiased;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#070b10;">
    <tr><td align="center" style="padding:34px 16px;">

      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:460px; background:#0b121a; border:1px solid rgba(122,160,180,0.18); border-radius:14px;">
        <tr><td style="padding:34px 34px 0;">
          <div style="font-family:'Segoe UI',Arial,sans-serif; font-size:20px; font-weight:700; letter-spacing:5px; color:#2ee6a6; text-transform:uppercase;">Sonar</div>
          <div style="font-family:'Courier New',monospace; font-size:11px; color:#7d8c98; margin-top:5px;">__SUBTITLE__</div>
        </td></tr>

        <tr><td style="padding:22px 34px 0;">
          <h1 style="margin:0 0 8px; font-family:'Segoe UI',Arial,sans-serif; font-size:19px; font-weight:600; color:#d6e2ea;">__HEADING__</h1>
          <p style="margin:0; font-family:'Segoe UI',Arial,sans-serif; font-size:14px; line-height:1.6; color:#9fb0bd;">__INTRO__</p>
        </td></tr>

        <tr><td align="center" style="padding:26px 34px 6px;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;">
            <tr><td style="border-radius:9px; background:#2ee6a6;">
              <a href="__LINK__" style="display:inline-block; padding:14px 36px; font-family:'Segoe UI',Arial,sans-serif; font-size:15px; font-weight:700; color:#070b10; text-decoration:none; border-radius:9px;">__BUTTON__</a>
            </td></tr>
          </table>
        </td></tr>

        <tr><td style="padding:20px 34px 0;">
          <p style="margin:0 0 8px; font-family:'Segoe UI',Arial,sans-serif; font-size:12px; color:#7d8c98;">__FALLBACK__</p>
          <p style="margin:0; font-family:'Courier New',monospace; font-size:12px; line-height:1.5; color:#9fb0bd; word-break:break-all; background:#070b10; border:1px solid rgba(122,160,180,0.18); border-radius:8px; padding:11px 13px;">__LINK__</p>
        </td></tr>

        <tr><td style="padding:22px 34px 32px;">
          <p style="margin:0; font-family:'Segoe UI',Arial,sans-serif; font-size:12px; line-height:1.6; color:#7d8c98;">__SECURITY__</p>
        </td></tr>
      </table>

      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:460px;">
        <tr><td align="center" style="padding:16px 0 0;">
          <p style="margin:0; font-family:'Courier New',monospace; font-size:11px; color:#46535d;">__FOOTER__</p>
        </td></tr>
      </table>

    </td></tr>
  </table>
</body>
</html>"""

# Repli si une locale ne définit pas la section "email" (la chaîne de fallback i18n
# renvoie déjà fr, mais on se couvre contre une clé manquante).
_FALLBACK = {
    "subject": "Sonar — ton lien de connexion",
    "subtitle": "console de reconnaissance",
    "heading": "Ta connexion",
    "intro": "Clique sur le bouton pour ouvrir ta session. Le lien est valable ~15 min et à usage unique.",
    "button": "Ouvrir ma session",
    "fallback": "Le bouton ne fonctionne pas ? Copie-colle ce lien :",
    "security": "Tu n'as pas demandé ce lien ? Ignore cet email, aucune action ne sera effectuée.",
    "footer": "Sonar · scanner de sécurité web auto-hébergé",
}


def _bodies(link: str, lang: str = "fr") -> tuple[str, str, str]:
    """Sujet + corps texte + corps HTML, dans la langue `lang`.

    Les chaînes viennent de `locales/ui/<lang>.json` (section `email`) via la couche i18n
    — ajouter une langue localise donc aussi l'email, sans toucher au code.
    """
    e = dict(_FALLBACK)
    try:
        loc = (i18n.render_ui(lang) or {}).get("email") or {}
        e.update({k: v for k, v in loc.items() if v})
    except Exception:  # un souci i18n ne doit pas empêcher l'envoi (on garde le fr de repli)
        pass

    subject = e["subject"]
    text = (
        f"SONAR — {e['subtitle']}\n\n"
        f"{e['heading']}\n"
        f"{e['intro']}\n\n"
        f"{link}\n\n"
        f"{e['security']}\n\n"
        f"— {e['footer']}"
    )
    html = _HTML_TEMPLATE
    html = html.replace("__LANG__", _html.escape(lang, quote=True))
    for slot in ("subtitle", "heading", "intro", "button", "fallback", "security", "footer"):
        html = html.replace(f"__{slot.upper()}__", _html.escape(e[slot]))
    html = html.replace("__LINK__", link)   # token urlsafe : aucun caractère à échapper
    return subject, text, html


async def send_magic_link(to_email: str, link: str, lang: str = "fr") -> bool:
    """Envoie le lien magique. Retourne True si réellement remis à Brevo, False si
    on a seulement loggé. L'appelant traite les deux cas comme un succès côté
    utilisateur (réponse générique) — on ne révèle jamais l'état d'envoi.

    `lang` (ex. depuis l'Accept-Language de la requête) choisit la langue du mail.
    """
    subject, text, html = _bodies(link, lang)

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
