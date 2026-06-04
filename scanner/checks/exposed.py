"""Fichiers/chemins sensibles exposés — Phase 2, actif léger.

On sonde quelques chemins classiques (`.env`, `.git/HEAD`, sauvegardes…) à la
racine de la cible. Beaucoup de sites renvoient 200 + HTML pour *tout* (soft-404),
donc chaque chemin a une **signature de contenu** : sans correspondance, on ne
signale rien. Une seule requête par chemin, tout est protégé par try/except.

Détection pure : chaque hit ne renvoie qu'un `code` (`found`) + `params` (le
chemin) + `evidence` (le snippet). Le texte humain (titre, détail, recommandation,
remédiation) vit dans `content/checks/exposed.fr.yaml` et est rendu par
`scanner.i18n` à partir de la clé ``(check_id, code)``.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.EXPOSURE

# Chemin improbable pour détecter les sites qui répondent 200 à tout (soft-404).
_PROBE_404 = "zz-sonar-probe-404-zz"

# Limite de lecture du corps : on n'a besoin que du début pour les signatures.
_MAX_BODY = 4096


def _looks_html(text: str, content_type: str) -> bool:
    """Heuristique « c'est du HTML » (donc probablement une page d'erreur déguisée)."""
    if "html" in content_type:
        return True
    head = text.lstrip()[:512].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head


def _sig_env(text: str, content_type: str) -> bool:
    # Au moins une ligne `CLE=valeur` typique d'un fichier d'environnement.
    return re.search(r"(?m)^[A-Z0-9_]+=", text) is not None


def _sig_git_head(text: str, content_type: str) -> bool:
    head = text.strip()
    return head.startswith("ref:") or re.fullmatch(r"[0-9a-f]{40}", head) is not None


def _sig_git_config(text: str, content_type: str) -> bool:
    return "[core]" in text


def _sig_svn(text: str, content_type: str) -> bool:
    # .svn/entries commence par un numéro de version sur sa propre ligne.
    return re.match(r"^\s*\d+\s*$", text.splitlines()[0]) is not None if text.strip() else False


def _sig_hg(text: str, content_type: str) -> bool:
    # .hg/requires : une liste de capacités (revlogv1, dotencode, store…).
    return "revlog" in text or "store" in text or "dotencode" in text


def _sig_compose(text: str, content_type: str) -> bool:
    return re.search(r"(?m)^\s*services:", text) is not None


def _sig_dockerfile(text: str, content_type: str) -> bool:
    return re.search(r"(?im)^\s*FROM\s+\S", text) is not None


def _sig_backup(text: str, content_type: str) -> bool:
    # Sauvegarde brute : 200 + type non-HTML suffit (archive/dump binaire ou texte).
    return not _looks_html(text, content_type)


def _sig_dsstore(text: str, content_type: str) -> bool:
    # En-tête magique d'un .DS_Store : \x00\x00\x00\x01Bud1
    return text[:8].startswith("\x00\x00\x00\x01Bud1")


def _sig_phpinfo(text: str, content_type: str) -> bool:
    low = text.lower()
    return "phpinfo()" in low or "phpinfo" in low and "php version" in low


# (chemin, check_id, sévérité, signature) — le texte humain part dans le YAML.
_TARGETS = [
    (".env", "exposed-env", Severity.CRITICAL, _sig_env),
    (".env.bak", "exposed-env-bak", Severity.HIGH, _sig_backup),
    (".git/HEAD", "exposed-git", Severity.HIGH, _sig_git_head),
    (".git/config", "exposed-git-config", Severity.HIGH, _sig_git_config),
    (".svn/entries", "exposed-svn", Severity.HIGH, _sig_svn),
    (".hg/requires", "exposed-hg", Severity.HIGH, _sig_hg),
    ("docker-compose.yml", "exposed-compose", Severity.MEDIUM, _sig_compose),
    ("Dockerfile", "exposed-dockerfile", Severity.MEDIUM, _sig_dockerfile),
    ("backup.zip", "exposed-backup-zip", Severity.HIGH, _sig_backup),
    ("backup.sql", "exposed-backup-sql", Severity.HIGH, _sig_backup),
    ("database.sql", "exposed-database-sql", Severity.HIGH, _sig_backup),
    ("config.php.bak", "exposed-config-bak", Severity.HIGH, _sig_backup),
    (".DS_Store", "exposed-dsstore", Severity.LOW, _sig_dsstore),
    ("phpinfo.php", "exposed-phpinfo", Severity.MEDIUM, _sig_phpinfo),
]


async def _probe_is_soft_404(ctx) -> bool:
    """True si la cible renvoie 200 sur un chemin random → 200 ne prouve rien."""
    try:
        url = urljoin(ctx.url, _PROBE_404)
        resp = await ctx.client.get(url)
        return resp.status_code == 200
    except Exception:
        # Injoignable / erreur : on reste prudent et on ne suppose pas le soft-404.
        return False


@check("exposed", "Fichiers sensibles exposés", Category.EXPOSURE)
async def exposed(ctx):
    # Le résultat de la sonde soft-404 n'est plus déterminant : on exige
    # *toujours* une signature de contenu, ce qui couvre aussi ce cas.
    soft_404 = await _probe_is_soft_404(ctx)  # noqa: F841 — informatif, signature reste reine

    findings: list[Finding] = []

    for path, cid, severity, signature in _TARGETS:
        try:
            url = urljoin(ctx.url, path)
            resp = await ctx.client.get(url)
        except Exception:
            # Un chemin injoignable ne doit rien casser : on passe au suivant.
            continue

        if resp.status_code != 200:
            continue

        content_type = (resp.headers.get("content-type") or "").lower()
        try:
            text = resp.text or ""
        except Exception:
            text = ""
        text = text[:_MAX_BODY]

        # Signature de contenu obligatoire : jamais sur le seul code 200.
        try:
            if not signature(text, content_type):
                continue
        except Exception:
            continue

        snippet = text.strip()[:200]
        # Détection pure : le chemin part en `params`, le snippet en `evidence` ;
        # titre/détail/reco sont rendus par le catalogue via (check_id, "found").
        findings.append(Finding(
            cid, C, severity,
            code="found",
            params={"path": path},
            evidence=snippet or None,
        ))

    if not findings:
        return [Finding("exposed", C, Severity.PASS, code="clean")]

    return findings
