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
from urllib.parse import urljoin, urlparse

from ..finding import Category, Finding, Severity
from ..registry import check

C = Category.EXPOSURE

# Chemin improbable pour détecter les sites qui répondent 200 à tout (soft-404).
_PROBE_404 = "zz-sonar-probe-404-zz"

# Limite de lecture du corps : on n'a besoin que du début pour les signatures.
_MAX_BODY = 4096


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


def _sig_zip(text: str, content_type: str) -> bool:
    # Archive ZIP : signature magique en tête (local / vide / spanned).
    return text[:4] in ("PK\x03\x04", "PK\x05\x06", "PK\x07\x08")


def _sig_sqldump(text: str, content_type: str) -> bool:
    # Dump SQL : marqueurs de structure/contenu typiques d'un export de base.
    low = text.lower()
    return any(m in low for m in (
        "create table", "insert into", "drop table",
        "mysql dump", "postgresql database dump"))


def _sig_php(text: str, content_type: str) -> bool:
    # Source PHP servi en clair (ex. sauvegarde .bak non interprétée) : commence par `<?php`.
    return text.lstrip().lower().startswith("<?php")


def _sig_wpconfig(text: str, content_type: str) -> bool:
    # wp-config.php servi en clair : contient les `define('DB_NAME'…)` de WordPress.
    return re.search(r"define\(\s*['\"]DB_", text) is not None


def _sig_aws(text: str, content_type: str) -> bool:
    # Identifiants AWS : profil INI avec aws_access_key_id / aws_secret_access_key.
    low = text.lower()
    return "aws_access_key_id" in low or "aws_secret_access_key" in low


def _sig_tfstate(text: str, content_type: str) -> bool:
    # État Terraform (JSON) : porte le schéma `terraform_version` / `resources`.
    low = text.lower()
    return '"terraform_version"' in low or ('"resources"' in low and '"version"' in low)


def _sig_dsstore(text: str, content_type: str) -> bool:
    # En-tête magique d'un .DS_Store : \x00\x00\x00\x01Bud1
    return text[:8].startswith("\x00\x00\x00\x01Bud1")


def _sig_phpinfo(text: str, content_type: str) -> bool:
    low = text.lower()
    return "phpinfo()" in low or "phpinfo" in low and "php version" in low


# (chemin, check_id, sévérité, signature) — le texte humain part dans le YAML.
# Chaque cible a une signature de CONTENU dédiée : un fichier de sauvegarde n'est plus
# signalé sur le seul fait d'« être non-HTML » (sinon une API renvoyant 200+JSON à tout
# déclenchait jusqu'à 5 faux HIGH), mais sur des octets/marqueurs qui lui sont propres.
_TARGETS = [
    (".env", "exposed-env", Severity.CRITICAL, _sig_env),
    (".env.bak", "exposed-env-bak", Severity.HIGH, _sig_env),
    (".git/HEAD", "exposed-git", Severity.HIGH, _sig_git_head),
    (".git/config", "exposed-git-config", Severity.HIGH, _sig_git_config),
    (".svn/entries", "exposed-svn", Severity.HIGH, _sig_svn),
    (".hg/requires", "exposed-hg", Severity.HIGH, _sig_hg),
    ("docker-compose.yml", "exposed-compose", Severity.MEDIUM, _sig_compose),
    ("Dockerfile", "exposed-dockerfile", Severity.MEDIUM, _sig_dockerfile),
    ("backup.zip", "exposed-backup-zip", Severity.HIGH, _sig_zip),
    ("backup.sql", "exposed-backup-sql", Severity.HIGH, _sig_sqldump),
    ("database.sql", "exposed-database-sql", Severity.HIGH, _sig_sqldump),
    ("config.php.bak", "exposed-config-bak", Severity.HIGH, _sig_php),
    (".DS_Store", "exposed-dsstore", Severity.LOW, _sig_dsstore),
    ("phpinfo.php", "exposed-phpinfo", Severity.MEDIUM, _sig_phpinfo),
    # Cibles supplémentaires (Batch 1), chacune à signature dédiée.
    ("wp-config.php", "exposed-wpconfig", Severity.HIGH, _sig_wpconfig),
    (".aws/credentials", "exposed-aws", Severity.CRITICAL, _sig_aws),
    ("terraform.tfstate", "exposed-tfstate", Severity.HIGH, _sig_tfstate),
]


async def _probe_404(ctx) -> tuple[bool, str]:
    """Réponse de référence sur un chemin improbable → (soft_404, corps_de_référence).

    `soft_404=True` si la cible répond 200 à n'importe quoi : le code 200 ne prouve alors
    rien (une signature de contenu reste TOUJOURS exigée). Le corps de référence sert en
    plus à écarter un « hit » dont le contenu est en fait la page générique du site."""
    try:
        resp = await ctx.client.get(urljoin(ctx.url, _PROBE_404))
        if resp.status_code == 200:
            return True, (resp.text or "")[:_MAX_BODY]
    except Exception:
        # Injoignable / erreur : on reste prudent et on ne suppose pas le soft-404.
        pass
    return False, ""


def _probe_bases(url: str) -> list[str]:
    """URLs de base à sonder : l'URL FINALE (après redirection) ET la racine du domaine
    (`scheme://host/`), dédupliquées. Ne sonder que l'URL finale ratait un `.env` servi à
    la racine quand l'accueil redirige vers un sous-chemin (ex. `/` → `/en/`)."""
    parsed = urlparse(url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    return [url] if url == root else [url, root]


async def _hit(ctx, bases, path, signature, soft_404, baseline) -> str | None:
    """Sonde `path` sous chaque base ; renvoie le snippet au premier vrai hit, sinon None."""
    for base in bases:
        try:
            resp = await ctx.client.get(urljoin(base, path))
        except Exception:
            continue  # un chemin injoignable ne doit rien casser
        if resp.status_code != 200:
            continue
        content_type = (resp.headers.get("content-type") or "").lower()
        try:
            text = (resp.text or "")[:_MAX_BODY]
        except Exception:
            continue
        # Soft-404 : si ce corps EST la page générique de référence, ce n'est pas notre
        # fichier — on écarte (le 200 ne prouve jamais rien à lui seul).
        if soft_404 and baseline and text.strip() == baseline.strip():
            continue
        # Signature de contenu obligatoire.
        try:
            if not signature(text, content_type):
                continue
        except Exception:
            continue
        return text.strip()[:200]
    return None


@check("exposed", "Fichiers sensibles exposés", Category.EXPOSURE)
async def exposed(ctx):
    soft_404, baseline = await _probe_404(ctx)
    bases = _probe_bases(ctx.url)

    findings: list[Finding] = []
    for path, cid, severity, signature in _TARGETS:
        snippet = await _hit(ctx, bases, path, signature, soft_404, baseline)
        if snippet is not None:
            # Détection pure : le chemin part en `params`, le snippet en `evidence` ;
            # titre/détail/reco sont rendus par le catalogue via (check_id, "found").
            findings.append(Finding(
                cid, C, severity, code="found",
                params={"path": path}, evidence=snippet or None))

    if not findings:
        return [Finding("exposed", C, Severity.PASS, code="clean")]
    return findings
