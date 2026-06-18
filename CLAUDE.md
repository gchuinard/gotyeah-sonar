# CLAUDE.md — repères pour travailler sur Sonar

Scanner de sécurité web auto-hébergé : un service Python (FastAPI + moteur de scan async),
dashboard Vue 3 (CDN, **zéro build**), historique SQLite. Tourne en Docker sur un Pi.

## Commandes
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt          # = requirements.txt + outils de test/qualité
python3 -m pytest                             # suite complète (hors-ligne, déterministe)
python3 -m pytest tests/test_xxx.py -q        # un fichier
SONAR_INTEGRATION=1 python3 -m pytest -m integration   # tests réseau réels (badssl), opt-in
ruff check . && ruff format --check . && mypy .        # lint / format / typage (cf. pyproject.toml)
python3 tools/gen_content.py validate --lang fr        # valide le catalogue i18n (et --lang en)
```
Lancer l'app en local : `uvicorn app:app --reload` (ou `docker compose up -d --build`).

## Principe directeur : tout est un `Finding`
Le backend ne fait que **streamer du JSON**. Chaque check renvoie des `Finding` **structurés**
(un `code` de résultat + `params`, **jamais de texte humain**). La couche `scanner/i18n/` rend
le texte dans la langue demandée à partir du catalogue `content/`. L'historique stocke la forme
structurée → un scan se **re-rend dans n'importe quelle langue**.

## Ajouter un check
1. Fichier dans `scanner/checks/`, fonction `async` décorée `@check("mon-id", "Titre", Category.X)`.
   Détection **pure** : renvoie `[Finding("mon-id", Cat, Severity.Y, code="...", params={...})]`.
2. Déclare le module dans `scanner/checks/__init__.py` (l'import = l'enregistrement).
3. Contenu (texte + remédiation) dans `content/checks/<famille>.fr.yaml` **et** `.en.yaml`,
   indexé par `(check_id, code)`. Valide avec `tools/gen_content.py`.
`ctx` donne : `ctx.url` (URL finale), `ctx.host`, `ctx.response`, `ctx.history`, `ctx.client`.

## Pièges à connaître
- **YAML i18n** : `off`/`null`/`on`/`no` sont des booléens → **à QUOTER** comme clés de code
  (`"off":`). Sinon le code de finding ne matche pas son entrée.
- **Couverture vs PASS** : un check qui n'a pas pu tourner (réseau, outil absent, timeout) doit
  être `unexecuted=True` (cf. `_UNEXECUTED_CODES` dans `runner.py`) → plafonne le grade. Ne pas
  le confondre avec un vrai PASS. « La note ne ment pas. »
- **Scoring** (`finding.py:score_and_grade`) : pénalité plafonnée par `(check_id, sévérité)`
  (anti-avalanche), puis grade plafonné par pire sévérité (CRITICAL→E, HIGH→C) et couverture
  incomplète (→ B max). Le front (`templates/index.html`) en a un **miroir approximatif** pour
  la jauge live ; la source de vérité reste le serveur.
- **Anti-SSRF** : `scanner/netguard.py` est la garde partagée (IP internes). Tout check qui ouvre
  un **socket brut** (ports/tls) doit la consulter — la garde httpx ne couvre QUE httpx.
  `SONAR_ALLOW_PRIVATE=on` lève la garde (homelab).
- **ZAP = état partagé** : le démon ZAP est **persistant** et son scanner passif **accumule** ses
  alertes en session → `core/view/alerts` ressort celles des scans **précédents** (preuves périmées
  = score figé). `zap.py` ouvre donc une **session vierge** (`newSession`) en **1er** appel, sous
  `_ZAP_LOCK` (un seul démon, mais jusqu'à 4 scans concurrents). nuclei, lui, est un sous-process
  neuf par scan → sans état. Tout futur check branché sur un **service à état partagé** doit
  réinitialiser cet état en début de scan.
- **Auth** : routes d'écriture/admin = **cookie de session uniquement** ; les PAT (Bearer) sont
  **lecture seule** (default-deny par construction). Cloisonnement par `user_id` (admin = tout).
  Toute **nouvelle table rattachée à `user_id`** (ex. `annotations`) DOIT être purgée dans
  `auth.delete_user` **et** `delete_user_guarded` (cascade) — dépôt public, pas de données orphelines.
- **Annotations de findings** : note perso + statut « risque accepté », rattachées au
  `(user_id, domaine, scan_compare.finding_key)` → reportées de scan en scan (même identité que
  `diff_scans`, evidence exclue). N'affectent **jamais** le score (« la note ne ment pas »). La
  greffe live (SSE) et archivée doit utiliser l'**hôte final** (post-redirection), pas l'hôte saisi.
- **Front zéro build** : Vue est servi en local (`/static/vendor/`), pas de CDN ; pas de
  transpilation — du JS/HTML directement éditable.

## Sécurité / déploiement
- En-têtes de sécurité posés par un middleware ASGI (`app.py`) — l'app suit ses propres règles.
- Dépôt **PUBLIC** : ne jamais committer de secrets ni de notes de failles
  (`.env`, `TODO-securite-sites.md`, `AMELIORATIONS.md` sont gitignorés).
- Déploiement : `deploy.yml` (push main → tests → rsync Pi → `docker compose up -d --build`).
  Le Pi reçoit les fichiers par rsync (pas de `git pull`) → son HEAD git ne bouge pas.
