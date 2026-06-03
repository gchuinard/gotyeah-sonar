# Sonar

Scanner de sécurité web auto-hébergé, pour auditer **tes propres sites** et les blinder.
Un seul service Python, un dashboard qui affiche les résultats en direct (streaming SSE),
un historique par domaine. Pensé pour tourner sur le Pi à côté du reste du homelab.

> ⚠️ **Usage autorisé uniquement.** Scanne exclusivement des domaines qui t'appartiennent
> ou pour lesquels tu as une autorisation explicite. C'est un outil défensif.

---

## Lancer

```bash
docker compose up -d --build
```

Puis : `http://<ip-du-pi>:8000`. Tape une URL, clique **Lancer**, regarde les findings
tomber en live et la jauge se stabiliser.

L'historique est persisté dans `./data/scans.db` (volume Docker).

### Derrière Nginx Proxy Manager

Le flux live passe par du Server-Sent Events. Le code envoie déjà l'en-tête
`X-Accel-Buffering: no`, donc **ne touche à rien** côté NPM : surtout n'active pas le
*proxy buffering*, sinon les résultats n'arriveraient qu'à la toute fin du scan.

---

## Ce que ça vérifie

### Phase 1 — passif (une seule requête)

| Catégorie | Checks |
|-----------|--------|
| En-têtes HTTP | CSP, HSTS (+ max-age), clickjacking (X-Frame-Options / frame-ancestors), nosniff, Referrer-Policy, Permissions-Policy, divulgation de version serveur |
| Cookies | Secure / HttpOnly / SameSite sur chaque cookie posé |
| TLS | version négociée (refus < 1.2), validité et expiration du certificat |
| DNS | SPF, DMARC (+ détection `p=none`), CAA |

### Phase 2 — actif léger (quelques requêtes ciblées)

| Catégorie | Checks |
|-----------|--------|
| Exposition | fichiers sensibles exposés (`.env`, `.git/HEAD`, `.git/config`, sauvegardes, `.DS_Store`, `phpinfo`…), avec sonde anti soft-404 et **signature de contenu obligatoire** (jamais sur le seul code 200) |
| CORS | origine reflétée, `*`, `null`, et combinaison dangereuse avec `Access-Control-Allow-Credentials` |
| Contenu mixte | ressources `http://` (actives vs passives) chargées sur une page `https://` |
| Sous-ressources | scripts/CSS même-origine servis sans `X-Content-Type-Options: nosniff` (échantillon récupéré activement) |
| Technologies | empreinte serveur / framework / CMS (en-têtes, cookies, balise meta generator) + alerte si une version est exposée |

### Phase 3 — pentest (nuclei)

| Catégorie | Checks |
|-----------|--------|
| Pentest | exécution de **nuclei** sur la cible ; chaque résultat (CVE, mauvaise config, panel exposé…) devient un `Finding`. Réglable par variables d'environnement : `NUCLEI_SEVERITY` (défaut `medium,high,critical`), `NUCLEI_TIMEOUT` (défaut 240 s), `NUCLEI_ARGS` (args bruts en plus), `SONAR_NUCLEI=off` pour le couper. nuclei est installé dans l'image Docker ; sans le binaire (dev local), le check se désactive proprement. |

Chaque finding a une sévérité (critique → conforme). Le score sur 100 et la note (A+ → F)
se calculent en pénalisant selon la gravité.

---

## Architecture

```
app.py                 FastAPI : sert la page + endpoint SSE + historique
db.py                  SQLite (historique des scans)
templates/index.html   dashboard Vue 3 (CDN, zéro build)
scanner/
  finding.py           Finding + sévérités + scoring  (le format de sortie commun)
  registry.py          décorateur @check
  runner.py            moteur : lance les checks en //, émet les events au fil de l'eau
  checks/              une famille de checks par fichier
```

Le principe : **tout est un `Finding`**, et le backend ne fait que *streamer du JSON*.
Le frontend est donc totalement interchangeable — si un jour tu veux changer la couche
d'affichage, tu ne touches qu'à `index.html`, rien côté serveur.

### Ajouter un check

Crée une fonction décorée, n'importe où dans `scanner/checks/`, et déclare le module
dans `scanner/checks/__init__.py`. C'est tout, le runner le prend automatiquement.

```python
from ..finding import Category, Finding, Severity
from ..registry import check

@check("hdr-coop", "Cross-Origin-Opener-Policy", Category.HEADERS)
async def coop(ctx):
    if ctx.response.headers.get("cross-origin-opener-policy"):
        return [Finding("hdr-coop", Category.HEADERS, Severity.PASS, "COOP présent")]
    return [Finding("hdr-coop", Category.HEADERS, Severity.LOW,
        "COOP absent", "…", "Ajoute `Cross-Origin-Opener-Policy: same-origin`.")]
```

`ctx` te donne : `ctx.url` (URL finale), `ctx.host`, `ctx.response` (réponse httpx avec
les en-têtes), `ctx.history` (redirections) et `ctx.client` si tu as besoin de refaire des requêtes.

---

## Roadmap

- **Phase 2 — actif léger** : ✅ complète — fichiers exposés (`.env`, `.git/HEAD`…), détection
  de technos/versions, contenu mixte, CORS, et en-têtes manquants sur les sous-ressources.
- **Phase 3 — vrai pentest** : ✅ implémentée — wrapper **nuclei** branché comme un simple check
  de plus (`scanner/checks/nuclei.py`). Il parse la sortie JSON de l'outil et la convertit en
  `Finding`. Aucune réécriture de moteur : le dashboard, le score et l'historique marchaient déjà.
  Piste restante : ajouter OWASP ZAP en mode API sur le même principe.

Tout ça se branche sans rien casser, parce que ça reste le même format de sortie.
