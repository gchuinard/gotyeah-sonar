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

## Accès — connexion par lien magique

Sonar est **authentifié** : pas de mot de passe, on se connecte par **lien magique**.
Tu saisis ton email sur `/login`, tu reçois un lien à usage unique (valable ~15 min),
le clic ouvre une session longue (cookie). Un compte ne peut **rien scanner** tant qu'il
n'a pas **vérifié un domaine par DNS** (l'admin, lui, scanne sans restriction).

**Première connexion / porte de secours.** Définis `SONAR_ADMIN_EMAIL` : au démarrage, un
lien de login one-time est imprimé dans les logs — récupère-le avec :

```bash
docker logs sonar | grep -A2 "PORTE DE SECOURS"
```

Tu l'ouvres dans le navigateur et te voilà connecté en admin, même sans email configuré.

**Emails (Brevo).** Tant que `BREVO_API_KEY` est vide, les liens magiques sont **loggés**
au lieu d'être envoyés (pratique pour démarrer). Renseigne ta clé Brevo + `SONAR_MAIL_FROM`
dans le `.env` pour l'envoi réel.

**Inscription.** `SONAR_OPEN_REGISTRATION=true` ouvre l'inscription ; `false` (défaut) =
sur invitation (un email inconnu ne reçoit pas de lien, mais la réponse reste générique pour
ne pas divulguer quels comptes existent). ⚠️ Renseigne `SONAR_BASE_URL` (URL publique) pour
que les liens dans les emails soient corrects derrière le proxy. Tout est dans `.env` (voir
`.env.example`).

**Vérifier un domaine (débloque le scan).** Dans le dashboard, panneau « Mes domaines »,
ajoute un domaine : Sonar te donne un enregistrement **TXT** à publier sur ta zone DNS —
`sonar-verify=<token>` sur l'apex, **ou** `<token>` sur `_sonar-verify.<domaine>`. Clique
**Vérifier** : si le TXT est trouvé, le domaine **et ses sous-domaines** deviennent
scannables. (La propagation DNS peut prendre quelques minutes.)

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

### Phase 3 — pentest (nuclei + OWASP ZAP)

| Catégorie | Checks |
|-----------|--------|
| Pentest (nuclei) | exécution de **nuclei** sur la cible ; chaque résultat (CVE, mauvaise config, panel exposé…) devient un `Finding`. Réglable par variables d'environnement : `NUCLEI_SEVERITY` (défaut `medium,high,critical`), `NUCLEI_TIMEOUT` (défaut 240 s), `NUCLEI_ARGS` (args bruts en plus), `SONAR_NUCLEI=off` pour le couper. nuclei est installé dans l'image Docker ; sans le binaire (dev local), le check se désactive proprement. |
| Pentest (ZAP) | dialogue avec un démon **OWASP ZAP** via son API REST (baseline passif par défaut : accès URL + spider borné + scan passif → alertes). Chaque alerte ZAP devient un `Finding`. Sans démon configuré, le check se désactive proprement. Voir [OWASP ZAP](#owasp-zap-optionnel). |

Chaque finding a une sévérité (critique → conforme). Le score sur 100 et la note (A+ → F)
se calculent en pénalisant selon la gravité.

#### OWASP ZAP (optionnel)

ZAP est une grosse appli Java : on ne l'embarque pas dans l'image Sonar, on lui parle via
son API. Lance-le en démon à côté (snippet à ajouter à ton `docker-compose.yml`) :

```yaml
  zap:
    image: zaproxy/zap-stable
    container_name: zap
    command: >
      zap.sh -daemon -host 0.0.0.0 -port 8090
      -config api.key=${ZAP_API_KEY}
      -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
    networks: [default]
    restart: unless-stopped
```

puis renseigne, sur le service `sonar`, les variables d'environnement :

| Variable | Rôle | Défaut |
|----------|------|--------|
| `ZAP_API_URL` | base de l'API ZAP (ex. `http://zap:8090`) | *(vide → check ignoré)* |
| `ZAP_API_KEY` | clé d'API ZAP | — |
| `ZAP_ACTIVE` | `on` pour lancer aussi un scan **actif** (intrusif) | passif |
| `ZAP_SPIDER_MAX` | nb max de pages explorées par le spider | `10` |
| `ZAP_TIMEOUT` | délai global du scan ZAP (s) | `240` |
| `SONAR_ZAP` | `off` pour désactiver même si `ZAP_API_URL` est défini | — |

---

## Architecture

```
app.py                 FastAPI : page + SSE + historique + langue (rend les findings)
db.py                  SQLite (historique des scans, sous forme STRUCTURÉE)
auth.py / mailer.py    auth lien magique + vérif domaine DNS ; envoi des emails
templates/index.html   dashboard Vue 3 (CDN, zéro build) — cartes de remédiation + langue
scanner/
  finding.py           Finding (détection structurée) + sévérités + scoring
  registry.py          décorateur @check
  runner.py            moteur : lance les checks en //, émet les events au fil de l'eau
  checks/              une famille de checks par fichier — DÉTECTION pure (code + params)
  i18n/                couche de PRÉSENTATION : (check_id, code, lang) -> texte rendu
content/               catalogue de remédiation (YAML) :
                         checks/<famille>.<lang>.yaml   (checks maison)
                         zap/<pluginId>.<lang>.yaml     (alertes ZAP transformées)
locales/ui/<lang>.json libellés d'interface (chrome : boutons, panneaux, bannières…)
tools/                 génération build-time du catalogue (validate / coverage / transform)
```

Le principe : **tout est un `Finding`**, et le backend ne fait que *streamer du JSON*.
Depuis l'i18n, ce `Finding` est **structuré** (il porte un `code` de résultat et des
`params`, pas de texte humain) ; la couche `scanner/i18n/` le **rend** dans la langue
demandée à partir des fichiers de `content/` et `locales/`. L'historique stocke la forme
structurée → un scan archivé se **re-rend dans n'importe quelle langue**.

### Ajouter un check

Crée une fonction décorée, n'importe où dans `scanner/checks/`, et déclare le module
dans `scanner/checks/__init__.py`. Le check ne fait que de la **détection** : il renvoie
un `code` (+ `params`/`evidence`), jamais de texte. Le texte (titre, détail, remédiation)
vit dans le catalogue YAML, indexé par `(check_id, code)`.

```python
# scanner/checks/coop.py — détection pure
from ..finding import Category, Finding, Severity
from ..registry import check

@check("hdr-coop", "Cross-Origin-Opener-Policy", Category.HEADERS)
async def coop(ctx):
    if ctx.response.headers.get("cross-origin-opener-policy"):
        return [Finding("hdr-coop", Category.HEADERS, Severity.PASS, code="ok")]
    return [Finding("hdr-coop", Category.HEADERS, Severity.LOW, code="absent")]
```

```yaml
# content/checks/headers.fr.yaml — présentation (texte + remédiation)
hdr-coop:
  absent:
    title: "Cross-Origin-Opener-Policy absent"
    detail: "Sans COOP, la page partage son contexte de navigation avec les popups."
    recommendation: "Ajoute `Cross-Origin-Opener-Policy: same-origin`."
    explanation: "…"          # c'est quoi
    why: "…"                  # le risque concret
    steps: ["…"]              # pas-à-pas
    stacks: { nginx: "add_header Cross-Origin-Opener-Policy \"same-origin\" always;" }
    ai_prompt: "… {host} … {stack} …"   # si corrigeable par un agent de code
    refs: ["https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"]
    a_verifier: false
  ok:
    title: "Cross-Origin-Opener-Policy présent"
    why: "Le contexte de navigation est isolé des fenêtres tierces."
```

`ctx` te donne : `ctx.url` (URL finale), `ctx.host`, `ctx.response` (réponse httpx avec
les en-têtes), `ctx.history` (redirections) et `ctx.client` si tu as besoin de refaire des requêtes.

### i18n & remédiation

**Détection / présentation séparées.** Les checks produisent des données structurées ;
la couche `scanner/i18n/` rend le texte dans la langue active (préférence utilisateur →
cookie → `Accept-Language` → `fr`). Le rendu est **côté serveur** : le front affiche du JSON
déjà localisé, et le gros catalogue ne part jamais dans le navigateur.

**Chaîne de fallback stricte** (jamais de clé brute, couverture toujours complète) :

```
langue demandée → fr → (ZAP/nuclei : texte d'origine anglais de l'outil) → défaut sûr
```

**Cartes de remédiation (façon GTmetrix).** Chaque finding non conforme se déplie :
explication, pourquoi ça compte, étapes, variantes selon la stack (Nginx / NPM / Cloudflare /
framework — la stack détectée est surlignée), preuve, **prompt IA prêt à copier** (pour les
problèmes corrigeables par un agent de code), références. Les `PASS` n'affichent qu'une ligne
« pourquoi c'est conforme ».

**Ajouter une langue = déposer des fichiers, ZÉRO code :**

1. `locales/ui/<lang>.json` — les libellés d'interface (copie `fr.json`, traduis).
2. `content/checks/<famille>.<lang>.yaml` et `content/zap/<pluginId>.<lang>.yaml` — le
   contenu de remédiation (ce qui manque retombe proprement sur `fr`, puis sur l'anglais ZAP).

Le sélecteur de langue apparaît automatiquement dans la topbar dès qu'une 2ᵉ langue existe.

**Regénérer / enrichir un catalogue.** Tout est figé en fichiers commités — **aucun LLM au
runtime**. L'outillage build-time :

```bash
python3 tools/gen_content.py validate --lang fr   # schéma de tout le catalogue
python3 tools/gen_content.py coverage --lang fr   # (check_id, code) maison sans entrée
python3 tools/gen_content.py zap --lang fr        # alertes ZAP (tools/zap_sources) à couvrir
python3 tools/gen_content.py scaffold --lang fr   # squelettes a_verifier:true à enrichir
```

Le catalogue ZAP est **transformé** (pas traduit) à partir de `tools/zap_sources/zap_alerts.json`,
strictement grounded sur ces sources ; les entrées générées non relues portent `a_verifier: true`.
Procédure complète (réutilisable pour `en`, `de`…) dans `tools/PROMPTS.md`.

---

## Roadmap

- **Phase 2 — actif léger** : ✅ complète — fichiers exposés (`.env`, `.git/HEAD`…), détection
  de technos/versions, contenu mixte, CORS, et en-têtes manquants sur les sous-ressources.
- **Phase 3 — vrai pentest** : ✅ implémentée — wrappers **nuclei** (`scanner/checks/nuclei.py`)
  et **OWASP ZAP** en mode API (`scanner/checks/zap.py`), chacun branché comme un simple check
  de plus qui convertit la sortie de l'outil en `Finding`. Aucune réécriture de moteur : le
  dashboard, le score et l'historique marchaient déjà.
- **i18n & remédiation** : ✅ — détection/présentation séparées, contenu multilingue (FR pour
  l'instant), cartes de remédiation dépliables + prompt IA, historique re-rendable dans
  n'importe quelle langue. Ajouter une langue ne demande que des fichiers de locale. Le
  catalogue ZAP est transformé en FR (fallback propre sur l'anglais d'origine pour le reste).

Tout ça se branche sans rien casser, parce que ça reste le même format de sortie.
