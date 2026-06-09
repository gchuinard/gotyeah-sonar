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

Le flux émet aussi un **heartbeat** (commentaire SSE `: keepalive`) toutes les ~15 s tant
qu'aucun résultat n'arrive : pendant un check long (nuclei peut durer plusieurs minutes),
ça garde la connexion active pour qu'aucun proxy ne la coupe (nginx ~60 s, Cloudflare ~100 s).
Sans ça, le scan affichait les checks rapides puis « Connexion interrompue » avant la fin de nuclei.

---

## Accès — connexion par lien magique

Sonar est **authentifié** : pas de mot de passe, on se connecte par **lien magique**.
Tu saisis ton email sur `/login`, tu reçois un lien à usage unique (valable ~15 min),
le clic ouvre une session longue (cookie). Un compte ne peut **rien scanner** tant qu'il
n'a pas **vérifié un domaine par DNS**. Par défaut, l'admin échappe à ce gate (commodité) ;
ça se règle soit via l'env `SONAR_ADMIN_SCAN_ANY=false` (valeur initiale), soit **à chaud
depuis le dashboard** (interrupteur « Scan libre admin » dans le panneau « Mes domaines »,
visible uniquement pour l'admin). Mis sur off, l'admin doit vérifier ses domaines comme tout le monde.

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

## MCP — piloter Sonar depuis Claude

Un **serveur MCP** permet d'interroger tes rapports Sonar directement depuis Claude
(« liste mes domaines », « montre le dernier scan de X », « priorise les findings
critiques du scan `<id>` ») — et, en mode distant, de **lancer un scan**. Outils :

| Outil | Rôle | Mode |
|-------|------|------|
| `list_domains` | tes domaines vérifiés | local + distant |
| `list_scans(domain?)` | historique (id, score, note, date, sévérités) | local + distant |
| `get_report(scan_id, lang?)` | rapport complet rendu (findings + remédiation) | local + distant |
| `diff_scans(scan_a, scan_b)` | compare deux scans : corrigé / nouveau / persistant + delta de score | local + distant |
| `get_fix(scan_id, check_id?)` | remédiation actionnable : prompt IA + snippet par stack détectée | local + distant |
| `get_scan_status(scan_id)` | état léger d'un scan (en cours + progression, ou score) | **distant uniquement** |
| `run_scan(domain, profile?)` | **lance un scan** sur un domaine vérifié (action active) | **distant uniquement** |

**Boucle d'amélioration** : `run_scan` → `get_fix` (le prompt IA se colle dans Claude Code pour
corriger la config) → `run_scan` → `diff_scans` (« +12 points, CSP réglée, mais une nouvelle source
map est apparue »). `diff_scans`/`get_fix` sont du pur calcul sur les rapports (read-only).

`run_scan` est borné aux **domaines vérifiés** du compte (ou leurs sous-domaines), exactement
comme le dashboard, et **rate-limité** par compte (`SONAR_SCAN_RATE`, défaut 10 / 15 min — c'est
une action publique). Deux profils :

- `profile="full"` (défaut) — scan complet. Potentiellement long (nuclei/ZAP), donc **asynchrone** :
  l'outil attend un court délai (`SONAR_MCP_SCAN_WAIT`, défaut 25 s) puis renvoie soit le rapport
  complet, soit `{scan_id, status:"running"}`. Dans ce cas le scan continue en arrière-plan
  (résultat **persisté quoi qu'il arrive**) ; suis-le avec `get_scan_status(scan_id)` puis
  récupère-le via `get_report(scan_id)`.
- `profile="fast"` — passif/actif léger seulement (en-têtes, TLS, DNS, exposition), **sans**
  nuclei/ZAP/ports : quelques secondes, **résultat direct**. Idéal pour vérifier un fix d'en-tête.

Le scan apparaît dans l'historique du dashboard (« en cours… » puis sa note). Les outils portent
des **annotations MCP** (`readOnlyHint` sur les lectures, action signalée sur `run_scan`) pour que
le client affiche la bonne UX.

Deux façons de s'y brancher :

| Mode | Pour qui | Auth | Surface |
|------|----------|------|---------|
| **Distant** (`/mcp`) | **claude.ai (web)** & Claude Desktop (connecteur) | OAuth 2.1 fédéré vers ton IdP OIDC | endpoint public sur ton instance |
| **Local** (stdio) | **Claude Code** / Claude Desktop (process local) | jeton perso (PAT), **lecture seule** | rien de public, tourne sur ta machine |

---

### Mode distant — `/mcp` (OAuth, pour claude.ai web)

Ton instance Sonar expose elle-même un endpoint MCP **Streamable HTTP** sur
`https://<ton-domaine>/mcp`, que **claude.ai** peut ajouter comme connecteur. L'auth n'est
**pas maison** : elle est **déléguée à un IdP OIDC** (ici **Pocket ID**). FastMCP joue le
serveur d'autorisation côté claude.ai (enregistrement dynamique du client / DCR, PKCE,
metadata OAuth RFC 9728 + 8414) et **fédère le login vers l'IdP** ; il valide ensuite les
access tokens (JWT signés par l'IdP). L'identité (`email` du token, ou du *userinfo* en
repli) est mappée sur ton compte Sonar — donc accès **scopé à l'utilisateur** (l'admin voit
tout l'historique). Trois outils en lecture + `run_scan` (action), borné aux domaines vérifiés.

> ⚠️ C'est une **surface publique authentifiée** : elle est **désactivée par défaut**
> (`SONAR_MCP_REMOTE` non défini). Active-la seulement si tu veux brancher claude.ai web.

**1. Côté IdP (Pocket ID).** Crée un **client confidentiel** pré-enregistré avec pour
unique `redirect_uri` le callback de Sonar : `<SONAR_BASE_URL>/auth/callback`. Récupère
son `client_id` / `client_secret` et l'URL de découverte OIDC
(`…/.well-known/openid-configuration`).

**2. Côté Sonar (`.env`).** `SONAR_BASE_URL` doit être en **HTTPS** (OAuth exige un issuer
absolu ; sinon le MCP distant se désactive proprement au démarrage). Puis :

```bash
SONAR_MCP_REMOTE=on
SONAR_OIDC_CONFIG_URL=https://idp.gautierchuinard.com/.well-known/openid-configuration
SONAR_OIDC_CLIENT_ID=...
SONAR_OIDC_CLIENT_SECRET=...
```

Au démarrage, les logs confirment : `[mcp-remote] activé sur https://…/mcp (auth fédérée OIDC)`.
Le mount n'expose publiquement que `/mcp`, la metadata `/.well-known/oauth-*`, et les
endpoints OAuth `/authorize` · `/token` · `/register` · `/auth/callback` — tout le reste du
site garde la priorité de routage.

**3. Côté claude.ai.** Ajoute un **connecteur personnalisé** pointant sur
`https://<ton-domaine>/mcp`. Claude lance le flux OAuth : tu te connectes via ton IdP, et
les trois outils apparaissent. Pour révoquer : retire le connecteur (et/ou la session côté
IdP).

> Derrière Nginx Proxy Manager : `/mcp` et les `/.well-known/*` doivent passer **sans
> réécriture de Host** (le transport refuse un hôte non public — protection anti
> DNS-rebinding) ; vérifie que NPM transmet bien l'`Host` public.

---

### Mode local — stdio (PAT, pour Claude Code)

Variante qui tourne **en local sur ta machine** et parle à l'API Sonar avec un jeton —
**aucune nouvelle porte publique** n'est ouverte sur ton instance. Idéale pour Claude Code.

**1. Générer un jeton.** Dans le dashboard, panneau **« Jetons d'accès (MCP) »** →
*Générer*. Le secret (`sonar_pat_…`) n'est **affiché qu'une fois** : copie-le tout de
suite. Il est **lecture seule** (scope `scans:read`) : il peut lire tes domaines, ton
historique et tes rapports — **rien d'autre** (ni écriture, ni lancement de scan, ni
admin). Révocable à tout moment depuis le même panneau.

**2. Installer le serveur MCP** (sur ta machine, dans un venv) :

```bash
cd gotyeah_sonar
python3 -m venv .mcpvenv && . .mcpvenv/bin/activate
pip install -r requirements-mcp.txt
```

**3a. Claude Code** — ajoute le serveur (adapte les chemins absolus) :

```bash
claude mcp add sonar \
  --env SONAR_TOKEN=sonar_pat_TON_JETON \
  --env SONAR_BASE_URL=https://sonar.gautierchuinard.com \
  --env PYTHONPATH=/chemin/vers/gotyeah_sonar \
  -- /chemin/vers/gotyeah_sonar/.mcpvenv/bin/python -m sonar_mcp
```

**3b. Claude Desktop** — dans `claude_desktop_config.json` :

```json
{
  "mcpServers": {
    "sonar": {
      "command": "/chemin/vers/gotyeah_sonar/.mcpvenv/bin/python",
      "args": ["-m", "sonar_mcp"],
      "env": {
        "SONAR_TOKEN": "sonar_pat_TON_JETON",
        "SONAR_BASE_URL": "https://sonar.gautierchuinard.com",
        "PYTHONPATH": "/chemin/vers/gotyeah_sonar"
      }
    }
  }
}
```

Le serveur se lance via `python -m sonar_mcp` (transport **stdio**) ; `PYTHONPATH` pointe
sur le dépôt pour rendre le package `sonar_mcp` importable. Les deux variables
`SONAR_TOKEN` et `SONAR_BASE_URL` sont **obligatoires**. Pour révoquer l'accès : supprime
le jeton dans le panneau (le serveur reçoit alors un `401` au prochain appel).

---

## Ce que ça vérifie

### Phase 1 — passif (une seule requête)

| Catégorie | Checks |
|-----------|--------|
| En-têtes HTTP | CSP, HSTS (+ max-age), clickjacking (X-Frame-Options / frame-ancestors), nosniff, Referrer-Policy, Permissions-Policy, divulgation de version serveur, **COOP / COEP / CORP**, **Cache-Control des réponses sensibles** |
| Cookies | Secure / HttpOnly / SameSite sur chaque cookie posé |
| TLS | version négociée (refus < 1.2), validité et expiration du certificat, **protocoles obsolètes encore acceptés (TLS 1.0/1.1)** |
| DNS | SPF (+ **qualificateur `all` permissif `+all`/`?all`** et **SPF multiples** = permerror), DMARC (`p=none`, **`pct=0`** = appliqué à 0 %, **`sp=none`** = sous-domaines exposés), CAA, **DKIM, MTA-STS, TLS-RPT, DNSSEC**, **subdomain takeover** (CNAME dangling vers GitHub Pages / S3 / Heroku…). Les enregistrements e-mail sont cherchés sur le **domaine d'organisation (eTLD+1)**, pas le sous-domaine scanné. |

### Phase 2 — actif léger (quelques requêtes ciblées)

| Catégorie | Checks |
|-----------|--------|
| Exposition | fichiers sensibles exposés (`.env`, `.git/HEAD`, `.git/config`, sauvegardes, `.DS_Store`, `phpinfo`…), avec sonde anti soft-404 et **signature de contenu obligatoire** (jamais sur le seul code 200) |
| Fuites & well-known | **source maps** (`.js.map`), **doc d'API** (Swagger/OpenAPI), **introspection GraphQL**, **listing de répertoire** (autoindex), présence de `/.well-known/security.txt` |
| Méthodes HTTP | **TRACE** (XST) et verbes d'écriture (PUT/DELETE/PATCH) annoncés — lecture seule |
| CORS | origine reflétée, `*`, `null`, et combinaison dangereuse avec `Access-Control-Allow-Credentials` |
| Contenu mixte | ressources `http://` (actives vs passives) chargées sur une page `https://` |
| Sous-ressources | scripts/CSS même-origine servis sans `X-Content-Type-Options: nosniff` (échantillon récupéré activement) |
| Technologies | empreinte serveur / framework / CMS (en-têtes, cookies, balise meta generator) + alerte si une version est exposée |

### Réseau — services exposés

| Catégorie | Checks |
|-----------|--------|
| Ports / services | **connect-scan async borné** (lecture seule) d'une liste curée de services qui ne devraient jamais être publics (Redis, MongoDB, Elasticsearch, Docker API, MySQL, Postgres, RDP…). Scanne **toutes les IP non-CDN** résolues (un host mixte CDN+origine voit bien son origine sondée). **Garde-fou CDN** : derrière Cloudflare, on ne scanne pas l'edge du tiers (renseigne `SONAR_ORIGIN_IP` pour viser ton origine). Coupe-circuit `SONAR_PORTS=off`. |

> 🛡️ **Sûreté du moteur HTTP.** Une **garde anti-SSRF** bloque toute cible (ou redirection) qui
> résout vers une IP interne — privée, loopback, lien-local, et l'endpoint de métadonnées cloud
> `169.254.169.254` ; en homelab, `SONAR_ALLOW_PRIVATE=on` lève la garde pour scanner une IP
> interne **explicitement**. Le scan a aussi un **plafond de durée** (`SONAR_SCAN_DEADLINE`, défaut
> 300 s) : un check bloqué est interrompu et signalé (couverture incomplète → note plafonnée), le
> scan ne reste jamais « en cours » indéfiniment.

### Phase 3 — pentest (nuclei + OWASP ZAP)

| Catégorie | Checks |
|-----------|--------|
| Pentest (nuclei) | exécution de **nuclei** sur la cible ; chaque résultat (CVE, mauvaise config, panel exposé…) devient un `Finding`. Par défaut **cantonné aux familles exploitables** (bornées par la sévérité pour le volume) : `NUCLEI_TAGS` (défaut `cve,misconfig,exposure,exposed-panels,default-login,takeover` ; `NUCLEI_TAGS=all` lève le filtre). Les résultats sont **dédoublonnés par template** (un template qui matche N pages = un seul finding, avec le compte), et la sortie est lue **au fil de l'eau** : au timeout, les résultats déjà trouvés sont **conservés** (le scan est alors marqué incomplet et la note plafonnée). Autres réglages : `NUCLEI_SEVERITY` (défaut `medium,high,critical`), `NUCLEI_RATE_LIMIT` (req/s, défaut 50), `NUCLEI_TIMEOUT` (défaut 240 s), `NUCLEI_ARGS` (args bruts en plus), `SONAR_NUCLEI=off` pour le couper. nuclei est installé dans l'image Docker ; sans le binaire (dev local), le check se désactive proprement. |
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
sonar_mcp/             serveur MCP LOCAL (stdio) — client de l'API, auth par PAT
mcp_remote/            serveur MCP DISTANT (/mcp, Streamable HTTP) — OAuth délégué OIDC
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
- **MCP** : ✅ — deux transports. **Local** : serveur stdio `sonar_mcp/` via un jeton perso
  (PAT), **lecture seule**. **Distant (v1.2)** : endpoint `/mcp` (`mcp_remote/`) exposé par le
  serveur, auth **OAuth 2.1 déléguée à un IdP OIDC** (Pocket ID via l'`OAuthProxy` de FastMCP) —
  branché directement dans claude.ai web. **v1.3** : `run_scan` (action active, **asynchrone et
  persistée**, bornée aux domaines vérifiés, rate-limitée ; profils full/fast) + `get_scan_status`
  pour lancer/suivre un scan depuis claude.ai. **v1.4** : `diff_scans` (corrigé/nouveau/persistant
  + delta entre deux scans) et `get_fix` (remédiation actionnable + prompt IA par stack) — pur
  calcul partagé (`scan_compare`), dispo dans les **deux** transports. La boucle
  scanne → corrige → vérifie est désormais entièrement pilotable depuis Claude.

Tout ça se branche sans rien casser, parce que ça reste le même format de sortie.
