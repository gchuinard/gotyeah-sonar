# Génération build-time du catalogue de remédiation (transform, pas trad)

Ce dossier outille la **génération hors-ligne** des entrées de remédiation, langue par
langue. **Aucun LLM n'est appelé au runtime** : on produit des fichiers YAML commités et
relisables. La même procédure se rejoue pour `en`, `de`, `es`… à partir des mêmes sources.

## Pipeline

1. **Sources** : `tools/zap_sources/zap_alerts.json` — faits ZAP (name, description,
   solution, cwe, refs) pour les alertes courantes. C'est le **grounding** : interdit
   d'inventer un correctif hors de ces sources.
2. **Couverture** : `python3 tools/gen_content.py zap --lang fr` liste les pluginIds non
   couverts ; `coverage --lang fr` liste les `(check_id, code)` maison sans entrée.
3. **Transform** (cette étape) : pour chaque alerte source, produire
   `content/zap/<pluginId>.<lang>.yaml` au **format maison** (voir prompt ci-dessous).
   Marquer `a_verifier: true` (généré, non relu).
4. **Validation** : `python3 tools/gen_content.py validate --lang fr` (schéma).
5. **Fallback** : toute alerte sans entrée traduite retombe sur le **texte d'origine ZAP**
   (anglais) via `source_text` → couverture toujours complète.

## Format d'une entrée `content/zap/<pluginId>.<lang>.yaml`

```yaml
alert:                          # le code des findings ZAP est toujours "alert"
  title: "..."                  # titre clair dans la langue cible
  detail: "..."                 # ce que ZAP a détecté, reformulé (pas de jargon brut)
  explanation: "..."            # c'est quoi (concis)
  why: "..."                    # le risque concret
  steps: ["...", "..."]         # pas-à-pas pour corriger, grounded sur la `solution` ZAP
  stacks:                       # variantes pertinentes (omettre les non pertinentes)
    nginx: "..."
    npm: "..."
    cloudflare: "..."
    apache: "..."
    nextjs: "..."
  ai_prompt: "..."              # UNIQUEMENT si corrigeable par un agent de code (headers,
                                # cookies, CORS, SRI, XSS, CSRF, config app/proxy).
                                # Interpole {host} et {stack}. Sinon, OMETTRE.
  refs: ["...", "https://cwe.mitre.org/data/definitions/<cwe>.html"]
  a_verifier: true              # généré, à relire
```

## Prompt de transformation (réutilisable, paramétré par `<LANG>`)

> Tu es un expert en sécurité web. À partir UNIQUEMENT de la source fournie (name,
> description, solution, cwe, refs de l'alerte OWASP ZAP — n'invente aucun correctif hors
> de ces faits), produis une entrée de remédiation en **<LANG>** au format maison ci-dessus.
> - `title`/`detail`/`explanation`/`why` : reformule clairement en <LANG>, sans recopier le
>   jargon ZAP, sans inventer.
> - `steps` : transpose la `solution` ZAP en pas-à-pas concret.
> - `stacks` : donne la configuration exacte pour les stacks pertinentes (Nginx, Nginx Proxy
>   Manager, Cloudflare, Apache, Next.js…). Si l'alerte n'est pas corrigeable par config
>   serveur (ex. XSS/SQLi/CSRF = code applicatif), mets les correctifs côté code.
> - `ai_prompt` : seulement si un agent de code peut corriger ; interpole {host} et {stack}.
> - `refs` : garde les refs source + ajoute le lien CWE.
> - `a_verifier: true`.
> Réfère-toi à `content/checks/headers.fr.yaml` pour le ton et le niveau de détail.

## Squelettes

`python3 tools/gen_content.py scaffold --lang <LANG>` écrit un squelette `a_verifier: true`
pour chaque alerte source manquante — point de départ à enrichir via le prompt ci-dessus.
