#!/bin/bash
# Déploiement de Sonar sur le Pi. Ce script ne se lance pas à la main : il est
# exécuté par /usr/local/sbin/gotyeah-deploy (commande forcée de la clé
# SSH_KEY dans authorized_keys), depuis /home/pi/deploiement/gotyeah-sonar (copie de ce dépôt public), après un git fetch.
# Variables reçues : CIBLE (commit à déployer), AVANT (commit en place).
# Le script est lu dans le commit CIBLE : le modifier sur main suffit.
# CIBLE est le commit que la CI a testé (deploy.yml l'envoie) : le Pi refuse de le
# déployer s'il n'est plus la pointe de main.
set -euo pipefail

# Le runner installait jusqu'ici exactement le commit testé (checkout de ce commit) :
# la copie se cale donc dessus, quel que soit son état.
git reset --hard "$CIBLE"

# Dossier du service, comme le faisait l'ancien rsync depuis GitHub, avec les mêmes
# exclusions : data/ (base SQLite), .env et le .git déjà présent dans ce dossier ne sont
# ni écrasés ni supprimés par --delete.
REMOTE_DIR=/home/pi/sites/gotyeah-sonar
mkdir -p "$REMOTE_DIR"
rsync -a --delete \
  --exclude='.git' \
  --exclude='data' \
  --exclude='__pycache__' \
  --exclude='*.db' \
  --exclude='.env' \
  ./ "$REMOTE_DIR/"

cd "$REMOTE_DIR"

# On construit l'image AVANT de toucher au conteneur (25/09) : l'ancienne version
# supprimait d'abord le conteneur (docker rm -f) puis construisait, si bien que le
# site restait coupé pendant tout le build, et pour de bon si le build échouait.
# Désormais l'ancien conteneur sert jusqu'à ce que la nouvelle image soit prête, et
# `up -d` ne fait plus que le recréer sur cette image (quelques secondes).
docker compose build

# Un conteneur "sonar" né ailleurs (ex. ancien déploiement depuis un autre dossier)
# bloquerait le nom ET le port 8000, container_name étant fixe : on ne le retire
# que si compose ne le reconnaît pas comme le sien, juste avant de recréer.
if [ -n "$(docker ps -aq -f 'name=^sonar$')" ] && [ -z "$(docker compose ps -aq sonar)" ]; then
  echo 'conteneur sonar orphelin (hors de ce projet compose) : suppression'
  docker rm -f sonar
fi
docker compose up -d
docker image prune -f

# Le déploiement n'est réussi que si l'application RÉPOND. Sans cette étape, un
# conteneur qui démarre puis meurt aussitôt passe pour un succès : `docker compose
# up -d` rend 0 dès que le conteneur est CRÉÉ, il ne dit rien de ce qui tourne
# dedans.
#
# La sonde tourne DANS le conteneur : pas de réseau Docker à connaître. Elle vérifie
# le CHAMP `status` plutôt que la présence du mot « ok » quelque part dans le corps,
# pour qu'une page d'erreur qui contiendrait ce mot ne passe pas pour une application
# saine.
#
# Six tentatives espacées de 5 s plutôt qu'un `sleep` fixe : sur le Pi, une image
# fraîchement reconstruite met un temps variable à servir sa première requête. En cas
# d'échec on imprime les dernières lignes de journal, qui remontent dans le job GitHub.
for tentative in 1 2 3 4 5 6; do
  if docker exec sonar python -c 'import json, urllib.request; d = json.load(urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=5)); print(d); assert d["status"] == "ok"'; then exit 0; fi
  echo "tentative $tentative sans reponse, nouvel essai dans 5 s"
  sleep 5
done
echo 'sonar ne repond pas sur /healthz apres 30 s'
docker logs --tail 40 sonar
exit 1
