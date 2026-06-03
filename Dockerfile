# Image unique : un seul service Python (FastAPI + moteur de scan).
FROM python:3.12-slim

WORKDIR /app

# Dépendances d'abord pour profiter du cache Docker.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# nuclei (Phase 3) — moteur de pentest, installé pour l'architecture de l'image
# (le Pi est généralement en arm64). La dernière version est résolue dynamiquement.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl unzip jq ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) na=linux_amd64 ;; \
      arm64) na=linux_arm64 ;; \
      armhf) na=linux_arm ;; \
      *) echo "architecture non supportee pour nuclei : $arch" >&2; exit 1 ;; \
    esac; \
    ver="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name | sed 's/^v//')"; \
    curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${ver}/nuclei_${ver}_${na}.zip"; \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei; \
    rm /tmp/nuclei.zip; \
    nuclei -version

# Pré-télécharge les templates pour éviter le téléchargement au 1er scan (best effort).
RUN nuclei -update-templates -disable-update-check || true

# Puis le code.
COPY . .

# L'historique SQLite vit ici (monté en volume via docker-compose).
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
