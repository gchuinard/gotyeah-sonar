# ---------------------------------------------------------------------------
# Builder : télécharge + VÉRIFIE nuclei. Les outils de build (curl/unzip) restent
# dans ce stage et ne polluent pas l'image finale.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS nuclei-builder

# Version ÉPINGLÉE (build reproductible : plus de résolution "latest" via l'API GitHub,
# qui rendait deux builds non identiques et cassait au moindre rate-limit). Bump volontaire
# après lecture des release notes. Le checksum officiel est vérifié ci-dessous.
ARG NUCLEI_VERSION=3.9.0

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl unzip ca-certificates; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) na=linux_amd64 ;; \
      arm64) na=linux_arm64 ;; \
      armhf) na=linux_arm ;; \
      *) echo "architecture non supportee pour nuclei : $arch" >&2; exit 1 ;; \
    esac; \
    base="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}"; \
    zip="nuclei_${NUCLEI_VERSION}_${na}.zip"; \
    cd /tmp; \
    curl -fsSL -o "$zip" "${base}/${zip}"; \
    curl -fsSL -o checksums.txt "${base}/nuclei_${NUCLEI_VERSION}_checksums.txt"; \
    grep " ${zip}\$" checksums.txt | sha256sum -c -; \
    unzip -o "$zip" -d /usr/local/bin nuclei; \
    /usr/local/bin/nuclei -version

# ---------------------------------------------------------------------------
# Image finale : un seul service Python (FastAPI + moteur de scan).
# ---------------------------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

# Dépendances Python d'abord (cache Docker).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ca-certificates : requêtes HTTPS du moteur de scan + téléchargement des templates nuclei.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Binaire nuclei vérifié (depuis le builder), sans les outils de build.
COPY --from=nuclei-builder /usr/local/bin/nuclei /usr/local/bin/nuclei

# Pré-télécharge les templates nuclei DANS l'image (sinon « no templates provided » au 1er scan).
RUN set -eux; \
    nuclei -update-templates; \
    [ -n "$(ls -A /root/nuclei-templates 2>/dev/null)" ]

# Puis le code.
COPY . .

# L'historique SQLite vit ici (monté en volume via docker-compose).
RUN mkdir -p /app/data

EXPOSE 8000

# Healthcheck natif (pas de curl/wget dans l'image) : GET /login en local.
HEALTHCHECK --interval=30s --timeout=4s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=3).status==200 else 1)"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
