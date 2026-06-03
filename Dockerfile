# Image unique : un seul service Python (FastAPI + moteur de scan).
FROM python:3.12-slim

WORKDIR /app

# Dépendances d'abord pour profiter du cache Docker.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Puis le code.
COPY . .

# L'historique SQLite vit ici (monté en volume via docker-compose).
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
