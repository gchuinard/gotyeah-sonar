"""Couche web : sert la page et transforme le flux du moteur en SSE.

Volontairement mince — toute la logique est dans `scanner/`. La page d'accueil
est servie telle quelle (pas de templating : Vue gère le rendu côté client).
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

import db
from scanner.runner import run_scan

BASE = Path(__file__).parent
PAGE = (BASE / "templates" / "index.html").read_text(encoding="utf-8")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="Sonar", lifespan=lifespan)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(PAGE)


@app.get("/api/scan/stream")
async def scan_stream(target: str = Query(..., min_length=3)):
    async def gen():
        summary = None
        findings = None
        async for ev in run_scan(target):
            if ev["event"] == "done":
                summary = ev["data"]
                findings = ev.get("_findings", [])
            yield _sse(ev["event"], ev["data"])
        if summary is not None:
            scan_id = db.save_scan(summary.get("target", target), summary, findings or [])
            yield _sse("saved", {"id": scan_id})

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        # Indispensable derrière Nginx / Nginx Proxy Manager : sans ça, le proxy
        # bufferise la réponse et le flux n'arrive qu'à la toute fin.
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)


@app.get("/api/history")
async def history():
    return JSONResponse(db.list_scans())


@app.get("/api/scan/{scan_id}")
async def scan_detail(scan_id: str):
    data = db.get_scan(scan_id)
    if not data:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(data)
