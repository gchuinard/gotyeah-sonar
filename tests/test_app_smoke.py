"""Smoke test de la couche web : l'app s'importe et expose ses routes."""
from fastapi import FastAPI


def test_app_and_routes():
    import app
    assert isinstance(app.app, FastAPI)
    paths = {r.path for r in app.app.routes}
    assert {"/", "/api/scan/stream", "/api/history"} <= paths


def test_sse_format():
    import app
    out = app._sse("finding", {"a": 1})
    assert out.startswith("event: finding\n")
    assert "data: " in out and out.endswith("\n\n")
