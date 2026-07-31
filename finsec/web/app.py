"""Starlette application serving the bundled FinSec Hunt research cockpit."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from finsec.errors import FinsecError
from finsec.web.service import (
    SnapshotCache,
    WorkspaceCatalog,
    WorkspaceSnapshot,
    document_payload,
    documents_payload,
    endpoints_payload,
    evidence_payload,
    hypotheses_payload,
    hypothesis_detail,
    model_payload,
    report_payload,
    workspace_overview,
)


def create_app(
    workspace_root: Path = Path("workspaces"),
    selected_workspace: Path | None = None,
) -> Starlette:
    """Create a read-only local application for one workspace root or exact workspace."""

    catalog = WorkspaceCatalog(workspace_root, selected_workspace)
    snapshot_cache = SnapshotCache()
    static_root = Path(str(files("finsec.web").joinpath("static")))
    index_path = static_root / "index.html"

    async def index(_: Request) -> Response:
        return FileResponse(index_path)

    async def workspaces(_: Request) -> Response:
        return JSONResponse({"workspaces": catalog.list_workspaces()})

    async def overview(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(workspace_overview(snapshot))

    async def hypotheses(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(hypotheses_payload(snapshot))

    async def hypothesis(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(hypothesis_detail(snapshot, request.path_params["hypothesis_id"]))

    async def endpoints(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(endpoints_payload(snapshot))

    async def model(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(model_payload(snapshot))

    async def evidence(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(evidence_payload(snapshot))

    async def documents(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(documents_payload(snapshot))

    async def document(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(document_payload(snapshot, request.path_params["document_id"]))

    async def report(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(report_payload(snapshot, request.path_params["filename"]))

    routes = [
        Route("/", endpoint=index),
        Route("/api/workspaces", endpoint=workspaces),
        Route("/api/workspaces/{workspace_key:str}/overview", endpoint=overview),
        Route("/api/workspaces/{workspace_key:str}/hypotheses", endpoint=hypotheses),
        Route(
            "/api/workspaces/{workspace_key:str}/hypotheses/{hypothesis_id:str}",
            endpoint=hypothesis,
        ),
        Route("/api/workspaces/{workspace_key:str}/endpoints", endpoint=endpoints),
        Route("/api/workspaces/{workspace_key:str}/model", endpoint=model),
        Route("/api/workspaces/{workspace_key:str}/evidence", endpoint=evidence),
        Route("/api/workspaces/{workspace_key:str}/documents", endpoint=documents),
        Route(
            "/api/workspaces/{workspace_key:str}/documents/{document_id:str}",
            endpoint=document,
        ),
        Route("/api/workspaces/{workspace_key:str}/reports/{filename:str}", endpoint=report),
        Mount("/assets", app=StaticFiles(directory=static_root), name="assets"),
    ]
    app = Starlette(
        debug=False,
        routes=routes,
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=_security_headers)],
    )
    app.add_exception_handler(FinsecError, _finsec_error)
    app.add_exception_handler(ValidationError, _validation_error)
    return app


def _snapshot(
    catalog: WorkspaceCatalog,
    cache: SnapshotCache,
    request: Request,
) -> WorkspaceSnapshot:
    return cache.get(catalog.resolve(request.path_params["workspace_key"]))


async def _finsec_error(_: Request, error: Exception) -> JSONResponse:
    return JSONResponse({"error": str(error)}, status_code=404)


async def _validation_error(_: Request, error: Exception) -> JSONResponse:
    return JSONResponse({"error": str(error)}, status_code=422)


async def _security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
    try:
        response = await call_next(request)
    except HTTPException as error:
        response = JSONResponse({"error": error.detail}, status_code=error.status_code)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response
