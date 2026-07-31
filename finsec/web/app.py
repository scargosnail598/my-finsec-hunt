"""Starlette application serving the bundled FinSec Hunt research cockpit."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from finsec.errors import FinsecError, WorkspaceError
from finsec.web.operations import (
    IngestRunRequest,
    SetupWorkspaceRequest,
    WebOperations,
    WorkspaceDeleteRequest,
)
from finsec.web.service import (
    SnapshotCache,
    WorkspaceCatalog,
    WorkspaceSnapshot,
    authentication_payload,
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
    capture_root: Path | None = None,
) -> Starlette:
    """Create a local UI with bounded setup, ingest, and workspace-retirement writes."""

    effective_workspace_root = (
        selected_workspace.expanduser().resolve().parent
        if selected_workspace is not None
        else workspace_root
    )
    catalog = WorkspaceCatalog(effective_workspace_root, selected_workspace)
    snapshot_cache = SnapshotCache()
    operations = WebOperations(effective_workspace_root, capture_root)
    static_root = Path(str(files("finsec.web").joinpath("static")))
    index_path = static_root / "index.html"

    async def index(_: Request) -> Response:
        return FileResponse(index_path)

    async def workspaces(_: Request) -> Response:
        return JSONResponse({"workspaces": catalog.list_workspaces()})

    async def setup_workspace(request: Request) -> Response:
        document = SetupWorkspaceRequest.model_validate(await _json_document(request))
        try:
            result = await run_in_threadpool(operations.setup_workspace, document)
        except WorkspaceError as error:
            return JSONResponse({"error": str(error)}, status_code=409)
        catalog.register(Path(result["workspace"]["path"]))
        return JSONResponse(result, status_code=201)

    async def overview(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(workspace_overview(snapshot))

    async def hypotheses(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(hypotheses_payload(snapshot))

    async def authentication(request: Request) -> Response:
        snapshot = _snapshot(catalog, snapshot_cache, request)
        return JSONResponse(authentication_payload(snapshot))

    async def deletion_preview(request: Request) -> Response:
        paths = catalog.resolve(request.path_params["workspace_key"])
        purge = request.query_params.get("mode") == "purge"
        return JSONResponse(
            await run_in_threadpool(operations.deletion_preview, paths, purge=purge)
        )

    async def remove_workspace(request: Request) -> Response:
        _require_destructive_write(request)
        document = WorkspaceDeleteRequest.model_validate(await _json_document(request))
        key = request.path_params["workspace_key"]
        paths = catalog.resolve(key)
        result = await run_in_threadpool(operations.delete_workspace, paths, document)
        snapshot_cache.invalidate(paths)
        catalog.unregister(key)
        return JSONResponse(result)

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

    async def ingest_state(request: Request) -> Response:
        paths = catalog.resolve(request.path_params["workspace_key"])
        return JSONResponse(await run_in_threadpool(operations.ingest_state, paths))

    async def initialize_ingest(request: Request) -> Response:
        _require_local_write(request)
        paths = catalog.resolve(request.path_params["workspace_key"])
        result = await run_in_threadpool(operations.initialize_capture, paths)
        return JSONResponse(result)

    async def upload_har(request: Request) -> Response:
        _require_local_write(request)
        if request.headers.get("x-finsec-reviewed") != "true":
            raise FinsecError("Confirm that the HAR is authorized and sanitized before upload.")
        filename = request.query_params.get("filename", "")
        content = await _bounded_body(request, maximum=50 * 1024 * 1024)
        paths = catalog.resolve(request.path_params["workspace_key"])
        result = await run_in_threadpool(operations.store_har, paths, filename, content)
        return JSONResponse(result, status_code=201)

    async def run_ingest(request: Request) -> Response:
        document = IngestRunRequest.model_validate(await _json_document(request))
        paths = catalog.resolve(request.path_params["workspace_key"])
        result = await run_in_threadpool(operations.run_ingest, paths, document)
        return JSONResponse(result)

    routes = [
        Route("/", endpoint=index),
        Route("/api/workspaces", endpoint=workspaces),
        Route("/api/setup", endpoint=setup_workspace, methods=["POST"]),
        Route("/api/workspaces/{workspace_key:str}/overview", endpoint=overview),
        Route("/api/workspaces/{workspace_key:str}/authentication", endpoint=authentication),
        Route(
            "/api/workspaces/{workspace_key:str}/deletion-preview",
            endpoint=deletion_preview,
        ),
        Route(
            "/api/workspaces/{workspace_key:str}/delete",
            endpoint=remove_workspace,
            methods=["POST"],
        ),
        Route("/api/workspaces/{workspace_key:str}/hypotheses", endpoint=hypotheses),
        Route(
            "/api/workspaces/{workspace_key:str}/hypotheses/{hypothesis_id:str}",
            endpoint=hypothesis,
        ),
        Route("/api/workspaces/{workspace_key:str}/endpoints", endpoint=endpoints),
        Route("/api/workspaces/{workspace_key:str}/model", endpoint=model),
        Route("/api/workspaces/{workspace_key:str}/evidence", endpoint=evidence),
        Route("/api/workspaces/{workspace_key:str}/ingest", endpoint=ingest_state),
        Route(
            "/api/workspaces/{workspace_key:str}/ingest/initialize",
            endpoint=initialize_ingest,
            methods=["POST"],
        ),
        Route(
            "/api/workspaces/{workspace_key:str}/ingest/upload",
            endpoint=upload_har,
            methods=["POST"],
        ),
        Route(
            "/api/workspaces/{workspace_key:str}/ingest/run",
            endpoint=run_ingest,
            methods=["POST"],
        ),
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
    app.add_exception_handler(WorkspaceError, _workspace_error)
    app.add_exception_handler(ValidationError, _validation_error)
    return app


def _snapshot(
    catalog: WorkspaceCatalog,
    cache: SnapshotCache,
    request: Request,
) -> WorkspaceSnapshot:
    return cache.get(catalog.resolve(request.path_params["workspace_key"]))


async def _finsec_error(_: Request, error: Exception) -> JSONResponse:
    return JSONResponse({"error": str(error)}, status_code=400)


async def _workspace_error(_: Request, error: Exception) -> JSONResponse:
    return JSONResponse({"error": str(error)}, status_code=404)


async def _validation_error(_: Request, error: Exception) -> JSONResponse:
    return JSONResponse({"error": str(error)}, status_code=422)


def _require_local_write(request: Request) -> None:
    if request.headers.get("x-finsec-ui") != "1":
        raise FinsecError("Local Web UI write header is required.")


def _require_destructive_write(request: Request) -> None:
    if request.headers.get("x-finsec-destructive") != "workspace-delete":
        raise FinsecError("Explicit workspace-deletion header is required.")


async def _json_document(request: Request) -> Any:
    _require_local_write(request)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise FinsecError("Web UI writes require application/json.")
    body = await _bounded_body(request, maximum=256 * 1024)
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FinsecError("Request body is not valid JSON.") from error


async def _bounded_body(request: Request, *, maximum: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as error:
            raise FinsecError("Invalid request content length.") from error
        if declared > maximum:
            raise FinsecError("Request body exceeds the local Web UI safety limit.")
    body = await request.body()
    if len(body) > maximum:
        raise FinsecError("Request body exceeds the local Web UI safety limit.")
    return body


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
