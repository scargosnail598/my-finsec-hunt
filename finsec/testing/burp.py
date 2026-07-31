"""Export approved structured plans as secret-free Burp Repeater requests."""

import hashlib
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import yaml

from finsec import __version__
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.execution.policy import ReviewedRequestExport, review_request_export
from finsec.testing.domain import StructuredRequest

HTTP_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
EXPORT_DIRECTORY = re.compile(r"^export-v(\d+)$")
RESERVED_HEADERS = {"connection", "content-length", "host", "transfer-encoding"}


@dataclass(frozen=True)
class BurpExportResult:
    """One immutable or reused Burp request export revision."""

    root: Path
    manifest: Path
    requests: tuple[Path, ...]
    created: bool


def _safe_value(value: str, label: str) -> str:
    if any(character in value for character in ("\r", "\n", "\0")):
        raise FinsecError(f"Burp export refused: {label} contains unsafe control bytes.")
    return value


def _token(value: str, fallback: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper() or fallback


def _secret_placeholder(request: StructuredRequest, header: str) -> str:
    actor = _token(request.actor, "ACTOR")
    component = _token(header, "CREDENTIAL")
    return f"<FINSEC_RUNTIME_SECRET:{actor}:{component}>"


def _host_header(request: StructuredRequest) -> str:
    host = _safe_value(request.host, f"request {request.id} host")
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 443 if request.scheme == "https" else 80
    if request.port is not None and request.port != default_port:
        return f"{authority}:{request.port}"
    return authority


def _request_target(request: StructuredRequest) -> str:
    pairs = [(name, value) for name, values in request.query_parameters.items() for value in values]
    query = urlencode(pairs)
    target = f"{request.path}?{query}" if query else request.path
    return _safe_value(target, f"request {request.id} target")


def render_burp_request(request: StructuredRequest) -> str:
    """Render one structured request as a paste-ready HTTP/1.1 message."""

    if request.method not in {"GET", "HEAD"} or request.body is not None:
        raise FinsecError("Burp export refused: only bodyless GET and HEAD requests are supported.")
    removed = {name.lower() for name in request.remove_headers}
    headers: list[tuple[str, str]] = [("Host", _host_header(request))]
    used = {"host"}
    for name, value in request.headers.items():
        normalized = name.lower()
        if not HTTP_HEADER_NAME.fullmatch(name):
            raise FinsecError(f"Burp export refused: request {request.id} has an invalid header.")
        if normalized in RESERVED_HEADERS:
            raise FinsecError(
                f"Burp export refused: request {request.id} stores reserved header {name}."
            )
        if normalized in removed:
            continue
        if normalized in used:
            raise FinsecError(f"Burp export refused: request {request.id} repeats header {name}.")
        headers.append((name, _safe_value(value, f"request {request.id} header {name}")))
        used.add(normalized)
    for secret in request.runtime_secrets:
        normalized = secret.header.lower()
        if normalized in removed:
            continue
        if not HTTP_HEADER_NAME.fullmatch(secret.header) or normalized in RESERVED_HEADERS:
            raise FinsecError(
                f"Burp export refused: request {request.id} has an invalid credential header."
            )
        if normalized in used:
            raise FinsecError(
                f"Burp export refused: request {request.id} repeats header {secret.header}."
            )
        headers.append((secret.header, _secret_placeholder(request, secret.header)))
        used.add(normalized)
    headers.append(("Connection", "close"))
    request_line = f"{request.method} {_request_target(request)} HTTP/1.1"
    return "\r\n".join([request_line, *(f"{name}: {value}" for name, value in headers), "", ""])


def _filename(index: int, request: StructuredRequest) -> str:
    request_id = re.sub(r"[^a-z0-9]+", "-", request.id.lower()).strip("-") or "request"
    return f"{index:02d}-{request_id}.http"


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _reviewed_export(workspace: WorkspacePaths, hypothesis_id: str) -> ReviewedRequestExport:
    try:
        return review_request_export(workspace, hypothesis_id)
    except FinsecError as error:
        detail = str(error)
        for prefix in ("Execution refused: ", "Approval refused: ", "Request export refused: "):
            if detail.startswith(prefix):
                detail = detail.removeprefix(prefix)
                break
        raise FinsecError(f"Burp export refused: {detail}") from error


def _render_export(reviewed: ReviewedRequestExport) -> tuple[dict[str, str], str]:
    approval = reviewed.plan.approval
    if approval is None:
        raise FinsecError("Burp export refused: the plan has no checksum-bound approval.")
    files: dict[str, str] = {}
    request_records: list[dict[str, Any]] = []
    for index, request in enumerate(reviewed.plan.requests, start=1):
        filename = _filename(index, request)
        content = render_burp_request(request)
        files[filename] = content
        request_records.append(
            {
                "file": filename,
                "sha256": _digest(content),
                "id": request.id,
                "role": request.role,
                "actor": request.actor,
                "channel": request.channel,
                "method": request.method,
                "scheme": request.scheme,
                "host": request.host,
                "port": request.port,
                "path": request.path,
                "mutations": [
                    mutation.model_dump(mode="json", exclude_none=True)
                    for mutation in request.mutations
                ],
            }
        )
    manifest = {
        "version": 1,
        "format": "burp_repeater_raw_http",
        "tool_version": __version__,
        "hypothesis_id": reviewed.hypothesis.id,
        "plan_id": reviewed.plan.id,
        "plan_checksum": reviewed.plan_checksum,
        "target_policy_checksum": reviewed.target_policy_checksum,
        "approval": {
            "approved_by": approval.approved_by,
            "approved_at": approval.approved_at,
        },
        "execution_default": reviewed.plan.execution_default,
        "request_budget": reviewed.plan.execution.request_budget,
        "mutation_dimensions": reviewed.plan.execution.mutation_dimensions,
        "runtime_credentials": "PLACEHOLDERS_ONLY",
        "requests": request_records,
        "stop_conditions": reviewed.plan.execution.stop_conditions,
        "warnings": [
            "These files contain no credential values.",
            "Insert only the current credential for the request's controlled actor inside Burp.",
            "Sending a request from Burp is manual active execution outside FinSec Hunt.",
            "Follow the approved request budget and stop conditions.",
        ],
    }
    manifest_text = yaml.safe_dump(
        manifest,
        sort_keys=False,
        allow_unicode=False,
        default_flow_style=False,
    )
    return files, manifest_text


def _revisions(root: Path) -> list[tuple[int, Path]]:
    revisions: list[tuple[int, Path]] = []
    if not root.is_dir():
        return revisions
    for path in root.iterdir():
        match = EXPORT_DIRECTORY.fullmatch(path.name)
        if path.is_dir() and match is not None:
            revisions.append((int(match.group(1)), path))
    return sorted(revisions)


def _matches(path: Path, files: dict[str, str], manifest: str) -> bool:
    manifest_path = path / "manifest.yaml"
    try:
        if not manifest_path.is_file() or manifest_path.read_text(encoding="utf-8") != manifest:
            return False
        return all(
            (path / name).is_file() and (path / name).read_bytes().decode("utf-8") == content
            for name, content in files.items()
        )
    except (OSError, UnicodeError):
        return False


def export_burp_requests(workspace: WorkspacePaths, hypothesis_id: str) -> BurpExportResult:
    """Write or reuse an immutable approved Burp Repeater request export."""

    reviewed = _reviewed_export(workspace, hypothesis_id)
    files, manifest = _render_export(reviewed)
    root = workspace.burp_exports_for(reviewed.hypothesis.id)
    if root.exists() and not root.is_dir():
        raise FinsecError(f"Burp export refused: export root is not a directory: {root}")
    revisions = _revisions(root)
    for _, path in revisions:
        if _matches(path, files, manifest):
            return BurpExportResult(
                root=path,
                manifest=path / "manifest.yaml",
                requests=tuple(path / name for name in files),
                created=False,
            )

    root.mkdir(parents=True, exist_ok=True)
    version = max((number for number, _ in revisions), default=0) + 1
    destination = root / f"export-v{version}"
    temporary = root / f".export-v{version}.tmp"
    if temporary.exists() or destination.exists():
        raise FinsecError("Burp export refused: the next export revision already exists.")
    temporary.mkdir()
    try:
        for name, content in files.items():
            (temporary / name).write_text(content, encoding="utf-8", newline="")
        (temporary / "manifest.yaml").write_text(manifest, encoding="utf-8", newline="\n")
        os.replace(temporary, destination)
    except OSError as error:
        shutil.rmtree(temporary, ignore_errors=True)
        raise FinsecError(f"Burp export failed while writing revision: {error}") from error
    return BurpExportResult(
        root=destination,
        manifest=destination / "manifest.yaml",
        requests=tuple(destination / name for name in files),
        created=True,
    )
