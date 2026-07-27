"""Shared passive-ingestion helpers for Phase 5 import formats."""

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from pydantic import ValidationError

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.models import (
    AuthenticationObservation,
    AuthenticationType,
    ChannelType,
    Observation,
    ObservationSource,
    ObservationStore,
)
from finsec.utils.redaction import redact_data, redact_named_value, redact_text
from finsec.utils.yaml_store import load_yaml, write_yaml


@dataclass(frozen=True)
class ObservationDraft:
    """Observation fields before workspace-local OBS identifiers are assigned."""

    source: ObservationSource
    source_reference: str
    source_fingerprint: str
    host: str
    method: str
    path: str
    authentication: AuthenticationObservation
    actor: str = "UNKNOWN"
    channel: ChannelType = "UNKNOWN"
    timestamp: str | None = None
    scheme: str | None = None
    query_parameters: dict[str, list[str]] = field(default_factory=dict)
    request_fields: list[str] = field(default_factory=list)
    response_fields: list[str] = field(default_factory=list)
    status_code: int | None = None
    content_type: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class PassiveIngestResult:
    """Shared result for passive external-format imports."""

    imported: int
    skipped: int
    relabeled: int
    total: int
    redacted_capture: Path


def load_observation_store(path: Path) -> ObservationStore:
    """Load the shared observation store with a concise user-facing error."""

    try:
        return ObservationStore.model_validate(load_yaml(path))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot read observation store {path}: {error}") from error


def append_observations(
    workspace: WorkspacePaths, drafts: list[ObservationDraft]
) -> tuple[int, int, int, int]:
    """Append observations and refresh corrected actor/channel assignments in place."""

    store = load_observation_store(workspace.observations)
    known = {item.source_fingerprint: item for item in store.observations}
    numbers = [
        int(match.group(1))
        for item in store.observations
        if (match := re.fullmatch(r"OBS-(\d+)", item.id)) is not None
    ]
    next_number = max(numbers, default=0) + 1
    imported = 0
    skipped = 0
    relabeled = 0
    for draft in drafts:
        existing = known.get(draft.source_fingerprint)
        if existing is not None:
            if existing.actor != draft.actor or existing.channel != draft.channel:
                existing.actor = draft.actor
                existing.channel = draft.channel
                relabeled += 1
            skipped += 1
            continue
        observation = Observation(
            id=f"OBS-{next_number:06d}",
            **draft.__dict__,
        )
        store.observations.append(observation)
        known[draft.source_fingerprint] = observation
        imported += 1
        next_number += 1
    write_yaml(workspace.observations, store.model_dump(mode="json", exclude_none=True))
    return imported, skipped, relabeled, len(store.observations)


def headers_from_any(value: Any) -> dict[str, str]:
    """Normalize mapping or name/value-list headers without retaining them in observations."""

    if isinstance(value, dict):
        return {str(name).lower(): str(item) for name, item in value.items()}
    result: dict[str, str] = {}
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                result[item["name"].lower()] = str(item.get("value", ""))
    return result


def authentication_from_headers(
    headers: dict[str, str], cookies_present: bool = False
) -> AuthenticationObservation:
    """Infer only the credential mechanism visible in supplied passive evidence."""

    types: set[AuthenticationType] = set()
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        types.add("bearer")
    elif authorization.lower().startswith("basic "):
        types.add("basic")
    elif authorization:
        types.add("mixed")
    if {"x-api-key", "api-key", "apikey", "x-client-secret"}.intersection(headers):
        types.add("api_key")
    if cookies_present or "cookie" in headers:
        types.add("cookie")
    if not types:
        observed_type: AuthenticationType = "none"
    elif len(types) == 1:
        observed_type = next(iter(types))
    else:
        observed_type = "mixed"
    return AuthenticationObservation(present=bool(types), observed_type=observed_type)


def field_paths(value: Any, prefix: str = "") -> set[str]:
    """Extract JSON field paths while discarding all values."""

    fields: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            fields.add(path)
            fields.update(field_paths(item, path))
    elif isinstance(value, list):
        for item in value:
            fields.update(field_paths(item, f"{prefix}[]" if prefix else "[]"))
    return fields


def json_field_paths(value: Any) -> list[str]:
    """Extract field paths from a decoded object or JSON text."""

    parsed = value
    if isinstance(value, bytes):
        try:
            parsed = value.decode("utf-8")
        except UnicodeDecodeError:
            return []
    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except json.JSONDecodeError:
            return []
    return sorted(field_paths(parsed)) if isinstance(parsed, dict | list) else []


def query_parameters(url: str) -> dict[str, list[str]]:
    """Extract redacted query parameters from a URL."""

    result: dict[str, list[str]] = {}
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        result.setdefault(name, []).append(redact_named_value(name, value))
    return result


def parse_raw_http(value: str) -> tuple[str, dict[str, str], str]:
    """Split a raw HTTP message into start line, normalized headers, and body."""

    normalized = value.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    lines = head.splitlines()
    start_line = lines[0] if lines else ""
    headers: dict[str, str] = {}
    current: str | None = None
    for line in lines[1:]:
        if line[:1].isspace() and current is not None:
            headers[current] = f"{headers[current]} {line.strip()}"
            continue
        name, delimiter, item = line.partition(":")
        if delimiter:
            current = name.strip().lower()
            headers[current] = item.strip()
    return start_line, headers, body if separator else ""


def safe_stem(path: Path) -> str:
    """Return a portable artifact stem."""

    return re.sub(r"[^A-Za-z0-9._-]+", "-", path.stem).strip("-") or "capture"


def source_digest(path: Path, maximum_bytes: int = 50_000_000) -> tuple[bytes, str]:
    """Read a bounded passive artifact and return content plus SHA-256 digest."""

    try:
        size = path.stat().st_size
    except OSError as error:
        raise FinsecError(f"Cannot inspect source file {path}: {error}") from error
    if size > maximum_bytes:
        raise FinsecError(f"Passive import is limited to {maximum_bytes} bytes per file.")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise FinsecError(f"Cannot read source file {path}: {error}") from error
    return raw, hashlib.sha256(raw).hexdigest()


def write_redacted_json(path: Path, value: Any) -> None:
    """Atomically persist a redacted JSON capture."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(redact_data(value), handle, indent=2, ensure_ascii=True)
        handle.write("\n")
    os.replace(temporary, path)


def redact_http_message(value: str) -> str:
    """Redact raw HTTP transcript text for traceability storage."""

    normalized = value.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    redacted_head = redact_text(head)
    if not separator:
        return redacted_head
    return f"{redacted_head}\n\n{redact_text(body)}"
