"""HAR ingestion that creates factual observations and a redacted capture copy."""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from pydantic import ValidationError

from finsec.captures.domain import Capture, CaptureAssignment, CaptureSourceType
from finsec.captures.service import associate_capture
from finsec.config.workspace import WorkspacePaths
from finsec.errors import HarFormatError
from finsec.ingest.har_io import load_har_json
from finsec.modeling.models import (
    AuthenticationObservation,
    AuthenticationType,
    ChannelType,
    Observation,
    ObservationStore,
)
from finsec.utils.redaction import redact_data, redact_named_value, redact_text
from finsec.utils.yaml_store import load_yaml, write_yaml


@dataclass(frozen=True)
class IngestResult:
    """Summary returned after a HAR import."""

    imported: int
    skipped: int
    relabeled: int
    total: int
    redacted_har: Path
    authentication_status: str | None = None
    credential_profile_ref: str | None = None
    capture: Capture | None = None


def _headers(items: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(items, list):
        return result
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            k = item["name"].lower()
            v = str(item.get("value", ""))
            if k in result:
                result[k] = f"{result[k]}, {v}" if k != "cookie" else f"{result[k]}; {v}"
            else:
                result[k] = v
    return result


def _authentication(request: dict[str, Any]) -> AuthenticationObservation:
    headers = _headers(request.get("headers"))
    types: set[AuthenticationType] = set()
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        types.add("bearer")
    elif authorization.lower().startswith("basic "):
        types.add("basic")
    elif authorization:
        types.add("mixed")

    api_key_headers = {"x-api-key", "api-key", "apikey", "x-client-secret"}
    if api_key_headers.intersection(headers):
        types.add("api_key")
    if headers.get("cookie") or request.get("cookies"):
        types.add("cookie")

    if not types:
        observed_type: AuthenticationType = "none"
    elif len(types) == 1:
        observed_type = next(iter(types))
    else:
        observed_type = "mixed"
    return AuthenticationObservation(present=bool(types), observed_type=observed_type)


def _json_value(text: str | None) -> Any | None:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _field_paths(value: Any, prefix: str = "") -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            fields.add(path)
            fields.update(_field_paths(item, path))
    elif isinstance(value, list):
        for item in value:
            fields.update(_field_paths(item, f"{prefix}[]" if prefix else "[]"))
    return fields


def _request_fields(request: dict[str, Any]) -> list[str]:
    post_data = request.get("postData")
    if not isinstance(post_data, dict):
        return []

    fields: set[str] = set()
    params = post_data.get("params")
    if isinstance(params, list):
        fields.update(
            str(item["name"])
            for item in params
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )

    text = post_data.get("text")
    parsed = _json_value(text if isinstance(text, str) else None)
    if parsed is not None:
        fields.update(_field_paths(parsed))
    return sorted(fields)


def _response_fields(response: dict[str, Any]) -> list[str]:
    content = response.get("content")
    if not isinstance(content, dict) or content.get("encoding") == "base64":
        return []
    text = content.get("text")
    parsed = _json_value(text if isinstance(text, str) else None)
    return sorted(_field_paths(parsed)) if parsed is not None else []


def _query_parameters(request: dict[str, Any], url: str) -> dict[str, list[str]]:
    pairs: list[tuple[str, str]] = []
    query_string = request.get("queryString")
    if isinstance(query_string, list):
        pairs.extend(
            (str(item["name"]), str(item.get("value", "")))
            for item in query_string
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )
    if not pairs:
        pairs.extend(parse_qsl(urlsplit(url).query, keep_blank_values=True))

    result: dict[str, list[str]] = {}
    for name, value in pairs:
        result.setdefault(name, []).append(redact_named_value(name, value))
    return result


def _content_type(response: dict[str, Any]) -> str | None:
    content = response.get("content")
    if isinstance(content, dict) and content.get("mimeType"):
        return str(content["mimeType"])
    return _headers(response.get("headers")).get("content-type")


def _parse_entry(
    entry: Any,
    observation_id: str,
    source_reference: str,
    fingerprint: str,
    actor: str,
    channel: ChannelType,
    sequence_position: int,
) -> Observation:
    if not isinstance(entry, dict):
        raise HarFormatError("Every HAR log entry must be an object.")
    request = entry.get("request")
    response = entry.get("response")
    if not isinstance(request, dict) or not isinstance(response, dict):
        raise HarFormatError("Each HAR entry must contain request and response objects.")

    url = request.get("url")
    if not isinstance(url, str) or not url:
        raise HarFormatError("Each HAR request must contain a URL.")
    parsed_url = urlsplit(url)
    if not parsed_url.hostname:
        raise HarFormatError("HAR request URL has no host.")

    status = response.get("status")
    status_code: int | None = None
    if isinstance(status, int | float | str):
        try:
            status_code = int(status)
        except (ValueError, TypeError, OverflowError):
            status_code = None
    request_headers = _headers(request.get("headers"))
    response_headers = _headers(response.get("headers"))
    redirect = response.get("redirectURL")
    return Observation(
        id=observation_id,
        timestamp=entry.get("startedDateTime"),
        source_reference=source_reference,
        source_fingerprint=fingerprint,
        capture_identity=source_reference.split("#", 1)[0],
        session_identity=f"{actor}:{source_reference.split('#', 1)[0]}",
        sequence_position=sequence_position,
        actor=actor,
        channel=channel,
        host=parsed_url.hostname.lower(),
        scheme=parsed_url.scheme.lower() or None,
        method=str(request.get("method", "GET")).upper(),
        path=parsed_url.path or "/",
        concrete_url=redact_text(url),
        query_parameters=_query_parameters(request, url),
        request_fields=_request_fields(request),
        response_fields=_response_fields(response),
        status_code=status_code,
        content_type=_content_type(response),
        relevant_header_names=sorted(
            {
                name
                for name in [*request_headers, *response_headers]
                if name
                in {
                    "content-type",
                    "idempotency-key",
                    "location",
                    "referer",
                    "x-correlation-id",
                    "x-request-id",
                }
            }
        ),
        redirect_target=redact_text(redirect) if isinstance(redirect, str) and redirect else None,
        redaction_metadata=["capture redacted before persistence", "credential values removed"],
        authentication=_authentication(request),
    )


def _load_store(path: Path) -> ObservationStore:
    try:
        return ObservationStore.model_validate(load_yaml(path))
    except (OSError, ValidationError) as error:
        raise HarFormatError(f"Cannot read observation store {path}: {error}") from error


def _next_observation_number(observations: list[Observation]) -> int:
    numbers = [
        int(match.group(1))
        for item in observations
        if (match := re.fullmatch(r"OBS-(\d+)", item.id))
    ]
    return max(numbers, default=0) + 1


def _write_redacted_har(path: Path, data: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=True)
        handle.write("\n")
    os.replace(temporary, path)


def ingest_har(
    har_path: Path,
    workspace: WorkspacePaths,
    actor: str = "UNKNOWN",
    channel: ChannelType = "UNKNOWN",
    *,
    capture_auth: bool = False,
    auth_candidate: int | None = None,
    auth_observed_renewal: bool = False,
    capture_assignment: CaptureAssignment | None = None,
) -> IngestResult:
    """Import one HAR file without retaining its unredacted content."""

    source_path, raw, document = load_har_json(har_path)

    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise HarFormatError("HAR must contain a log.entries array.")

    digest = hashlib.sha256(raw).hexdigest()
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "-", source_path.stem).strip("-") or "capture"
    redacted_name = f"{safe_stem}-{digest[:8]}-redacted.har"
    redacted_path = workspace.redacted_har / redacted_name
    workspace.redacted_har.mkdir(parents=True, exist_ok=True)
    _write_redacted_har(redacted_path, redact_data(document))

    store = _load_store(workspace.observations)
    known_fingerprints = {item.source_fingerprint: item for item in store.observations}
    next_number = _next_observation_number(store.observations)
    imported = 0
    skipped = 0
    relabeled = 0

    for index, entry in enumerate(entries):
        fingerprint = hashlib.sha256(f"{digest}:{index}".encode()).hexdigest()
        existing = known_fingerprints.get(fingerprint)
        if existing is not None:
            if existing.actor != actor or existing.channel != channel:
                existing.actor = actor
                existing.channel = channel
                if existing.capture_id is not None:
                    existing.session_identity = f"{actor}:{existing.capture_id}"
                elif existing.capture_identity is not None:
                    existing.session_identity = f"{actor}:{existing.capture_identity}"
                relabeled += 1
            skipped += 1
            continue
        observation_id = f"OBS-{next_number:06d}"
        source_reference = f"observations/har/{redacted_name}#entry-{index}"
        observation = _parse_entry(
            entry,
            observation_id,
            source_reference,
            fingerprint,
            actor,
            channel,
            index,
        )
        store.observations.append(observation)
        known_fingerprints[fingerprint] = observation
        imported += 1
        next_number += 1

    write_yaml(workspace.observations, store.model_dump(mode="json", exclude_none=True))
    authentication_status: str | None = None
    credential_profile_ref: str | None = None
    if capture_auth:
        if actor == "UNKNOWN":
            raise HarFormatError("--capture-auth requires an explicitly configured actor.")
        from finsec.auth.service import capture_from_har

        authentication, _ = capture_from_har(
            workspace,
            actor,
            source_path,
            candidate_number=auth_candidate,
            observed_renewal=auth_observed_renewal,
        )
        authentication_status = authentication.status
        credential_profile_ref = authentication.profile_ref
    capture = associate_capture(
        workspace,
        source_type=CaptureSourceType.HAR,
        source_file=source_path,
        source_fingerprint=digest,
        redacted_capture=redacted_path,
        actor_id=actor,
        assignment=capture_assignment,
    )
    return IngestResult(
        imported=imported,
        skipped=skipped,
        relabeled=relabeled,
        total=len(store.observations),
        redacted_har=redacted_path,
        authentication_status=authentication_status,
        credential_profile_ref=credential_profile_ref,
        capture=capture,
    )
