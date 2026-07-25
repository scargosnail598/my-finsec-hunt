"""Passive Burp XML and Caido JSON traffic importers."""

import base64
import binascii
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.ingest.common import (
    ObservationDraft,
    PassiveIngestResult,
    append_observations,
    authentication_from_headers,
    headers_from_any,
    json_field_paths,
    parse_raw_http,
    query_parameters,
    redact_http_message,
    safe_stem,
    source_digest,
    write_redacted_json,
)
from finsec.modeling.models import ChannelType
from finsec.utils.redaction import redact_text


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _xml_text(item: ET.Element, name: str) -> str:
    node = item.find(name)
    return node.text or "" if node is not None else ""


def _xml_http(item: ET.Element, name: str) -> str:
    node = item.find(name)
    if node is None or node.text is None:
        return ""
    if node.attrib.get("base64", "false").lower() != "true":
        return node.text
    try:
        encoded = "".join(node.text.split())
        return base64.b64decode(encoded, validate=True).decode("utf-8", errors="replace")
    except (ValueError, binascii.Error) as error:
        raise FinsecError(f"Invalid base64 {name} in Burp XML export.") from error


def ingest_burp_xml(
    source: Path,
    workspace: WorkspacePaths,
    actor: str = "UNKNOWN",
    channel: ChannelType = "UNKNOWN",
) -> PassiveIngestResult:
    """Import Burp XML history without retaining unredacted request or response data."""

    path = source.expanduser().resolve()
    if not path.is_file():
        raise FinsecError(f"Burp XML file not found: {path}")
    raw, digest = source_digest(path)
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", raw, flags=re.IGNORECASE):
        raise FinsecError("Burp XML containing DTD or entity declarations is not accepted.")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise FinsecError(f"Cannot parse Burp XML {path}: {error}") from error
    items = root.findall(".//item")
    if not items:
        raise FinsecError("Burp XML must contain at least one <item> entry.")
    capture_name = f"{safe_stem(path)}-{digest[:8]}-redacted.burp.json"
    capture_path = workspace.root / "observations" / "raw" / capture_name
    drafts: list[ObservationDraft] = []
    redacted_items: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        request_text = _xml_http(item, "request")
        response_text = _xml_http(item, "response")
        request_line, request_headers, request_body = parse_raw_http(request_text)
        response_line, response_headers, response_body = parse_raw_http(response_text)
        url = _xml_text(item, "url")
        if not url:
            protocol = _xml_text(item, "protocol") or "https"
            host = _xml_text(item, "host")
            target = request_line.split()[1] if len(request_line.split()) >= 2 else "/"
            url = f"{protocol}://{host}{target}"
        parsed = urlsplit(url)
        if not parsed.hostname:
            raise FinsecError(f"Burp item {index} has no usable request host.")
        method = _xml_text(item, "method") or (request_line.split()[0] if request_line else "GET")
        status = _integer(_xml_text(item, "status"))
        if status is None and response_line.startswith("HTTP/"):
            parts = response_line.split()
            status = _integer(parts[1]) if len(parts) > 1 else None
        drafts.append(
            ObservationDraft(
                source="BURP_XML",
                source_reference=f"observations/raw/{capture_name}#item-{index}",
                source_fingerprint=f"burp:{digest}:{index}",
                actor=actor,
                channel=channel,
                host=parsed.hostname.lower(),
                scheme=parsed.scheme.lower() or None,
                method=method.upper(),
                path=parsed.path or "/",
                query_parameters=query_parameters(url),
                request_fields=json_field_paths(request_body),
                response_fields=json_field_paths(response_body),
                status_code=status,
                content_type=response_headers.get("content-type") or _xml_text(item, "mimetype"),
                authentication=authentication_from_headers(request_headers),
            )
        )
        redacted_items.append(
            {
                "url": redact_text(url),
                "method": method.upper(),
                "request": redact_http_message(request_text),
                "response": redact_http_message(response_text),
            }
        )
    write_redacted_json(capture_path, {"source": "BURP_XML", "items": redacted_items})
    imported, skipped, total = append_observations(workspace, drafts)
    return PassiveIngestResult(imported, skipped, total, capture_path)


def _entries(document: Any) -> list[dict[str, Any]]:
    value = document
    if isinstance(document, dict):
        value = document.get("entries", document.get("requests", document.get("items")))
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise FinsecError("Caido JSON must be an array or contain entries, requests, or items.")
    return value


def _caido_request(entry: dict[str, Any]) -> tuple[str, str, dict[str, str], Any]:
    request_value = entry.get("request")
    request: dict[str, Any] = request_value if isinstance(request_value, dict) else entry
    raw = request.get("raw")
    if isinstance(raw, str):
        request_line, raw_headers, body = parse_raw_http(raw)
    else:
        request_line, raw_headers, body = "", {}, request.get("body", "")
    headers = {**raw_headers, **headers_from_any(request.get("headers"))}
    method = str(request.get("method") or entry.get("method") or "")
    if not method and request_line:
        method = request_line.split()[0]
    url = str(request.get("url") or entry.get("url") or "")
    if not url:
        scheme = str(request.get("scheme") or entry.get("scheme") or "https")
        host = str(request.get("host") or entry.get("host") or "")
        target = str(request.get("path") or entry.get("path") or "/")
        url = f"{scheme}://{host}{target}"
    return url, method.upper() or "GET", headers, body


def _caido_response(entry: dict[str, Any]) -> tuple[int | None, dict[str, str], Any]:
    response_value = entry.get("response")
    response: dict[str, Any] = response_value if isinstance(response_value, dict) else {}
    raw = response.get("raw")
    if isinstance(raw, str):
        status_line, raw_headers, body = parse_raw_http(raw)
    else:
        status_line, raw_headers, body = "", {}, response.get("body", "")
    headers = {**raw_headers, **headers_from_any(response.get("headers"))}
    status = _integer(response.get("status", response.get("statusCode")))
    if status is None and status_line.startswith("HTTP/"):
        parts = status_line.split()
        status = _integer(parts[1]) if len(parts) > 1 else None
    return status, headers, body


def ingest_caido_json(
    source: Path,
    workspace: WorkspacePaths,
    actor: str = "UNKNOWN",
    channel: ChannelType = "UNKNOWN",
) -> PassiveIngestResult:
    """Import a bounded Caido-style JSON exchange without retaining secrets."""

    path = source.expanduser().resolve()
    if not path.is_file():
        raise FinsecError(f"Caido JSON file not found: {path}")
    raw, digest = source_digest(path)
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FinsecError(f"Cannot parse Caido JSON {path}: {error}") from error
    entries = _entries(document)
    capture_name = f"{safe_stem(path)}-{digest[:8]}-redacted.caido.json"
    capture_path = workspace.root / "observations" / "raw" / capture_name
    drafts: list[ObservationDraft] = []
    for index, entry in enumerate(entries):
        url, method, request_headers, request_body = _caido_request(entry)
        status, response_headers, response_body = _caido_response(entry)
        parsed = urlsplit(url)
        if not parsed.hostname:
            raise FinsecError(f"Caido entry {index} has no usable request host.")
        drafts.append(
            ObservationDraft(
                source="CAIDO_JSON",
                source_reference=f"observations/raw/{capture_name}#entry-{index}",
                source_fingerprint=f"caido:{digest}:{index}",
                actor=actor,
                channel=channel,
                host=parsed.hostname.lower(),
                scheme=parsed.scheme.lower() or None,
                method=method,
                path=parsed.path or "/",
                query_parameters=query_parameters(url),
                request_fields=json_field_paths(request_body),
                response_fields=json_field_paths(response_body),
                status_code=status,
                content_type=response_headers.get("content-type"),
                authentication=authentication_from_headers(request_headers),
            )
        )
    write_redacted_json(capture_path, document)
    imported, skipped, total = append_observations(workspace, drafts)
    return PassiveIngestResult(imported, skipped, total, capture_path)
