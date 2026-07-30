"""Passive Burp XML and Caido JSON traffic importers."""

import base64
import binascii
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
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


@dataclass(frozen=True, repr=False)
class BurpExchange:
    """One decoded Burp history item; raw HTTP values are intentionally omitted from repr."""

    index: int
    url: str
    method: str
    request_text: str = field(repr=False)
    response_text: str = field(repr=False)
    status: int | None = None
    content_type: str | None = None
    timestamp: str | None = None


@dataclass(frozen=True)
class BurpXmlDocument:
    """Validated Burp XML metadata and decoded exchanges."""

    path: Path
    digest: str
    exchanges: tuple[BurpExchange, ...] = field(repr=False)


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


def _doctype_end(raw: bytes, start: int) -> int:
    bracket_depth = 0
    quote: int | None = None
    for index in range(start, len(raw)):
        character = raw[index]
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in {ord('"'), ord("'")}:
            quote = character
        elif character == ord("["):
            bracket_depth += 1
        elif character == ord("]") and bracket_depth:
            bracket_depth -= 1
        elif character == ord(">") and bracket_depth == 0:
            return index + 1
    raise FinsecError("Burp XML contains an unterminated DOCTYPE declaration.")


def _without_unsafe_dtd(raw: bytes) -> bytes:
    """Strip Burp's schema-only internal DTD while rejecting entity and external declarations."""

    if re.search(rb"<!\s*ENTITY\b", raw, flags=re.IGNORECASE):
        raise FinsecError("Burp XML containing entity declarations is not accepted.")
    matches = list(re.finditer(rb"<!\s*DOCTYPE\b", raw, flags=re.IGNORECASE))
    if not matches:
        return raw
    if len(matches) != 1:
        raise FinsecError("Burp XML must not contain multiple DOCTYPE declarations.")
    start = matches[0].start()
    end = _doctype_end(raw, start)
    declaration = raw[start:end]
    if re.search(rb"\b(?:SYSTEM|PUBLIC)\b", declaration, flags=re.IGNORECASE):
        raise FinsecError("Burp XML containing an external DTD is not accepted.")
    return raw[:start] + raw[end:]


def load_burp_xml(source: Path) -> BurpXmlDocument:
    """Load a Burp history export without resolving DTDs or XML entities."""

    path = source.expanduser().resolve()
    if not path.is_file():
        raise FinsecError(f"Burp XML file not found: {path}")
    raw, digest = source_digest(path)
    parseable = _without_unsafe_dtd(raw)
    try:
        root = ET.fromstring(parseable)
    except ET.ParseError as error:
        raise FinsecError(f"Cannot parse Burp XML {path}: {error}") from error
    items = root.findall(".//item")
    if not items:
        raise FinsecError("Burp XML must contain at least one <item> entry.")
    exchanges: list[BurpExchange] = []
    for index, item in enumerate(items):
        request_text = _xml_http(item, "request")
        response_text = _xml_http(item, "response")
        request_line, _request_headers, _request_body = parse_raw_http(request_text)
        response_line, response_headers, _response_body = parse_raw_http(response_text)
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
        exchanges.append(
            BurpExchange(
                index=index,
                url=url,
                method=method.upper(),
                request_text=request_text,
                response_text=response_text,
                status=status,
                content_type=response_headers.get("content-type")
                or _xml_text(item, "mimetype")
                or None,
                timestamp=_xml_text(item, "time") or None,
            )
        )
    return BurpXmlDocument(path=path, digest=digest, exchanges=tuple(exchanges))


def ingest_burp_xml(
    source: Path,
    workspace: WorkspacePaths,
    actor: str = "UNKNOWN",
    channel: ChannelType = "UNKNOWN",
    *,
    capture_auth: bool = False,
    auth_candidate: int | None = None,
    auth_observed_renewal: bool = False,
) -> PassiveIngestResult:
    """Import Burp XML history without retaining unredacted request or response data."""

    document = load_burp_xml(source)
    capture_name = f"{safe_stem(document.path)}-{document.digest[:8]}-redacted.burp.json"
    capture_path = workspace.root / "observations" / "raw" / capture_name
    drafts: list[ObservationDraft] = []
    redacted_items: list[dict[str, Any]] = []
    for exchange in document.exchanges:
        _request_line, request_headers, request_body = parse_raw_http(exchange.request_text)
        _response_line, response_headers, response_body = parse_raw_http(exchange.response_text)
        parsed = urlsplit(exchange.url)
        host = parsed.hostname
        if host is None:
            raise FinsecError(f"Burp item {exchange.index} has no usable request host.")
        drafts.append(
            ObservationDraft(
                source="BURP_XML",
                source_reference=f"observations/raw/{capture_name}#item-{exchange.index}",
                source_fingerprint=f"burp:{document.digest}:{exchange.index}",
                actor=actor,
                channel=channel,
                host=host.lower(),
                scheme=parsed.scheme.lower() or None,
                method=exchange.method,
                path=parsed.path or "/",
                query_parameters=query_parameters(exchange.url),
                request_fields=json_field_paths(request_body),
                response_fields=json_field_paths(response_body),
                status_code=exchange.status,
                content_type=response_headers.get("content-type") or exchange.content_type,
                authentication=authentication_from_headers(request_headers),
                timestamp=exchange.timestamp,
            )
        )
        redacted_items.append(
            {
                "url": redact_text(exchange.url),
                "method": exchange.method,
                "request": redact_http_message(exchange.request_text),
                "response": redact_http_message(exchange.response_text),
            }
        )
    write_redacted_json(capture_path, {"source": "BURP_XML", "items": redacted_items})
    imported, skipped, relabeled, total = append_observations(workspace, drafts)
    authentication_status: str | None = None
    credential_profile_ref: str | None = None
    if capture_auth:
        if actor == "UNKNOWN":
            raise FinsecError("--capture-auth requires an explicitly configured actor.")
        from finsec.auth.service import capture_from_burp

        authentication, _ = capture_from_burp(
            workspace,
            actor,
            document.path,
            candidate_number=auth_candidate,
            observed_renewal=auth_observed_renewal,
        )
        authentication_status = authentication.status
        credential_profile_ref = authentication.profile_ref
    return PassiveIngestResult(
        imported,
        skipped,
        relabeled,
        total,
        capture_path,
        authentication_status,
        credential_profile_ref,
    )


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
    imported, skipped, relabeled, total = append_observations(workspace, drafts)
    return PassiveIngestResult(imported, skipped, relabeled, total, capture_path)
