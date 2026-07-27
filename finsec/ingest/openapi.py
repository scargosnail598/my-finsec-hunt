"""Passive OpenAPI/Swagger ingestion into documented observations."""

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.ingest.common import (
    ObservationDraft,
    PassiveIngestResult,
    append_observations,
    safe_stem,
    source_digest,
)
from finsec.modeling.models import (
    AuthenticationObservation,
    AuthenticationType,
    ChannelType,
)
from finsec.utils.redaction import redact_text
from finsec.utils.yaml_store import write_yaml

HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}


def _document(raw: bytes, path: Path) -> dict[str, Any]:
    try:
        value = (
            json.loads(raw.decode("utf-8-sig"))
            if path.suffix.lower() == ".json"
            else yaml.safe_load(raw)
        )
    except (UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise FinsecError(f"Cannot parse OpenAPI document {path}: {error}") from error
    if not isinstance(value, dict) or not isinstance(value.get("paths"), dict):
        raise FinsecError("OpenAPI input must be a mapping containing a paths object.")
    if not value.get("openapi") and not value.get("swagger"):
        raise FinsecError("Document does not declare an OpenAPI or Swagger version.")
    return value


def _replace_server_variables(server: dict[str, Any]) -> str:
    url = str(server.get("url", ""))
    variables = server.get("variables")
    if isinstance(variables, dict):
        for name, value in variables.items():
            if isinstance(value, dict) and value.get("default") is not None:
                url = url.replace(f"{{{name}}}", str(value["default"]))
    return url


def _normalize_base_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise FinsecError("OpenAPI server URL is empty.")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlsplit(candidate)
    if not parsed.hostname:
        raise FinsecError(f"OpenAPI server URL has no host: {value}")
    if parsed.username or parsed.password:
        raise FinsecError("OpenAPI server URL must not contain credentials.")
    return candidate.rstrip("/")


def _servers(document: dict[str, Any], override: str | None) -> list[str]:
    if override:
        return [_normalize_base_url(override)]
    result: list[str] = []
    servers = document.get("servers")
    if isinstance(servers, list):
        for server in servers[:20]:
            if isinstance(server, dict):
                result.append(_normalize_base_url(_replace_server_variables(server)))
    if not result and isinstance(document.get("host"), str):
        schemes = document.get("schemes")
        scheme = str(schemes[0]) if isinstance(schemes, list) and schemes else "https"
        base_path = str(document.get("basePath", ""))
        result.append(_normalize_base_url(f"{scheme}://{document['host']}{base_path}"))
    if not result:
        raise FinsecError("OpenAPI has no absolute server URL; pass --base-url.")
    return sorted(set(result))


def _security_schemes(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    components = document.get("components")
    if isinstance(components, dict) and isinstance(components.get("securitySchemes"), dict):
        return {
            str(name): value
            for name, value in components["securitySchemes"].items()
            if isinstance(value, dict)
        }
    definitions = document.get("securityDefinitions")
    if isinstance(definitions, dict):
        return {str(name): value for name, value in definitions.items() if isinstance(value, dict)}
    return {}


def _authentication(
    document: dict[str, Any], operation: dict[str, Any]
) -> AuthenticationObservation:
    security = operation.get("security", document.get("security"))
    if security == [] or not isinstance(security, list):
        return AuthenticationObservation(present=False, observed_type="none")
    names = {
        str(name)
        for requirement in security
        if isinstance(requirement, dict)
        for name in requirement
    }
    schemes = _security_schemes(document)
    types: set[AuthenticationType] = set()
    for name in names:
        scheme = schemes.get(name, {})
        kind = str(scheme.get("type", "")).lower()
        value = str(scheme.get("scheme", "")).lower()
        location = str(scheme.get("in", "")).lower()
        if kind == "http" and value == "basic":
            types.add("basic")
        elif kind in {"oauth2", "openidconnect"} or value == "bearer":
            types.add("bearer")
        elif kind == "apikey" and location == "cookie":
            types.add("cookie")
        elif kind == "apikey":
            types.add("api_key")
        else:
            types.add("mixed")
    if not types:
        observed_type: AuthenticationType = "mixed" if names else "none"
    elif len(types) == 1:
        observed_type = next(iter(types))
    else:
        observed_type = "mixed"
    return AuthenticationObservation(present=bool(names), observed_type=observed_type)


def _schema_fields(schema: Any, prefix: str = "") -> set[str]:
    if not isinstance(schema, dict):
        return set()
    fields: set[str] = set()
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, value in properties.items():
            path = f"{prefix}.{name}" if prefix else str(name)
            fields.add(path)
            fields.update(_schema_fields(value, path))
    items = schema.get("items")
    if isinstance(items, dict):
        fields.update(_schema_fields(items, f"{prefix}[]" if prefix else "[]"))
    return fields


def _parameters(
    path_item: dict[str, Any], operation: dict[str, Any]
) -> tuple[dict[str, list[str]], set[str]]:
    values: list[Any] = []
    for owner in (path_item, operation):
        if isinstance(owner.get("parameters"), list):
            values.extend(owner["parameters"])
    query: dict[str, list[str]] = {}
    request_fields: set[str] = set()
    for parameter in values:
        if not isinstance(parameter, dict) or not isinstance(parameter.get("name"), str):
            continue
        location = str(parameter.get("in", ""))
        name = parameter["name"]
        if location == "query":
            query.setdefault(name, [])
        elif location in {"body", "formData"}:
            request_fields.add(name)
            request_fields.update(_schema_fields(parameter.get("schema"), name))
        elif location in {"header", "cookie"}:
            request_fields.add(f"{location}.{name}")
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict) and isinstance(request_body.get("content"), dict):
        for media in request_body["content"].values():
            if isinstance(media, dict):
                request_fields.update(_schema_fields(media.get("schema")))
    return query, request_fields


def _response_fields(operation: dict[str, Any]) -> tuple[set[str], str | None]:
    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return set(), None
    fields: set[str] = set()
    content_type: str | None = None
    for status, response in responses.items():
        if not str(status).startswith("2") or not isinstance(response, dict):
            continue
        content = response.get("content")
        if isinstance(content, dict):
            for media_type, media in content.items():
                content_type = content_type or str(media_type)
                if isinstance(media, dict):
                    fields.update(_schema_fields(media.get("schema")))
        fields.update(_schema_fields(response.get("schema")))
    return fields, content_type


def _operation_servers(
    document_servers: list[str], path_item: dict[str, Any], operation: dict[str, Any]
) -> list[str]:
    for owner in (operation, path_item):
        values = owner.get("servers")
        if isinstance(values, list) and values:
            result = [
                _normalize_base_url(_replace_server_variables(item))
                for item in values[:20]
                if isinstance(item, dict)
            ]
            if result:
                return sorted(set(result))
    return document_servers


def _full_url(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    base_path = parsed.path.rstrip("/")
    joined = f"{base_path}/{path.lstrip('/')}"
    authority = parsed.netloc
    return f"{parsed.scheme}://{authority}{joined}"


def ingest_openapi(
    source: Path,
    workspace: WorkspacePaths,
    base_url: str | None = None,
    channel: ChannelType = "PUBLIC_API",
) -> PassiveIngestResult:
    """Import documented operations as passive observations, never runtime confirmations."""

    path = source.expanduser().resolve()
    if not path.is_file():
        raise FinsecError(f"OpenAPI file not found: {path}")
    raw, digest = source_digest(path)
    document = _document(raw, path)
    default_servers = _servers(document, base_url)
    capture_name = f"{safe_stem(path)}-{digest[:8]}-redacted.openapi.yaml"
    capture_path = workspace.root / "observations" / "raw" / capture_name
    drafts: list[ObservationDraft] = []
    capture_operations: list[dict[str, Any]] = []
    paths = document["paths"]
    for documented_path, value in sorted(paths.items()):
        if not isinstance(documented_path, str) or not isinstance(value, dict):
            continue
        path_item = value
        for method, operation_value in sorted(path_item.items()):
            if method.lower() not in HTTP_METHODS or not isinstance(operation_value, dict):
                continue
            operation = operation_value
            query, request_fields = _parameters(path_item, operation)
            response_fields, content_type = _response_fields(operation)
            servers = _operation_servers(default_servers, path_item, operation)
            for server_index, server in enumerate(servers):
                url = _full_url(server, documented_path)
                parsed = urlsplit(url)
                fingerprint = f"openapi:{digest}:{method.lower()}:{documented_path}:{server_index}"
                authentication = _authentication(document, operation)
                capture_index = len(capture_operations)
                capture_operations.append(
                    {
                        "method": method.upper(),
                        "documented_path": documented_path,
                        "server": redact_text(server),
                        "authentication": authentication.model_dump(mode="json"),
                        "query_parameters": sorted(query),
                        "request_fields": sorted(request_fields),
                        "response_fields": sorted(response_fields),
                        "content_type": content_type,
                    }
                )
                drafts.append(
                    ObservationDraft(
                        source="OPENAPI",
                        source_reference=f"observations/raw/{capture_name}#/operations/{capture_index}",
                        source_fingerprint=fingerprint,
                        channel=channel,
                        host=parsed.hostname or "",
                        scheme=parsed.scheme,
                        method=method.upper(),
                        path=parsed.path or "/",
                        query_parameters=query,
                        request_fields=sorted(request_fields),
                        response_fields=sorted(response_fields),
                        content_type=content_type,
                        authentication=authentication,
                        notes="Documented in OpenAPI; runtime behavior is not observed.",
                    )
                )
    if not drafts:
        raise FinsecError("OpenAPI document contains no supported HTTP operations.")
    write_yaml(
        capture_path,
        {
            "source_format": "OpenAPI/Swagger",
            "source_digest": digest,
            "operations": capture_operations,
            "notes": (
                "Normalized documentation evidence; examples and credential values are omitted."
            ),
        },
    )
    imported, skipped, relabeled, total = append_observations(workspace, drafts)
    return PassiveIngestResult(imported, skipped, relabeled, total, capture_path)
