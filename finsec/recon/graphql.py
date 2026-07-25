"""Passive GraphQL SDL and introspection inventory generation."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.ingest.common import safe_stem, source_digest, write_redacted_json
from finsec.modeling.merge import merge_generated_records, stable_fingerprint
from finsec.recon.domain import GraphQLStore
from finsec.utils.redaction import redact_text
from finsec.utils.yaml_store import load_yaml, write_yaml

TOKEN_PATTERN = re.compile(r"[_A-Za-z][_0-9A-Za-z]*|[!$():=@\[\]{},]")
TYPE_NAME_PATTERN = re.compile(r"^[_A-Za-z][_0-9A-Za-z]*$")


@dataclass(frozen=True)
class GraphQLImportResult:
    """Summary of one passive GraphQL schema import."""

    operations: int
    added: int
    updated: int
    conflicts: tuple[str, ...]
    inventory_path: Path
    redacted_capture: Path


def _normalize_endpoint(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = value.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise FinsecError("GraphQL --endpoint must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password:
        raise FinsecError("GraphQL --endpoint must not contain credentials.")
    return redact_text(candidate)


def _mask_sdl(value: str) -> str:
    """Remove comments and string contents while preserving structural tokens."""

    result = list(value)
    index = 0
    while index < len(value):
        if value.startswith('"""', index):
            end = value.find('"""', index + 3)
            end = len(value) - 3 if end < 0 else end
            for position in range(index, min(end + 3, len(result))):
                result[position] = " "
            index = end + 3
            continue
        if value[index] == '"':
            position = index + 1
            escaped = False
            while position < len(value):
                character = value[position]
                if character == '"' and not escaped:
                    position += 1
                    break
                escaped = character == "\\" and not escaped
                if character != "\\":
                    escaped = False
                position += 1
            for masked in range(index, position):
                result[masked] = " "
            index = position
            continue
        if value[index] == "#":
            end = value.find("\n", index)
            end = len(value) if end < 0 else end
            for position in range(index, end):
                result[position] = " "
            index = end
            continue
        index += 1
    return "".join(result)


def _matching(tokens: list[str], start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index] == opening:
            depth += 1
        elif tokens[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    raise FinsecError(f"Unbalanced GraphQL schema token: expected {closing}.")


def _type_reference(tokens: list[str], start: int, limit: int) -> tuple[str, int]:
    if start >= limit:
        raise FinsecError("GraphQL field has an invalid type reference.")
    if tokens[start] == "[":
        inner, index = _type_reference(tokens, start + 1, limit)
        if index >= limit or tokens[index] != "]":
            raise FinsecError("GraphQL list type is missing a closing bracket.")
        result = f"[{inner}]"
        index += 1
    elif TYPE_NAME_PATTERN.match(tokens[start]):
        result = tokens[start]
        index = start + 1
    else:
        raise FinsecError("GraphQL field has an invalid type reference.")
    if index < limit and tokens[index] == "!":
        result += "!"
        index += 1
    return result, index


def _arguments(tokens: list[str], start: int, end: int) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    index = start + 1
    depth = 1
    while index < end:
        token = tokens[index]
        if token in {"(", "[", "{"}:
            depth += 1
            index += 1
            continue
        if token in {
            ")",
            "]",
            "}",
        }:
            depth -= 1
            index += 1
            continue
        if (
            depth == 1
            and TYPE_NAME_PATTERN.match(token)
            and index + 1 < end
            and tokens[index + 1] == ":"
        ):
            type_name, next_index = _type_reference(tokens, index + 2, end)
            result.append({"name": token, "type": type_name})
            index = next_index
            continue
        index += 1
    return result


def _skip_directives(tokens: list[str], start: int, end: int) -> int:
    index = start
    while index < end and tokens[index] == "@":
        index += 1
        if index < end and TYPE_NAME_PATTERN.match(tokens[index]):
            index += 1
        if index < end and tokens[index] == "(":
            index = _matching(tokens, index, "(", ")") + 1
    return index


def _root_fields(tokens: list[str], start: int, end: int) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    index = start + 1
    while index < end:
        if not TYPE_NAME_PATTERN.match(tokens[index]):
            index += 1
            continue
        field = tokens[index]
        index += 1
        arguments: list[dict[str, str]] = []
        if index < end and tokens[index] == "(":
            argument_end = _matching(tokens, index, "(", ")")
            arguments = _arguments(tokens, index, argument_end)
            index = argument_end + 1
        if index >= end or tokens[index] != ":":
            continue
        return_type, index = _type_reference(tokens, index + 1, end)
        index = _skip_directives(tokens, index, end)
        fields.append({"field": field, "arguments": arguments, "return_type": return_type})
    return fields


def _sdl_operations(value: str) -> list[dict[str, Any]]:
    tokens = TOKEN_PATTERN.findall(_mask_sdl(value))
    root_names = {"query": "Query", "mutation": "Mutation", "subscription": "Subscription"}
    for index, token in enumerate(tokens):
        if token != "schema" or index + 1 >= len(tokens) or tokens[index + 1] != "{":
            continue
        end = _matching(tokens, index + 1, "{", "}")
        cursor = index + 2
        while cursor + 2 < end:
            operation_type = tokens[cursor]
            if operation_type in root_names and tokens[cursor + 1] == ":":
                root_names[operation_type] = tokens[cursor + 2]
            cursor += 1

    operations: list[dict[str, Any]] = []
    index = 0
    while index < len(tokens):
        if tokens[index] == "extend" and index + 1 < len(tokens) and tokens[index + 1] == "type":
            index += 1
        if tokens[index] != "type" or index + 2 >= len(tokens):
            index += 1
            continue
        type_name = tokens[index + 1]
        cursor = index + 2
        while cursor < len(tokens) and tokens[cursor] != "{":
            cursor += 1
        if cursor >= len(tokens):
            break
        end = _matching(tokens, cursor, "{", "}")
        operation_type = next(
            (name for name, root_name in root_names.items() if root_name == type_name), None
        )
        if operation_type is not None:
            for field in _root_fields(tokens, cursor, end):
                field["operation_type"] = operation_type
                operations.append(field)
        index = end + 1
    return operations


def _introspection_type(value: Any) -> str:
    if not isinstance(value, dict):
        raise FinsecError("GraphQL introspection contains an invalid type reference.")
    kind = value.get("kind")
    if kind == "NON_NULL":
        return f"{_introspection_type(value.get('ofType'))}!"
    if kind == "LIST":
        return f"[{_introspection_type(value.get('ofType'))}]"
    name = value.get("name")
    if not isinstance(name, str) or not TYPE_NAME_PATTERN.match(name):
        raise FinsecError("GraphQL introspection contains an unnamed type.")
    return name


def _introspection_operations(document: dict[str, Any]) -> list[dict[str, Any]]:
    data = document.get("data") if isinstance(document.get("data"), dict) else document
    schema = data.get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict) or not isinstance(schema.get("types"), list):
        raise FinsecError("GraphQL JSON must contain data.__schema or __schema introspection data.")
    types = {
        item["name"]: item
        for item in schema["types"]
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    operations: list[dict[str, Any]] = []
    for operation_type, root_key in (
        ("query", "queryType"),
        ("mutation", "mutationType"),
        ("subscription", "subscriptionType"),
    ):
        root = schema.get(root_key)
        root_name = root.get("name") if isinstance(root, dict) else None
        root_type = types.get(root_name) if isinstance(root_name, str) else None
        fields = root_type.get("fields") if isinstance(root_type, dict) else None
        if not isinstance(fields, list):
            continue
        for field in fields:
            if not isinstance(field, dict) or not isinstance(field.get("name"), str):
                continue
            arguments = []
            if isinstance(field.get("args"), list):
                for argument in field["args"]:
                    if isinstance(argument, dict) and isinstance(argument.get("name"), str):
                        arguments.append(
                            {
                                "name": argument["name"],
                                "type": _introspection_type(argument.get("type")),
                            }
                        )
            operations.append(
                {
                    "operation_type": operation_type,
                    "field": field["name"],
                    "arguments": arguments,
                    "return_type": _introspection_type(field.get("type")),
                }
            )
    return operations


def _existing_sources(path: Path) -> dict[str, list[str]]:
    if not path.is_file():
        return {}
    try:
        store = GraphQLStore.model_validate(load_yaml(path))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot read GraphQL inventory {path}: {error}") from error
    return {item.key: item.sources for item in store.operations}


def ingest_graphql(
    source: Path, workspace: WorkspacePaths, endpoint: str | None = None
) -> GraphQLImportResult:
    """Inventory supplied GraphQL schema evidence without contacting a server."""

    path = source.expanduser().resolve()
    if not path.is_file():
        raise FinsecError(f"GraphQL schema file not found: {path}")
    raw, digest = source_digest(path)
    normalized_endpoint = _normalize_endpoint(endpoint)
    capture_name = f"{safe_stem(path)}-{digest[:8]}-redacted.graphql.json"
    capture_path = workspace.root / "observations" / "raw" / capture_name
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise FinsecError(f"GraphQL schema must be UTF-8 text: {path}") from error
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        operations = _sdl_operations(text)
        capture_format = "SDL"
        reference_prefix = f"observations/raw/{capture_name}#sdl"
    else:
        if not isinstance(document, dict):
            raise FinsecError("GraphQL introspection JSON must be a mapping.")
        operations = _introspection_operations(document)
        capture_format = "INTROSPECTION"
        reference_prefix = f"observations/raw/{capture_name}#/data/__schema"
    if not operations:
        raise FinsecError("GraphQL schema contains no query, mutation, or subscription fields.")
    write_redacted_json(
        capture_path,
        {
            "format": capture_format,
            "endpoint": normalized_endpoint,
            "operations": operations,
            "notes": "Normalized schema evidence; descriptions and default values are omitted.",
        },
    )

    existing_sources = _existing_sources(workspace.graphql)
    drafts_by_key: dict[str, dict[str, Any]] = {}
    for item in operations:
        key = "|".join(
            [normalized_endpoint or "UNSPECIFIED", item["operation_type"], item["field"]]
        )
        source_reference = f"{reference_prefix}/{item['operation_type']}/{item['field']}"
        drafts_by_key[key] = {
            "key": key,
            "operation_type": item["operation_type"],
            "field": item["field"],
            "arguments": sorted(item["arguments"], key=lambda value: value["name"]),
            "return_type": item["return_type"],
            "endpoint": normalized_endpoint,
            "sources": sorted({*existing_sources.get(key, []), source_reference}),
            "confidence": "high",
            "knowledge_status": "OBSERVED",
            "notes": (
                "Observed in supplied GraphQL schema evidence; endpoint reachability and "
                "runtime authorization are not confirmed."
            ),
        }
    source_fingerprint = stable_fingerprint(
        {"digest": digest, "endpoint": normalized_endpoint, "operations": operations}
    )
    merge = merge_generated_records(
        workspace.graphql,
        collection_key="operations",
        id_prefix="GQL",
        generator="phase5.graphql",
        source_fingerprint=source_fingerprint,
        drafts=list(drafts_by_key.values()),
    )
    try:
        store = GraphQLStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(f"Generated GraphQL inventory is invalid: {error}") from error
    write_yaml(workspace.graphql, store.model_dump(mode="json", exclude_none=True))
    return GraphQLImportResult(
        operations=len(store.operations),
        added=merge.added,
        updated=merge.updated,
        conflicts=merge.conflicts,
        inventory_path=workspace.graphql,
        redacted_capture=capture_path,
    )
