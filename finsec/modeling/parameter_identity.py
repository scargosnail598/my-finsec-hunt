"""Canonical cross-layer identity for one endpoint parameter."""

from __future__ import annotations

import re
from dataclasses import dataclass

_ARRAY_INDEX = re.compile(r"\[(?:\*|\d*)\]")
_BRACKET_FIELD = re.compile(r"\[['\"]([A-Za-z_][A-Za-z0-9_-]*)['\"]\]")
_JSON_PATH = re.compile(r"^\$(?:\.[A-Za-z_][A-Za-z0-9_-]*|\[\*\])+$")


def normalize_parameter_name(value: str) -> str:
    """Normalize terminal parameter spelling without discarding its location or JSON path."""

    return re.sub(r"[^a-z0-9]", "", value.casefold())


def normalize_json_path(value: str | None) -> str | None:
    """Normalize supported dotted and array JSON-path notation to one canonical form."""

    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    normalized = _BRACKET_FIELD.sub(r".\1", normalized)
    if not normalized.startswith("$"):
        normalized = f"$.{normalized.lstrip('.')}"
    normalized = _ARRAY_INDEX.sub("[*]", normalized)
    normalized = re.sub(r"\.{2,}", ".", normalized)
    return normalized if _JSON_PATH.fullmatch(normalized) else None


@dataclass(frozen=True, order=True)
class ParameterIdentity:
    """Exact parameter identity used for semantics, ownership, clustering, and planning."""

    location: str
    normalized_json_path: str | None
    normalized_parameter_name: str


def parameter_identity(
    location: str | None,
    json_path: str | None,
    parameter_name: str | None,
) -> ParameterIdentity | None:
    """Build a fail-closed identity; body targets require their own JSON path."""

    if location is None or parameter_name is None:
        return None
    normalized_location = location.strip().casefold()
    normalized_name = normalize_parameter_name(parameter_name)
    if not normalized_location or not normalized_name:
        return None
    normalized_path = normalize_json_path(json_path)
    if json_path is not None and normalized_path is None:
        return None
    if normalized_location == "body" and normalized_path is None:
        return None
    return ParameterIdentity(normalized_location, normalized_path, normalized_name)


def parameter_identities_match(
    *,
    evidence_location: str | None,
    evidence_json_path: str | None,
    evidence_name: str,
    target_location: str | None,
    target_json_path: str | None,
    target_name: str | None,
) -> bool:
    """Match exact identities while allowing legacy name-only evidence only for path targets."""

    target = parameter_identity(target_location, target_json_path, target_name)
    if target is None:
        return False
    if evidence_location is None:
        return (
            target.location == "path"
            and target.normalized_json_path is None
            and normalize_parameter_name(evidence_name) == target.normalized_parameter_name
        )
    evidence = parameter_identity(evidence_location, evidence_json_path, evidence_name)
    return evidence is not None and evidence == target
