"""Conservative path normalization with explicit evidence and rules."""

import re
import uuid
from dataclasses import dataclass

from finsec.modeling.models import (
    Confidence,
    EndpointPrimaryClassification,
    Observation,
    ParameterType,
)

UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
ULID_PATTERN = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$", re.IGNORECASE)
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{16,64}$")
OPAQUE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,80}$")
STRUCTURED_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{7,63}$")
VERSION_PATTERNS = (
    re.compile(r"^v\d+$", re.IGNORECASE),
    re.compile(r"^v\d+\.\d+$", re.IGNORECASE),
    re.compile(r"^v\d+\.\d+\.\d+$", re.IGNORECASE),
    re.compile(r"^version[-_]?\d+$", re.IGNORECASE),
    re.compile(r"^api[-_]?v\d+$", re.IGNORECASE),
)
STATIC_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "webp",
    "gif",
    "svg",
    "ico",
    "css",
    "js",
    "map",
    "woff",
    "woff2",
    "ttf",
    "eot",
    "mp4",
    "webm",
}
NON_RESOURCE_SEGMENTS = {
    "api",
    "page",
    "pages",
    "offset",
    "limit",
    "year",
    "month",
    "day",
    "version",
}


@dataclass(frozen=True)
class PathParameter:
    """A parameter introduced while normalizing a path."""

    name: str
    inferred_type: ParameterType
    confidence: Confidence
    rule: str
    original_examples: tuple[str, ...] = ()
    normalization_reason: tuple[str, ...] = ()


@dataclass(frozen=True)
class NormalizedPath:
    """Normalized path plus transparent inference details."""

    path: str
    parameters: tuple[PathParameter, ...]
    rules: tuple[str, ...]


def _segments(path: str) -> list[str]:
    return [segment for segment in path.split("/") if segment]


def is_version_segment(segment: str) -> bool:
    """Return whether a segment is an explicit API or asset version."""

    return any(pattern.fullmatch(segment) for pattern in VERSION_PATTERNS)


def _is_static_filename(segment: str) -> bool:
    _, separator, extension = segment.rpartition(".")
    return bool(separator) and extension.lower() in STATIC_EXTENSIONS


def _strong_identifier(segment: str) -> tuple[ParameterType, str] | None:
    if is_version_segment(segment):
        return None
    try:
        uuid.UUID(segment)
        return ("uuid", "uuid")
    except (ValueError, TypeError, AttributeError):
        pass
    if ULID_PATTERN.fullmatch(segment):
        return ("string", "ulid")
    if HEX_PATTERN.fullmatch(segment):
        return ("string", "long_hex")
    if OPAQUE_PATTERN.fullmatch(segment) and any(char.isdigit() for char in segment):
        return ("string", "long_opaque")
    if STRUCTURED_ID_PATTERN.fullmatch(segment):
        separators = segment.count("-") + segment.count("_")
        has_digit = any(char.isdigit() for char in segment)
        has_uppercase = any(char.isupper() for char in segment)
        if (separators >= 2 and (has_digit or has_uppercase)) or (separators >= 1 and has_digit):
            return ("string", "structured_opaque")
    return None


def _is_numeric_candidate(segment: str, previous: str | None) -> bool:
    if not segment.isdigit():
        return False
    try:
        val = int(segment)
        if len(segment) == 4 and 1900 <= val <= 2100:
            return False
    except (ValueError, TypeError, OverflowError):
        return False
    return not previous or previous.lower() not in NON_RESOURCE_SEGMENTS


def _signature(path: str, static_asset: bool = False) -> tuple[str, ...]:
    result: list[str] = []
    segments = _segments(path)
    for index, segment in enumerate(segments):
        previous = segments[index - 1] if index else None
        if static_asset and _is_static_filename(segment):
            result.append("<FILENAME>")
        elif _strong_identifier(segment):
            result.append("<STRONG_ID>")
        elif _is_numeric_candidate(segment, previous):
            result.append("<NUMERIC_CANDIDATE>")
        else:
            result.append(segment)
    return tuple(result)


def _singular(value: str) -> str:
    lowered = value.lower()
    if lowered.endswith("ies") and len(lowered) > 3:
        return f"{lowered[:-3]}y"
    if lowered.endswith("s") and not lowered.endswith("ss") and len(lowered) > 1:
        return lowered[:-1]
    return lowered


def _parameter_name(previous: str | None) -> str:
    if not previous or previous.lower() in NON_RESOURCE_SEGMENTS:
        return "resourceId"
    # Stripping parameter placeholders if previous segment was dynamic
    clean_prev = re.sub(r"^\{|\}$", "", previous)
    words = [word for word in re.split(r"[-_]", _singular(clean_prev)) if word]
    if not words:
        return "resourceId"
    # Ensure parameter name starts with a valid alpha character
    if not words[0][0].isalpha():
        return "resourceId"
    camel = words[0] + "".join(word.title() for word in words[1:])
    return f"{camel}Id"


def normalize_paths(
    observations: list[Observation],
    classifications: dict[str, EndpointPrimaryClassification] | None = None,
) -> dict[str, NormalizedPath]:
    """Normalize strong identifiers and repeated numeric segments only."""

    groups: dict[tuple[str, str, tuple[str, ...]], list[Observation]] = {}
    for observation in observations:
        static_asset = (
            classifications is not None
            and classifications.get(observation.id) == EndpointPrimaryClassification.STATIC_ASSET
        )
        key = (observation.method, observation.host, _signature(observation.path, static_asset))
        groups.setdefault(key, []).append(observation)

    results: dict[str, NormalizedPath] = {}
    for (_, _, signature), items in groups.items():
        numeric_positions: set[int] = set()
        for index, marker in enumerate(signature):
            if marker != "<NUMERIC_CANDIDATE>":
                continue
            values = {_segments(item.path)[index] for item in items}
            if len(values) > 1:
                numeric_positions.add(index)

        for observation in items:
            original = _segments(observation.path)
            normalized: list[str] = []
            parameters: list[PathParameter] = []
            rules: list[str] = []
            for index, segment in enumerate(original):
                previous = original[index - 1] if index else None
                strong = _strong_identifier(segment)
                if signature[index] == "<FILENAME>":
                    filenames = {_segments(item.path)[index] for item in items}
                    if len(filenames) > 1:
                        normalized.append("{filename}")
                        parameters.append(
                            PathParameter(
                                "filename",
                                "string",
                                Confidence.HIGH,
                                "static_filename",
                                tuple(sorted(filenames)),
                                ("static asset filename grouped into one route family",),
                            )
                        )
                        rules.append("static_filename")
                    else:
                        normalized.append(segment)
                elif strong:
                    inferred_type, rule = strong
                    name = _parameter_name(previous)
                    if (
                        classifications
                        and classifications.get(observation.id)
                        == EndpointPrimaryClassification.STATIC_ASSET
                    ):
                        name = "uuid" if rule == "uuid" else "opaqueId"
                    normalized.append(f"{{{name}}}")
                    parameters.append(
                        PathParameter(
                            name,
                            inferred_type,
                            Confidence.HIGH,
                            rule,
                            (segment,),
                            (f"segment matches {rule} pattern",),
                        )
                    )
                    rules.append(rule)
                elif index in numeric_positions:
                    name = _parameter_name(previous)
                    normalized.append(f"{{{name}}}")
                    parameters.append(
                        PathParameter(
                            name,
                            "integer",
                            Confidence.MEDIUM,
                            "repeated_numeric",
                            tuple(sorted({_segments(item.path)[index] for item in items})),
                            ("same route structure observed with multiple integer values",),
                        )
                    )
                    rules.append("repeated_numeric")
                else:
                    normalized.append(segment)

            path = "/" + "/".join(normalized)
            if observation.path.endswith("/") and path != "/":
                path += "/"
            results[observation.id] = NormalizedPath(
                path=path,
                parameters=tuple(parameters),
                rules=tuple(sorted(set(rules))),
            )
    return results
