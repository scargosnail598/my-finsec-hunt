"""Conservative path normalization with explicit evidence and rules."""

import re
from dataclasses import dataclass

from finsec.modeling.models import Confidence, Observation, ParameterType

UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
ULID_PATTERN = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$", re.IGNORECASE)
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{16,64}$")
OPAQUE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,80}$")
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


@dataclass(frozen=True)
class NormalizedPath:
    """Normalized path plus transparent inference details."""

    path: str
    parameters: tuple[PathParameter, ...]
    rules: tuple[str, ...]


def _segments(path: str) -> list[str]:
    return [segment for segment in path.split("/") if segment]


def _strong_identifier(segment: str) -> tuple[ParameterType, str] | None:
    if UUID_PATTERN.fullmatch(segment):
        return ("uuid", "uuid")
    if ULID_PATTERN.fullmatch(segment):
        return ("string", "ulid")
    if HEX_PATTERN.fullmatch(segment):
        return ("string", "long_hex")
    if OPAQUE_PATTERN.fullmatch(segment) and any(char.isdigit() for char in segment):
        return ("string", "long_opaque")
    return None


def _is_numeric_candidate(segment: str, previous: str | None) -> bool:
    if not segment.isdigit():
        return False
    if len(segment) == 4 and 1900 <= int(segment) <= 2100:
        return False
    return not previous or previous.lower() not in NON_RESOURCE_SEGMENTS


def _signature(path: str) -> tuple[str, ...]:
    result: list[str] = []
    segments = _segments(path)
    for index, segment in enumerate(segments):
        previous = segments[index - 1] if index else None
        if _strong_identifier(segment):
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
    words = [word for word in re.split(r"[-_]", _singular(previous)) if word]
    if not words:
        return "resourceId"
    camel = words[0] + "".join(word.title() for word in words[1:])
    return f"{camel}Id"


def normalize_paths(observations: list[Observation]) -> dict[str, NormalizedPath]:
    """Normalize strong identifiers and repeated numeric segments only."""

    groups: dict[tuple[str, str, tuple[str, ...]], list[Observation]] = {}
    for observation in observations:
        key = (observation.method, observation.host, _signature(observation.path))
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
                if strong:
                    inferred_type, rule = strong
                    name = _parameter_name(previous)
                    normalized.append(f"{{{name}}}")
                    parameters.append(PathParameter(name, inferred_type, Confidence.HIGH, rule))
                    rules.append(rule)
                elif index in numeric_positions:
                    name = _parameter_name(previous)
                    normalized.append(f"{{{name}}}")
                    parameters.append(
                        PathParameter(name, "integer", Confidence.MEDIUM, "repeated_numeric")
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
