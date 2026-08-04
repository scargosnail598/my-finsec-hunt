"""Non-destructive merging for generated YAML and Markdown artifacts."""

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from finsec.errors import FinsecError
from finsec.utils.yaml_store import load_yaml


@dataclass(frozen=True)
class MergeResult:
    """Result of reconciling generated records with researcher edits."""

    document: dict[str, Any]
    added: int
    updated: int
    conflicts: tuple[str, ...]
    preserved: int


def stable_fingerprint(value: Any) -> str:
    """Return a deterministic SHA-256 fingerprint for JSON-compatible data."""

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _record_checksum(record: dict[str, Any], ignored_fields: tuple[str, ...] = ()) -> str:
    ignored = {"generation", *ignored_fields}
    payload = {key: value for key, value in record.items() if key not in ignored}
    return stable_fingerprint(payload)


def _next_id(records: list[dict[str, Any]], prefix: str) -> int:
    pattern = re.compile(rf"^{re.escape(prefix)}-(\d+)$")
    values = [
        int(match.group(1))
        for record in records
        if isinstance(record.get("id"), str)
        and (match := pattern.fullmatch(record["id"])) is not None
    ]
    return max(values, default=0) + 1


def merge_generated_records(
    path: Path,
    collection_key: str,
    id_prefix: str,
    generator: str,
    source_fingerprint: str,
    drafts: list[dict[str, Any]],
    preserved_fields: tuple[str, ...] = (),
) -> MergeResult:
    """Refresh untouched generated records and preserve all researcher edits."""

    if path.is_file():
        loaded = load_yaml(path)
        if not isinstance(loaded, dict):
            raise FinsecError(f"Expected a YAML mapping in {path}.")
        document = copy.deepcopy(loaded)
    else:
        document = {"version": 1, collection_key: []}

    raw_records = document.get(collection_key, [])
    if not isinstance(raw_records, list) or not all(isinstance(item, dict) for item in raw_records):
        raise FinsecError(f"Expected '{collection_key}' to be a list in {path}.")
    existing: list[dict[str, Any]] = [copy.deepcopy(item) for item in raw_records]
    existing_by_key = {item["key"]: item for item in existing if isinstance(item.get("key"), str)}
    next_number = _next_id(existing, id_prefix)
    merged: list[dict[str, Any]] = []
    consumed: set[str] = set()
    conflicts: list[str] = []
    added = 0
    updated = 0

    for draft in sorted(drafts, key=lambda item: str(item["key"])):
        key = str(draft["key"])
        current = existing_by_key.get(key)
        candidate = copy.deepcopy(draft)
        if current is None:
            if not isinstance(candidate.get("id"), str):
                candidate["id"] = f"{id_prefix}-{next_number:03d}"
                next_number += 1
            added += 1
        else:
            consumed.add(key)
            candidate["id"] = current.get("id", f"{id_prefix}-{next_number:03d}")
            generation = current.get("generation")
            stored_checksum = (
                generation.get("generated_checksum") if isinstance(generation, dict) else None
            )
            if stored_checksum != _record_checksum(current, preserved_fields):
                merged.append(current)
                conflicts.append(key)
                continue
            for field in preserved_fields:
                if field in current:
                    candidate[field] = copy.deepcopy(current[field])
            updated += 1

        candidate["generation"] = {
            "managed": True,
            "generator": generator,
            "generated_checksum": _record_checksum(candidate, preserved_fields),
            "source_fingerprint": source_fingerprint,
        }
        merged.append(candidate)

    preserved_records = [
        item
        for item in existing
        if not isinstance(item.get("key"), str) or item["key"] not in consumed
    ]
    merged.extend(preserved_records)
    document["version"] = int(document.get("version", 1))
    document[collection_key] = merged
    return MergeResult(
        document=document,
        added=added,
        updated=updated,
        conflicts=tuple(sorted(conflicts)),
        preserved=len(preserved_records),
    )


def write_managed_markdown(path: Path, title: str, section: str, content: str) -> None:
    """Replace one generated Markdown block while preserving researcher text."""

    start = f"<!-- FINSEC-GENERATED:{section}:START -->"
    end = f"<!-- FINSEC-GENERATED:{section}:END -->"
    block = f"{start}\n{content.rstrip()}\n{end}"
    existing = path.read_text(encoding="utf-8") if path.is_file() else f"# {title}\n"

    if start in existing and end in existing:
        prefix, remainder = existing.split(start, 1)
        _, suffix = remainder.split(end, 1)
        updated = f"{prefix}{block}{suffix}"
    else:
        stripped = existing.strip()
        prefix = f"# {title}\n\n" if "Phase 2 artifact." in stripped else f"{existing.rstrip()}\n\n"
        notes = "" if "## Researcher Notes" in existing else "\n\n## Researcher Notes\n\n"
        updated = f"{prefix}{block}{notes}"

    path.write_text(f"{updated.rstrip()}\n", encoding="utf-8", newline="\n")
