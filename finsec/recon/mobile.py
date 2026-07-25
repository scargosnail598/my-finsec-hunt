"""Bounded static discovery of mobile-to-backend architecture leads."""

import re
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from pydantic import ValidationError

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.merge import merge_generated_records, stable_fingerprint
from finsec.recon.domain import MobileDiscoveryKind, MobileDiscoveryStore
from finsec.utils.redaction import redact_text
from finsec.utils.yaml_store import load_yaml, write_yaml

MAX_FILES = 2_000
MAX_FILE_BYTES = 5_000_000
MAX_TOTAL_BYTES = 50_000_000
MAX_DISCOVERIES = 5_000

ASCII_STRING = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
HTTP_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%{}-]+")
WEBSOCKET_URL = re.compile(r"wss?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%{}-]+")
CUSTOM_SCHEME = re.compile(r"(?<![A-Za-z0-9+.-])([a-z][a-z0-9+.-]{1,31}://[^\s\"'<>]+)", re.I)
API_PATH = re.compile(r"/(?:api|rest)(?:/v\d+)?(?:/[A-Za-z0-9._{}~-]+){1,12}", re.I)
GRAPHQL_PATH = re.compile(r"/(?:api/)?graphql(?:/[A-Za-z0-9._{}~-]+){0,4}", re.I)
CUSTOM_HEADER = re.compile(r"\bX-[A-Za-z0-9][A-Za-z0-9-]{2,62}\b", re.I)
TRAILING_PUNCTUATION = ".,;:)]}"


@dataclass(frozen=True)
class MobileScanResult:
    """Summary of one passive mobile artifact scan."""

    discoveries: int
    added: int
    updated: int
    files_scanned: int
    conflicts: tuple[str, ...]
    inventory_path: Path


def _strings(data: bytes) -> set[str]:
    values = {match.group().decode("ascii") for match in ASCII_STRING.finditer(data)}
    values.update(
        match.group().decode("utf-16-le", errors="ignore")
        for match in UTF16LE_STRING.finditer(data)
    )
    return values


def _bounded_file(path: Path) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise FinsecError(f"Cannot inspect mobile artifact file {path}: {error}") from error
    if size > MAX_FILE_BYTES:
        raise FinsecError(f"Mobile artifact file exceeds the {MAX_FILE_BYTES}-byte limit: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise FinsecError(f"Cannot read mobile artifact file {path}: {error}") from error


def _directory_inputs(root: Path) -> list[tuple[str, bytes]]:
    files = sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink())
    if len(files) > MAX_FILES:
        raise FinsecError(f"Mobile scan is limited to {MAX_FILES} files.")
    result: list[tuple[str, bytes]] = []
    total = 0
    for path in files:
        data = _bounded_file(path)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise FinsecError(f"Mobile scan exceeds the {MAX_TOTAL_BYTES}-byte total limit.")
        result.append((path.relative_to(root).as_posix(), data))
    return result


def _apk_inputs(path: Path) -> list[tuple[str, bytes]]:
    try:
        with zipfile.ZipFile(path) as archive:
            entries = [item for item in archive.infolist() if not item.is_dir()]
            if len(entries) > MAX_FILES:
                raise FinsecError(f"APK scan is limited to {MAX_FILES} archive entries.")
            total = sum(item.file_size for item in entries)
            if total > MAX_TOTAL_BYTES:
                raise FinsecError(f"APK uncompressed content exceeds {MAX_TOTAL_BYTES} bytes.")
            result: list[tuple[str, bytes]] = []
            for entry in sorted(entries, key=lambda item: item.filename):
                if entry.flag_bits & 0x1:
                    raise FinsecError(f"Encrypted APK entry is not supported: {entry.filename}")
                if entry.file_size > MAX_FILE_BYTES:
                    raise FinsecError(
                        f"APK entry exceeds the {MAX_FILE_BYTES}-byte limit: {entry.filename}"
                    )
                result.append((entry.filename, archive.read(entry)))
            return result
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise FinsecError(f"Cannot read APK archive {path}: {error}") from error


def _artifact_inputs(path: Path) -> list[tuple[str, bytes]]:
    if path.is_symlink():
        raise FinsecError("Mobile scan input must not be a symbolic link.")
    if path.is_dir():
        return _directory_inputs(path)
    if not path.is_file():
        raise FinsecError(f"Mobile artifact not found: {path}")
    if path.suffix.lower() == ".apk":
        return _apk_inputs(path)
    return [(path.name, _bounded_file(path))]


def _clean(value: str) -> str:
    return redact_text(value.rstrip(TRAILING_PUNCTUATION))


def _discover(values: Iterable[str]) -> set[tuple[MobileDiscoveryKind, str]]:
    discoveries: set[tuple[MobileDiscoveryKind, str]] = set()
    for text in values:
        for match in HTTP_URL.finditer(text):
            url = _clean(match.group())
            discoveries.add(("BASE_URL", url))
            if "graphql" in url.lower():
                discoveries.add(("GRAPHQL_ENDPOINT", url))
        for match in WEBSOCKET_URL.finditer(text):
            discoveries.add(("WEBSOCKET", _clean(match.group())))
        for match in GRAPHQL_PATH.finditer(text):
            discoveries.add(("GRAPHQL_ENDPOINT", _clean(match.group())))
        for match in API_PATH.finditer(text):
            discoveries.add(("API_PATH", _clean(match.group())))
        for match in CUSTOM_SCHEME.finditer(text):
            value = _clean(match.group(1))
            if not value.lower().startswith(("http://", "https://", "ws://", "wss://")):
                discoveries.add(("DEEP_LINK", value))
        for match in CUSTOM_HEADER.finditer(text):
            discoveries.add(("CUSTOM_HEADER", match.group()))
    return discoveries


def _existing_sources(path: Path) -> dict[str, list[str]]:
    if not path.is_file():
        return {}
    try:
        store = MobileDiscoveryStore.model_validate(load_yaml(path))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot read mobile discovery inventory {path}: {error}") from error
    return {item.key: item.sources for item in store.discoveries}


def scan_mobile(source: Path, workspace: WorkspacePaths) -> MobileScanResult:
    """Extract bounded string-level leads without executing or unpacking an application."""

    candidate = source.expanduser()
    if candidate.is_symlink():
        raise FinsecError("Mobile scan input must not be a symbolic link.")
    path = candidate.resolve()
    inputs = _artifact_inputs(path)
    if not inputs:
        raise FinsecError("Mobile artifact contains no readable files.")
    file_digests = [(name, sha256(data).hexdigest()) for name, data in inputs]
    artifact_fingerprint = stable_fingerprint({"artifact": path.name, "files": file_digests})
    found: dict[tuple[MobileDiscoveryKind, str], set[str]] = {}
    for reference, data in inputs:
        for discovery in _discover(_strings(data)):
            found.setdefault(discovery, set()).add(
                f"artifact:{path.name}@{artifact_fingerprint[:12]}!/{reference}"
            )
    if len(found) > MAX_DISCOVERIES:
        raise FinsecError(
            f"Mobile artifact produced more than {MAX_DISCOVERIES} discoveries; narrow the input."
        )

    existing_sources = _existing_sources(workspace.mobile_discoveries)
    drafts: list[dict[str, object]] = []
    for (kind, value), references in sorted(found.items()):
        key = f"{kind}|{value}"
        drafts.append(
            {
                "key": key,
                "kind": kind,
                "value": value,
                "sources": sorted({*existing_sources.get(key, []), *references}),
                "channel": "MOBILE",
                "confidence": "high" if kind in {"BASE_URL", "WEBSOCKET"} else "medium",
                "knowledge_status": "OBSERVED",
                "notes": (
                    "Observed as a static artifact string; backend reachability, authorization, "
                    "and feature availability are not confirmed."
                ),
            }
        )
    merge = merge_generated_records(
        workspace.mobile_discoveries,
        collection_key="discoveries",
        id_prefix="MOB",
        generator="phase5.mobile",
        source_fingerprint=artifact_fingerprint,
        drafts=drafts,
    )
    try:
        store = MobileDiscoveryStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(f"Generated mobile discovery inventory is invalid: {error}") from error
    write_yaml(
        workspace.mobile_discoveries,
        store.model_dump(mode="json", exclude_none=True),
    )
    return MobileScanResult(
        discoveries=len(store.discoveries),
        added=merge.added,
        updated=merge.updated,
        files_scanned=len(inputs),
        conflicts=merge.conflicts,
        inventory_path=workspace.mobile_discoveries,
    )
