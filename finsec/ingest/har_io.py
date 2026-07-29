"""Shared bounded loading for HAR files used by ingestion and authentication."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from finsec.errors import HarFormatError

MAX_HAR_BYTES = 256 * 1024 * 1024
MAX_CONFIGURABLE_HAR_BYTES = 512 * 1024 * 1024
HAR_LIMIT_ENVIRONMENT_VARIABLE = "FINSEC_MAX_HAR_BYTES"


def har_size_limit() -> int:
    """Return the default 256 MiB ceiling or a bounded local override."""

    configured = os.environ.get(HAR_LIMIT_ENVIRONMENT_VARIABLE, "").strip()
    if not configured:
        return MAX_HAR_BYTES
    try:
        limit = int(configured)
    except ValueError as error:
        raise HarFormatError(
            f"{HAR_LIMIT_ENVIRONMENT_VARIABLE} must be an integer byte count."
        ) from error
    if not 1 <= limit <= MAX_CONFIGURABLE_HAR_BYTES:
        raise HarFormatError(
            f"{HAR_LIMIT_ENVIRONMENT_VARIABLE} must be between 1 and "
            f"{MAX_CONFIGURABLE_HAR_BYTES} bytes."
        )
    return limit


def load_har_json(har_path: Path) -> tuple[Path, bytes, Any]:
    """Read and decode one HAR under the shared memory-safety ceiling."""

    source = har_path.expanduser().resolve()
    try:
        size = source.stat().st_size
    except OSError as error:
        raise HarFormatError(f"HAR file was not found or is unreadable: {source}") from error
    limit = har_size_limit()
    if size > limit:
        mebibytes = limit / (1024 * 1024)
        raise HarFormatError(
            f"HAR import is limited to {limit} bytes ({mebibytes:g} MiB) per file. "
            f"Set {HAR_LIMIT_ENVIRONMENT_VARIABLE} to a larger byte count, up to "
            f"{MAX_CONFIGURABLE_HAR_BYTES}, or split the capture."
        )
    try:
        raw = source.read_bytes()
    except OSError as error:
        raise HarFormatError(f"HAR file is unreadable: {source}") from error
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarFormatError(f"HAR is not valid UTF-8 JSON: {source}") from error
    return source, raw, document
