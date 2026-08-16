"""Canonical current-state classification for controlled resource evidence."""

from enum import StrEnum


class ControlledObjectLiveness(StrEnum):
    """Whether passive evidence can bind a controlled object to a new execution."""

    LIVE = "LIVE"
    DELETED = "DELETED"
    UNKNOWN = "UNKNOWN"
    HISTORICAL_ONLY = "HISTORICAL_ONLY"


def execution_binding_eligible(liveness: ControlledObjectLiveness) -> bool:
    """Only authoritative current-live evidence may be reused by bounded execution."""

    return liveness == ControlledObjectLiveness.LIVE
