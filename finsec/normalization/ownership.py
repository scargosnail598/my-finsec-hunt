"""Centralized classification for path parameters that may express ownership scope."""

import re
from typing import Literal

from finsec.config.models import OwnershipInferenceConfig

OwnershipScopeClassification = Literal[
    "TRUSTED_PARENT_SCOPE",
    "PUBLIC_SHARED_SCOPE",
    "UNCLASSIFIED",
]


def normalized_parameter_name(value: str) -> str:
    """Normalize spelling variants without broadening the configured semantics."""

    return re.sub(r"[^a-z0-9]", "", value.lower())


def classify_ownership_scope_parameter(
    parameter: str,
    config: OwnershipInferenceConfig,
) -> OwnershipScopeClassification:
    """Classify one parameter, with the public/shared denylist taking precedence."""

    normalized = normalized_parameter_name(parameter)
    public = {normalized_parameter_name(item) for item in config.public_shared_parameters}
    if normalized in public:
        return "PUBLIC_SHARED_SCOPE"
    trusted = {normalized_parameter_name(item) for item in config.trusted_parent_parameters}
    if normalized in trusted:
        return "TRUSTED_PARENT_SCOPE"
    return "UNCLASSIFIED"
