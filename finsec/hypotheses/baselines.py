"""Stable secret-free identities for controlled comparison baselines."""

from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import ActorObjectBaseline


def opaque_reference(prefix: str, value: str) -> str:
    """Reference a sensitive scalar without returning the scalar itself."""

    return f"{prefix}-{stable_fingerprint({'value': value})[:16].upper()}"


def canonical_baseline_identity(
    baseline: ActorObjectBaseline,
) -> tuple[str, str, str | None]:
    """Return the shared canonical ID plus opaque object and parent references."""

    object_reference = baseline.subject_resource_id or opaque_reference(
        "OBJ", baseline.requested_value
    )
    parent_reference = baseline.parent_resource_id
    if parent_reference is None and baseline.parent_value is not None:
        parent_reference = opaque_reference("PARENT", baseline.parent_value)
    canonical_reference = (
        "CBL-"
        + stable_fingerprint(
            {
                "actor": baseline.actor,
                "object": object_reference,
                "parent": parent_reference,
                "route": baseline.route_family,
                "collection": baseline.collection_route_family,
            }
        )[:16].upper()
    )
    return canonical_reference, object_reference, parent_reference
