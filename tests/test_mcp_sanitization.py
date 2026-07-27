"""Security regression tests for centralized MCP sanitization."""

import json

from finsec.mcp.sanitization import OMITTED, REDACTED_PATH, Sanitizer
from finsec.modeling.models import KnowledgeStatus

CANARIES = {
    "SUPER_SECRET_BEARER_TOKEN",
    "SESSION_COOKIE_CANARY",
    "CSRF_CANARY",
    "researcher@example.test",
    "+1 (202) 555-0199",
    "4111 1111 1111 1111",
    "GB82WEST12345698765432",
}


def test_sanitizer_removes_secrets_pii_values_bodies_examples_and_paths() -> None:
    sanitizer = Sanitizer("workspace-a")
    value = {
        "Authorization": "Bearer SUPER_SECRET_BEARER_TOKEN",
        "Cookie": "session=SESSION_COOKIE_CANARY",
        "x-csrf-token": "CSRF_CANARY",
        "contact": "researcher@example.test +1 (202) 555-0199",
        "card": "4111 1111 1111 1111",
        "iban": "GB82WEST12345698765432",
        "query_parameters": {
            "access_token": ["SUPER_SECRET_BEARER_TOKEN"],
            "include": ["private-value"],
        },
        "body": {"password": "SUPER_SECRET_BEARER_TOKEN"},
        "source_path": "/home/researcher/captures/private.har",
        "original_examples": ["real-object-123"],
        "path": "/accounts/12345?view=private&token=SUPER_SECRET_BEARER_TOKEN",
    }

    result = sanitizer.mapping(value)
    serialized = json.dumps(result, sort_keys=True)

    assert not any(canary in serialized for canary in CANARIES)
    assert "private-value" not in serialized
    assert "real-object-123" not in serialized
    assert result["body"] == OMITTED
    assert result["source_path"] == REDACTED_PATH
    assert result["path"] == "/accounts/{id}?view=%5BREDACTED%5D&token=%5BREDACTED%5D"


def test_route_drops_url_authority_and_preserves_api_path_names() -> None:
    sanitizer = Sanitizer("workspace-a")

    result = sanitizer.route(
        "https://SUPER_SECRET_BEARER_TOKEN@api.example.test/users/12345?view=private"
    )

    assert result == "/users/{id}?view=%5BREDACTED%5D"
    assert "SUPER_SECRET_BEARER_TOKEN" not in result
    assert "api.example.test" not in result


def test_credential_fingerprints_are_one_way_stable_and_context_scoped() -> None:
    first = Sanitizer("workspace-a")
    same_context = Sanitizer("workspace-a")
    other_context = Sanitizer("workspace-b")

    fingerprint = first.credential_fingerprint("SUPER_SECRET_BEARER_TOKEN")

    assert fingerprint == same_context.credential_fingerprint("SUPER_SECRET_BEARER_TOKEN")
    assert fingerprint != other_context.credential_fingerprint("SUPER_SECRET_BEARER_TOKEN")
    assert "SUPER_SECRET_BEARER_TOKEN" not in fingerprint


def test_authentication_tri_state_does_not_treat_redacted_metadata_as_anonymous() -> None:
    sanitizer = Sanitizer("workspace-a")

    present = sanitizer.observation_authentication(
        present=True,
        observed_type="bearer",
        source="HAR",
        knowledge_status=KnowledgeStatus.OBSERVED,
    )
    absent = sanitizer.observation_authentication(
        present=False,
        observed_type="none",
        source="HAR",
        knowledge_status=KnowledgeStatus.OBSERVED,
    )
    unknown = sanitizer.observation_authentication(
        present=False,
        observed_type="none",
        source="OPENAPI",
        knowledge_status=KnowledgeStatus.OBSERVED,
    )

    assert present.state == "PRESENT"
    assert present.value == "<REDACTED>"
    assert absent.state == "ABSENT_CONFIRMED"
    assert unknown.state == "UNKNOWN_OR_REDACTED"
