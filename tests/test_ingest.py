"""HAR ingestion and redaction tests."""

from pathlib import Path
from typing import Any

import pytest

from finsec.config.workspace import create_workspace
from finsec.errors import HarFormatError
from finsec.ingest.har import ingest_har
from finsec.modeling.models import KnowledgeStatus, ObservationStore
from finsec.utils.redaction import REDACTED, redact_data, redact_text
from finsec.utils.yaml_store import load_yaml


def test_har_import_redacts_secrets_and_is_idempotent(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    har_path, _ = sample_har
    workspace = create_workspace("demo", tmp_path / "workspaces")

    first = ingest_har(har_path, workspace, actor="ACCOUNT_A")
    second = ingest_har(har_path, workspace, actor="ACCOUNT_A")

    assert first.imported == 5
    assert first.skipped == 0
    assert second.imported == 0
    assert second.skipped == 5
    assert second.relabeled == 0
    assert second.total == 5

    redacted_text = first.redacted_har.read_text(encoding="utf-8")
    for secret in (
        "QUERY_SECRET",
        "BEARER_SECRET",
        "SECOND_SECRET",
        "COOKIE_SECRET",
        "RESPONSE_COOKIE_SECRET",
        "BODY_SECRET",
        "PASSWORD_SECRET",
        "123456",
        "LOGIN_TOKEN_SECRET",
    ):
        assert secret not in redacted_text
    assert REDACTED in redacted_text
    assert "https://api.example.test/api/payments/12345" in redacted_text

    store = ObservationStore.model_validate(load_yaml(workspace.observations))
    expected_ids = [f"OBS-{number:06d}" for number in range(1, 6)]
    assert [item.id for item in store.observations] == expected_ids
    assert all(item.knowledge_status == KnowledgeStatus.OBSERVED for item in store.observations)
    assert all(item.actor == "ACCOUNT_A" for item in store.observations)
    assert store.observations[0].query_parameters["access_token"] == [REDACTED]
    assert set(store.observations[4].request_fields) == {"email", "otp", "password"}
    assert "LOGIN_TOKEN_SECRET" not in workspace.observations.read_text(encoding="utf-8")


def test_reingest_refreshes_actor_and_channel_without_changing_observation_ids(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    har_path, _ = sample_har
    workspace = create_workspace("demo", tmp_path / "workspaces")
    first = ingest_har(har_path, workspace, actor="ACCOUNT_A", channel="WEB")

    corrected = ingest_har(har_path, workspace, actor="ACCOUNT_B", channel="MOBILE")

    assert corrected.imported == 0
    assert corrected.skipped == 5
    assert corrected.relabeled == 5
    store = ObservationStore.model_validate(load_yaml(workspace.observations))
    assert [item.id for item in store.observations] == [
        f"OBS-{number:06d}" for number in range(1, 6)
    ]
    assert {item.actor for item in store.observations} == {"ACCOUNT_B"}
    assert {item.channel for item in store.observations} == {"MOBILE"}
    assert first.total == corrected.total == 5


def test_har_import_enforces_file_size_limit(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    har_path, _ = sample_har
    workspace = create_workspace("demo", tmp_path / "workspaces")
    monkeypatch.setattr("finsec.ingest.har_io.MAX_HAR_BYTES", 1)

    with pytest.raises(HarFormatError, match="limited"):
        ingest_har(har_path, workspace)


def test_source_har_is_not_copied_unredacted(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    har_path, _ = sample_har
    workspace = create_workspace("demo", tmp_path / "workspaces")
    result = ingest_har(har_path, workspace)

    files = list(workspace.redacted_har.iterdir())
    assert files == [result.redacted_har]
    assert result.redacted_har.name.endswith("-redacted.har")
    assert har_path.resolve() != result.redacted_har.resolve()


def test_numeric_authentication_codes_are_redacted_without_hiding_status_codes() -> None:
    redacted = redact_data(
        {
            "code": "123456",
            "verification_code": "654321",
            "statusCode": 200,
            "result": "code_sent",
        }
    )

    assert redacted == {
        "code": REDACTED,
        "verification_code": REDACTED,
        "statusCode": 200,
        "result": "code_sent",
    }


def test_malformed_url_like_text_does_not_abort_redaction() -> None:
    value = "https://example.test[not-ipv6]/path?token=SYNTHETIC_SECRET"

    redacted = redact_text(value)

    assert "SYNTHETIC_SECRET" not in redacted
    assert REDACTED in redacted
