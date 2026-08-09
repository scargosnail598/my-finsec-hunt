"""Actor authentication capture, lifecycle, preflight, and safety regression tests."""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from finsec.auth.capture import (
    candidate_from_raw_request,
    decode_jwt_metadata,
    detect_burp_authentication,
    detect_har_authentication,
)
from finsec.auth.service import (
    actor_preflight,
    capture_from_burp,
    capture_from_har,
    configure_refresh_from_har,
    ensure_authentication_defaults,
    migrate_legacy_authentication,
    recommend_burp_authentication,
    recommend_har_authentication,
    refresh_actor_authentication,
    validate_actor_baseline,
)
from finsec.auth.store import SecretStore
from finsec.cli import app
from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.errors import FinsecError
from finsec.execution.policy import approve_plan, prepare_execution
from finsec.execution.runner import execute_prepared
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.ingest.har_io import MAX_HAR_BYTES, har_size_limit
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.normalization.inventory import build_inventory
from finsec.setup import AccountInput, build_setup_config, create_setup_workspace
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml, write_yaml

RUNNER = CliRunner()


def test_default_har_limit_accepts_browser_exports_over_100_mb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FINSEC_MAX_HAR_BYTES", raising=False)
    assert MAX_HAR_BYTES == 256 * 1024 * 1024
    assert har_size_limit() == MAX_HAR_BYTES

    monkeypatch.setenv("FINSEC_MAX_HAR_BYTES", str(300 * 1024 * 1024))
    assert har_size_limit() == 300 * 1024 * 1024


def _segment(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(
    subject: str = "user-12",
    *,
    expires_in: int | None = 3600,
    role: str = "customer",
    tenant: str = "tenant-a",
) -> str:
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "tenant": tenant,
        "iat": int(datetime.now(UTC).timestamp()),
    }
    if expires_in is not None:
        payload["exp"] = int((datetime.now(UTC) + timedelta(seconds=expires_in)).timestamp())
    return f"{_segment({'alg': 'none', 'typ': 'JWT'})}.{_segment(payload)}.synthetic"


def _har(path: Path, entries: list[dict[str, Any]]) -> Path:
    path.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "pytest", "version": "1"},
                    "entries": entries,
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _entry(
    url: str,
    token: str,
    *,
    headers: list[dict[str, str]] | None = None,
    cookies: list[dict[str, Any]] | None = None,
    response_status: int = 200,
    response_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    request_headers = [{"name": "Authorization", "value": f"Bearer {token}"}]
    request_headers.extend(headers or [])
    return {
        "startedDateTime": datetime.now(UTC).isoformat(),
        "request": {
            "method": "GET",
            "url": url,
            "headers": request_headers,
            "cookies": cookies or [],
        },
        "response": {
            "status": response_status,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {
                "mimeType": "application/json",
                "text": json.dumps(response_body or {"id": 1}),
            },
        },
    }


def _burp_xml(path: Path, tokens: list[str]) -> Path:
    items: list[str] = []
    for index, token in enumerate(tokens, start=1):
        request = (
            f"GET /profile/{index} HTTP/1.1\r\n"
            "Host: api.example.test\r\n"
            f"Authorization: Bearer {token}\r\n"
            "Accept: application/json\r\n\r\n"
        )
        response = f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{"id":{index}}}'
        items.append(
            "<item>"
            f"<time>{datetime.now(UTC).isoformat()}</time>"
            f"<url>https://api.example.test/profile/{index}</url>"
            "<host>api.example.test</host><port>443</port><protocol>https</protocol>"
            "<method>GET</method><status>200</status><mimetype>application/json</mimetype>"
            f'<request base64="true">{base64.b64encode(request.encode()).decode()}</request>'
            f'<response base64="true">{base64.b64encode(response.encode()).decode()}</response>'
            "</item>"
        )
    path.write_text(
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE items [\n"
        "<!ELEMENT items (item*)>\n"
        "<!ELEMENT item ANY>\n"
        "]>\n"
        f"<items>{''.join(items)}</items>",
        encoding="utf-8",
    )
    return path


def _configured_workspace(tmp_path: Path, *actors: str) -> WorkspacePaths:
    workspace = create_workspace("auth-demo", tmp_path / "workspaces")
    target = TargetDocument.model_validate(load_yaml(workspace.target))
    target.scope.hosts = ["api.example.test"]
    target.accounts = [AccountInput(actor).to_config() for actor in actors or ("ACCOUNT_A",)]
    ensure_authentication_defaults(target)
    write_yaml(workspace.target, target.model_dump(mode="json", exclude_none=True))
    return workspace


def test_setup_initializes_authenticated_and_anonymous_actor_states(tmp_path: Path) -> None:
    config = build_setup_config(
        project_name="Auth Demo",
        slug="auth-demo",
        hosts=["api.example.test"],
        accounts=[AccountInput("ACCOUNT_A"), AccountInput("ANONYMOUS", authenticated=False)],
        production=True,
        base_url="https://api.example.test",
    )
    result = create_setup_workspace(config, tmp_path / "workspaces", tmp_path / "captures")
    target = TargetDocument.model_validate(load_yaml(result.workspace.target))

    authenticated, anonymous = target.accounts
    assert authenticated.authentication is not None
    assert authenticated.authentication.status == "MISSING"
    assert anonymous.actor_type == "anonymous"
    assert anonymous.authentication is not None
    assert anonymous.authentication.auth_type == "none"
    assert anonymous.authentication.status == "NONE"


def test_jwt_metadata_handles_expiration_absence_and_malformed_values() -> None:
    expiration, identity = decode_jwt_metadata(_jwt())
    assert expiration.detectable is True
    assert expiration.expires_at is not None
    assert identity.subject == "user-12"
    assert identity.roles == ["customer"]
    assert identity.tenant == "tenant-a"

    no_expiration, _ = decode_jwt_metadata(_jwt(expires_in=None))
    assert no_expiration.detectable is False
    assert no_expiration.expires_at is None

    malformed, malformed_identity = decode_jwt_metadata("not-a-jwt")
    assert malformed.detectable is False
    assert malformed_identity.subject is None


def test_har_detection_groups_bearer_cookie_and_csrf_without_displaying_values(
    tmp_path: Path,
) -> None:
    secret = _jwt()
    capture = _har(
        tmp_path / "actor.har",
        [
            _entry(
                "https://api.example.test/profile",
                secret,
                headers=[{"name": "X-CSRF-Token", "value": "csrf-synthetic-secret"}],
                cookies=[
                    {
                        "name": "session",
                        "value": "cookie-synthetic-secret",
                        "domain": "api.example.test",
                        "path": "/",
                        "expires": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
                    }
                ],
            )
        ],
    )

    candidates = detect_har_authentication(capture)

    assert len(candidates) == 1
    assert candidates[0].auth_type == "mixed"
    assert {item.name.lower() for item in candidates[0].components} == {
        "authorization",
        "cookie",
        "x-csrf-token",
    }
    cookie = next(item for item in candidates[0].components if item.name.lower() == "cookie")
    assert cookie.cookie_domain == "api.example.test"
    assert cookie.cookie_path == "/"
    assert cookie.cookie_session_only is False
    summary = candidates[0].redacted_summary()
    assert "GET api.example.test/profile" in summary
    assert "HAR entry 1" in summary
    assert secret not in summary
    assert "cookie-synthetic-secret" not in summary
    assert "csrf-synthetic-secret" not in summary


def test_raw_request_extracts_api_key_and_csrf_material(tmp_path: Path) -> None:
    request = tmp_path / "request.txt"
    request.write_text(
        "GET /profile HTTP/1.1\n"
        "Host: api.example.test\n"
        "X-API-Key: api-key-synthetic-secret\n"
        "X-CSRF-Token: csrf-synthetic-secret\n\n",
        encoding="utf-8",
    )

    candidate = candidate_from_raw_request(request)

    assert candidate.auth_type == "api_key"
    assert {item.purpose for item in candidate.components} == {"api_key", "csrf"}


def test_multiple_har_candidates_require_explicit_selection(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    first = _jwt("user-1")
    second = _jwt("user-2")
    capture = _har(
        tmp_path / "multiple.har",
        [
            _entry("https://api.example.test/one", first),
            _entry("https://api.example.test/two", second),
        ],
    )

    with pytest.raises(FinsecError, match="Multiple authentication candidates"):
        capture_from_har(workspace, "ACCOUNT_A", capture)

    authentication, _ = capture_from_har(workspace, "ACCOUNT_A", capture, candidate_number=1)
    assert authentication.identity.subject == "user-1"


def test_burp_authentication_candidates_are_secret_free_and_storable(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    token = _jwt("burp-user")
    capture = _burp_xml(tmp_path / "auth.xml", [token])

    candidates = detect_burp_authentication(capture)
    recommendation = recommend_burp_authentication(workspace, "ACCOUNT_A", capture)
    authentication, _ = capture_from_burp(
        workspace,
        "ACCOUNT_A",
        capture,
        candidate_number=1,
    )

    assert len(candidates) == 1
    assert "Burp item 1" in candidates[0].redacted_summary()
    assert token not in candidates[0].redacted_summary()
    assert recommendation.recommended_number == 1
    assert token not in repr(recommendation)
    assert authentication.source.type == "burp_xml"
    assert authentication.source.file_reference == capture.name
    reference = authentication.components[0].credential_ref
    assert SecretStore(workspace).resolve(reference, "ACCOUNT_A") == f"Bearer {token}"


def test_cli_ingest_burp_can_capture_authentication_without_echoing_secrets(
    tmp_path: Path,
) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    token = _jwt("burp-cli-user")
    capture = _burp_xml(tmp_path / "auth-cli.xml", [token])

    result = RUNNER.invoke(
        app,
        [
            "ingest-burp",
            str(capture),
            "--workspace",
            str(workspace.root),
            "--actor",
            "ACCOUNT_A",
            "--channel",
            "WEB",
            "--capture-auth",
            "--auth-candidate",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Credential storage: successful" in result.output
    assert "Actor status: READY" in result.output
    assert token not in result.output
    target = TargetDocument.model_validate(load_yaml(workspace.target))
    authentication = target.accounts[0].authentication
    assert authentication is not None
    assert authentication.source.type == "burp_xml"


def test_cli_actor_auth_refresh_accepts_burp_xml(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    token = _jwt("burp-refresh-user")
    capture = _burp_xml(tmp_path / "auth-refresh.xml", [token])

    result = RUNNER.invoke(
        app,
        [
            "actor",
            "auth",
            "refresh",
            "ACCOUNT_A",
            "--workspace",
            str(workspace.root),
            "--burp",
            str(capture),
            "--auth-candidate",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Credential replaced for ACCOUNT_A" in result.output
    assert token not in result.output


def test_auth_recommendation_prefers_fresh_same_identity_request(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    old_token = _jwt("user-12", expires_in=60)
    old_entry = _entry("https://api.example.test/profile", old_token)
    old_entry["startedDateTime"] = "2026-01-02T10:00:00Z"
    old_capture = _har(tmp_path / "old.har", [old_entry])
    capture_from_har(workspace, "ACCOUNT_A", old_capture, candidate_number=1)

    renewed_token = _jwt("user-12", expires_in=3600)
    changed_token = _jwt("different-user", expires_in=7200)
    old_request = _entry("https://api.example.test/profile", old_token)
    old_request["startedDateTime"] = "2026-01-02T10:01:00Z"
    renewed_request = _entry("https://api.example.test/rest/basket/7", renewed_token)
    renewed_request["startedDateTime"] = "2026-01-02T10:02:00Z"
    changed_request = _entry("https://api.example.test/admin", changed_token)
    changed_request["startedDateTime"] = "2026-01-02T10:03:00Z"
    replacement = _har(
        tmp_path / "replacement.har",
        [old_request, renewed_request, changed_request],
    )

    recommendation = recommend_har_authentication(workspace, "ACCOUNT_A", replacement)

    assert recommendation.recommended_number == 2
    assert recommendation.assessments[1].recommended is True
    assert recommendation.assessments[2].eligible is False
    assert any(
        "identity hints conflict" in reason for reason in recommendation.assessments[2].reasons
    )
    rendered = repr(recommendation)
    assert old_token not in rendered
    assert renewed_token not in rendered
    assert changed_token not in rendered


def test_cli_update_auth_uses_recommended_request_without_echoing_tokens(
    tmp_path: Path,
) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    old_token = _jwt("user-12", expires_in=60)
    old_entry = _entry("https://api.example.test/profile", old_token)
    old_entry["startedDateTime"] = "2026-01-02T10:00:00Z"
    capture_from_har(
        workspace,
        "ACCOUNT_A",
        _har(tmp_path / "old.har", [old_entry]),
        candidate_number=1,
    )
    new_token = _jwt("user-12", expires_in=3600)
    old_request = _entry("https://api.example.test/profile", old_token)
    old_request["startedDateTime"] = "2026-01-02T10:01:00Z"
    new_request = _entry("https://api.example.test/rest/basket/7", new_token)
    new_request["startedDateTime"] = "2026-01-02T10:02:00Z"
    replacement = _har(tmp_path / "replacement.har", [old_request, new_request])

    result = RUNNER.invoke(
        app,
        [
            "ingest",
            str(replacement),
            "--workspace",
            str(workspace.root),
            "--actor",
            "ACCOUNT_A",
            "--channel",
            "WEB",
            "--update-auth",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Recommended authentication request 2" in result.output
    assert "Automatically selected recommended authentication request 2" in result.output
    assert old_token not in result.output
    assert new_token not in result.output
    target = TargetDocument.model_validate(load_yaml(workspace.target))
    authentication = target.accounts[0].authentication
    assert authentication is not None
    assert authentication.source.file_reference == replacement.name
    reference = authentication.components[0].credential_ref
    assert SecretStore(workspace).resolve(reference, "ACCOUNT_A") == f"Bearer {new_token}"


def test_ingest_wizard_imports_multiple_new_hars_and_updates_authentication(
    tmp_path: Path,
) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A", "ACCOUNT_B")
    capture_root = tmp_path / "captures" / "auth-demo"
    incoming = capture_root / "incoming"
    incoming.mkdir(parents=True)

    new_tokens: dict[str, str] = {}
    for index, actor in enumerate(("ACCOUNT_A", "ACCOUNT_B"), start=1):
        old_token = _jwt(f"user-{index}", expires_in=60)
        old_entry = _entry("https://api.example.test/profile", old_token)
        old_entry["startedDateTime"] = f"2026-01-02T10:0{index}:00Z"
        capture_from_har(
            workspace,
            actor,
            _har(tmp_path / f"old-{index}.har", [old_entry]),
            candidate_number=1,
        )
        new_token = _jwt(f"user-{index}", expires_in=3600)
        new_tokens[actor] = new_token
        renewed = _entry("https://api.example.test/profile", new_token)
        renewed["startedDateTime"] = f"2026-01-02T11:0{index}:00Z"
        _har(incoming / f"new-{index}.har", [renewed])

    result = RUNNER.invoke(
        app,
        [
            "ingest-wizard",
            "--workspace",
            str(workspace.root),
            "--capture-root",
            str(capture_root),
        ],
        input="ACCOUNT_A\n\n\nACCOUNT_B\n\n\ny\nn\n",
    )

    assert result.exit_code == 0, result.output
    assert result.output.count("Recommended authentication request 1") == 2
    assert result.output.count("Authentication updated") == 2
    assert all(token not in result.output for token in new_tokens.values())
    manifest = load_yaml(capture_root / "workflow.yaml")
    assert manifest["captures"] == [
        {"file": "new-1.har", "actor": "ACCOUNT_A", "channel": "WEB", "enabled": True},
        {"file": "new-2.har", "actor": "ACCOUNT_B", "channel": "WEB", "enabled": True},
    ]
    target = TargetDocument.model_validate(load_yaml(workspace.target))
    for actor in target.accounts:
        authentication = actor.authentication
        assert authentication is not None
        reference = authentication.components[0].credential_ref
        assert SecretStore(workspace).resolve(reference, actor.id) == (
            f"Bearer {new_tokens[actor.id]}"
        )


def test_secret_store_is_actor_bound_restricted_and_absent_from_workspace(
    tmp_path: Path,
) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A", "ACCOUNT_B")
    token = _jwt("user-a")
    capture = _har(
        tmp_path / "account-a.har",
        [_entry("https://api.example.test/profile", token)],
    )
    authentication, _ = capture_from_har(workspace, "ACCOUNT_A", capture, candidate_number=1)
    reference = authentication.components[0].credential_ref
    store = SecretStore(workspace)

    assert store.resolve(reference, "ACCOUNT_A") == f"Bearer {token}"
    with pytest.raises(FinsecError, match="another actor"):
        store.resolve(reference, "ACCOUNT_B")
    assert store.permissions() == 0o600
    assert not store.path.is_relative_to(workspace.root)
    assert token not in workspace.target.read_text(encoding="utf-8")
    assert token not in "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in workspace.root.rglob("*")
        if path.is_file()
    )

    store.path.chmod(0o644)
    with pytest.raises(FinsecError, match="permissions are too broad"):
        store.resolve(reference, "ACCOUNT_A")


def test_expired_and_expiring_credentials_fail_closed_for_execution(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    expired = _har(
        tmp_path / "expired.har",
        [_entry("https://api.example.test/profile", _jwt(expires_in=-60))],
    )
    capture_from_har(workspace, "ACCOUNT_A", expired, candidate_number=1)
    preflight = actor_preflight(workspace, "ACCOUNT_A", for_execution=True)
    assert preflight.status == "EXPIRED"
    assert preflight.result == "BLOCKED_BY_AUTH"

    soon = _har(
        tmp_path / "soon.har",
        [_entry("https://api.example.test/profile", _jwt(expires_in=90))],
    )
    capture_from_har(workspace, "ACCOUNT_A", soon, candidate_number=1, observed_renewal=True)
    planning = actor_preflight(workspace, "ACCOUNT_A")
    execution = actor_preflight(workspace, "ACCOUNT_A", for_execution=True)
    assert planning.status == "EXPIRING_SOON"
    assert planning.result == "READY_FOR_PLANNING"
    assert execution.result == "BLOCKED_BY_AUTH"


def test_anonymous_actor_can_never_receive_a_credential(tmp_path: Path) -> None:
    workspace = create_workspace("anonymous", tmp_path / "workspaces")
    target = TargetDocument.model_validate(load_yaml(workspace.target))
    target.scope.hosts = ["api.example.test"]
    target.accounts = [AccountInput("ANONYMOUS", authenticated=False).to_config()]
    ensure_authentication_defaults(target)
    write_yaml(workspace.target, target.model_dump(mode="json", exclude_none=True))
    capture = _har(
        tmp_path / "anonymous.har",
        [_entry("https://api.example.test/profile", _jwt())],
    )

    with pytest.raises(FinsecError, match="cannot receive authentication"):
        capture_from_har(workspace, "ANONYMOUS", capture, candidate_number=1)


def test_actor_credential_capture_must_match_target_scope(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    capture = _har(
        tmp_path / "outside-auth.har",
        [_entry("https://outside.example.test/profile", _jwt())],
    )

    with pytest.raises(FinsecError, match="outside target scope"):
        capture_from_har(workspace, "ACCOUNT_A", capture, candidate_number=1)


def _auth_plan_workspace(
    tmp_path: Path, *, port: int = 9, active_execution: bool = False
) -> tuple[WorkspacePaths, str, str]:
    workspace = create_workspace("actor-plan", tmp_path / "workspaces")
    target = TargetDocument.model_validate(load_yaml(workspace.target))
    target.scope.hosts = ["127.0.0.1"]
    target.testing.local_lab = True
    target.testing.synthetic = True
    target.testing.active_execution_enabled = active_execution
    target.accounts = [AccountInput("ACCOUNT_A").to_config(), AccountInput("ACCOUNT_B").to_config()]
    ensure_authentication_defaults(target)
    write_yaml(workspace.target, target.model_dump(mode="json", exclude_none=True))
    tokens = {"ACCOUNT_A": _jwt("user-a"), "ACCOUNT_B": _jwt("user-b")}
    for index, (actor, basket_id, owner_id) in enumerate(
        [("ACCOUNT_A", 6, 10), ("ACCOUNT_B", 7, 11)], start=1
    ):
        capture = _har(
            tmp_path / f"actor-{index}.har",
            [
                _entry(
                    f"http://127.0.0.1:{port}/rest/basket/{basket_id}",
                    tokens[actor],
                    response_body={
                        "status": "success",
                        "data": {"id": basket_id, "UserId": owner_id, "Products": []},
                    },
                )
            ],
        )
        ingest_har(
            capture,
            workspace,
            actor=actor,
            channel="WEB",
            capture_auth=True,
            auth_candidate=1,
        )
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    hypothesis = next(
        item
        for item in hypotheses.hypotheses
        if item.kind == "SECURITY_HYPOTHESIS" and item.category == "authorization"
    )
    return workspace, hypothesis.id, tokens["ACCOUNT_B"]


def test_actor_aware_plan_uses_secret_references_and_dry_run_resolves_them(
    tmp_path: Path,
) -> None:
    workspace, hypothesis_id, token = _auth_plan_workspace(tmp_path)

    plan = generate_plan(workspace, hypothesis_id).plan

    assert plan.status == "READY_FOR_REVIEW"
    assert plan.authentication[0].actor == "ACCOUNT_B"
    assert plan.authentication[0].credential_profile_ref == "actor-account-b-default"
    assert all(item.source == "actor_store" for item in plan.requests[0].runtime_secrets)
    plan_text = workspace.test_plans.read_text(encoding="utf-8")
    assert token not in plan_text
    assert "FINSEC_ACCOUNT_B_AUTH" not in plan_text
    target = TargetDocument.model_validate(load_yaml(workspace.target))
    target.testing.active_execution_enabled = True
    write_yaml(workspace.target, target.model_dump(mode="json", exclude_none=True))
    generate_plan(workspace, hypothesis_id)
    approve_plan(workspace, hypothesis_id, approved_by="pytest")
    prepared = prepare_execution(workspace, hypothesis_id, dry_run=True)
    assert prepared.authentication_preflight[0].result == "READY_FOR_PLANNING"
    assert prepared.runtime_headers == {}


def test_planner_blocks_missing_and_expired_actor_authentication(tmp_path: Path) -> None:
    workspace = create_workspace("blocked-auth-plan", tmp_path / "workspaces")
    target = TargetDocument.model_validate(load_yaml(workspace.target))
    target.scope.hosts = ["127.0.0.1"]
    target.testing.local_lab = True
    target.accounts = [AccountInput("ACCOUNT_A").to_config(), AccountInput("ACCOUNT_B").to_config()]
    ensure_authentication_defaults(target)
    write_yaml(workspace.target, target.model_dump(mode="json", exclude_none=True))
    for index, (actor, basket_id, owner_id) in enumerate(
        [("ACCOUNT_A", 6, 10), ("ACCOUNT_B", 7, 11)], start=1
    ):
        capture = _har(
            tmp_path / f"missing-{index}.har",
            [
                _entry(
                    f"http://127.0.0.1:9/rest/basket/{basket_id}",
                    _jwt(actor, expires_in=-60 if actor == "ACCOUNT_B" else 3600),
                    response_body={
                        "status": "success",
                        "data": {"id": basket_id, "UserId": owner_id, "Products": []},
                    },
                )
            ],
        )
        ingest_har(capture, workspace, actor=actor, channel="WEB")
        if actor == "ACCOUNT_B":
            capture_from_har(workspace, actor, capture, candidate_number=1)
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    hypothesis = next(item for item in hypotheses.hypotheses if item.category == "authorization")

    plan = generate_plan(workspace, hypothesis.id).plan

    assert plan.status == "READY_FOR_REVIEW"
    assert plan.risk.decision == "REQUIRES_HUMAN_APPROVAL"
    assert plan.planning_blockers == []
    assert plan.execution.supported is False
    assert any("ACCOUNT_B authentication" in reason for reason in plan.execution.blockers)
    assert any("expiration" in reason.lower() for reason in plan.execution.blockers)


def test_cli_capture_and_manual_entry_never_echo_secrets(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    token = _jwt("cli-user")
    capture = _har(tmp_path / "cli.har", [_entry("https://api.example.test/profile", token)])
    imported = RUNNER.invoke(
        app,
        [
            "ingest",
            str(capture),
            "--workspace",
            str(workspace.root),
            "--actor",
            "ACCOUNT_A",
            "--capture-auth",
            "--auth-candidate",
            "1",
        ],
    )
    assert imported.exit_code == 0, imported.output
    assert token not in imported.output

    manual_secret = "manual-synthetic-secret"
    manual = RUNNER.invoke(
        app,
        [
            "actor",
            "auth",
            "set",
            "ACCOUNT_A",
            "--workspace",
            str(workspace.root),
            "--type",
            "api_key",
            "--header",
            "X-API-Key",
        ],
        input=f"{manual_secret}\n{manual_secret}\n",
    )
    assert manual.exit_code == 0, manual.output
    assert manual_secret not in manual.output


def test_execution_evidence_and_audit_never_contain_resolved_actor_secret(
    tmp_path: Path,
) -> None:
    with auth_server() as server:
        workspace, hypothesis_id, token = _auth_plan_workspace(
            tmp_path, port=server.server_port, active_execution=True
        )
        generate_plan(workspace, hypothesis_id)
        approve_plan(workspace, hypothesis_id, approved_by="pytest")

        result = execute_prepared(prepare_execution(workspace, hypothesis_id, dry_run=False))

        assert result.requests_sent == 2
        generated = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in workspace.root.rglob("*")
            if path.is_file()
        )
        assert token not in generated
        assert f"Bearer {token}" not in generated


def test_material_replacement_is_rejected_and_invalidates_approval(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    first = _har(
        tmp_path / "first.har",
        [_entry("https://api.example.test/profile", _jwt("user-12"))],
    )
    capture_from_har(workspace, "ACCOUNT_A", first, candidate_number=1)
    write_yaml(
        workspace.test_plans,
        {"version": 1, "plans": [{"approval_status": "APPROVED", "approval": {"x": 1}}]},
    )
    changed = _har(
        tmp_path / "changed.har",
        [_entry("https://api.example.test/profile", _jwt("user-44"))],
    )

    with pytest.raises(FinsecError, match="AUTH_CONTEXT_CHANGED"):
        capture_from_har(workspace, "ACCOUNT_A", changed, candidate_number=1)

    target = TargetDocument.model_validate(load_yaml(workspace.target))
    assert target.accounts[0].authentication is not None
    assert target.accounts[0].authentication.status == "AUTH_CONTEXT_CHANGED"
    plan = load_yaml(workspace.test_plans)["plans"][0]
    assert plan["approval_status"] == "NOT_REQUESTED"
    assert "approval" not in plan


def test_verified_same_identity_renewal_preserves_approval(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    first = _har(
        tmp_path / "renewal-first.har",
        [_entry("https://api.example.test/profile", _jwt("user-12", expires_in=60))],
    )
    capture_from_har(workspace, "ACCOUNT_A", first, candidate_number=1)
    write_yaml(
        workspace.test_plans,
        {"version": 1, "plans": [{"approval_status": "APPROVED", "approval": {"x": 1}}]},
    )
    renewed = _har(
        tmp_path / "renewed.har",
        [_entry("https://api.example.test/profile", _jwt("user-12", expires_in=3600))],
    )

    authentication, _ = capture_from_har(
        workspace,
        "ACCOUNT_A",
        renewed,
        candidate_number=1,
        observed_renewal=True,
    )

    assert authentication.status == "READY"
    plan = load_yaml(workspace.test_plans)["plans"][0]
    assert plan["approval_status"] == "APPROVED"
    assert plan["approval"] == {"x": 1}


class AuthServer(ThreadingHTTPServer):
    response_token: str
    get_status: int
    received: list[tuple[str, str]]


class AuthHandler(BaseHTTPRequestHandler):
    server: AuthServer

    def do_GET(self) -> None:  # noqa: N802
        self.server.received.append(("GET", self.path))
        if self.path.startswith("/rest/basket/"):
            basket_id = int(self.path.rsplit("/", 1)[-1])
            owner_id = 11 if basket_id == 7 else 10
            body = json.dumps(
                {
                    "status": "success",
                    "data": {"id": basket_id, "UserId": owner_id, "Products": []},
                }
            ).encode()
        else:
            body = b'{"id":"user-12"}'
        self.send_response(self.server.get_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        self.server.received.append(("POST", body))
        response = json.dumps(
            {"access_token": self.server.response_token, "refresh_token": "rotated-refresh"}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def auth_server(*, get_status: int = 200, subject: str = "user-12") -> Iterator[AuthServer]:
    server = AuthServer(("127.0.0.1", 0), AuthHandler)
    server.response_token = _jwt(subject)
    server.get_status = get_status
    server.received = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _local_auth_workspace(tmp_path: Path, port: int, token: str) -> tuple[WorkspacePaths, Path]:
    workspace = create_workspace("refresh-demo", tmp_path / "workspaces")
    target = TargetDocument.model_validate(load_yaml(workspace.target))
    target.scope.hosts = ["127.0.0.1"]
    target.testing.local_lab = True
    target.testing.synthetic = True
    target.testing.active_execution_enabled = True
    target.accounts = [AccountInput("ACCOUNT_A").to_config()]
    ensure_authentication_defaults(target)
    write_yaml(workspace.target, target.model_dump(mode="json", exclude_none=True))
    access_har = _har(
        tmp_path / "access.har",
        [_entry(f"http://127.0.0.1:{port}/profile", token)],
    )
    capture_from_har(workspace, "ACCOUNT_A", access_har, candidate_number=1)
    return workspace, access_har


def test_observed_refresh_uses_one_request_and_rotates_access_and_refresh_secrets(
    tmp_path: Path,
) -> None:
    with auth_server() as server:
        workspace, _ = _local_auth_workspace(tmp_path, server.server_port, _jwt(expires_in=-60))
        refresh_har = _har(
            tmp_path / "refresh.har",
            [
                {
                    "startedDateTime": datetime.now(UTC).isoformat(),
                    "request": {
                        "method": "POST",
                        "url": f"http://127.0.0.1:{server.server_port}/refresh?client=web",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"refresh_token": "original-refresh"}),
                        },
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {
                                    "access_token": _jwt(),
                                    "refresh_token": "observed-rotated-refresh",
                                }
                            ),
                        },
                    },
                }
            ],
        )
        configured = configure_refresh_from_har(workspace, "ACCOUNT_A", refresh_har)

        result = refresh_actor_authentication(workspace, "ACCOUNT_A")

        assert configured.path == "/refresh?client=web"
        assert result.request_count == 1
        assert result.new_credential_received is True
        assert result.identity_continuity == "CONFIRMED"
        assert len(server.received) == 1
        assert server.received[0][0] == "POST"
        assert "original-refresh" in server.received[0][1]
        target = TargetDocument.model_validate(load_yaml(workspace.target))
        authentication = target.accounts[0].authentication
        assert authentication is not None
        access = next(item for item in authentication.components if item.purpose == "access")
        refresh = next(item for item in authentication.components if item.purpose == "refresh")
        store = SecretStore(workspace)
        assert store.resolve(access.credential_ref, "ACCOUNT_A") == (
            f"Bearer {server.response_token}"
        )
        assert store.resolve(refresh.credential_ref, "ACCOUNT_A") == "rotated-refresh"


def test_refresh_rejects_a_new_credential_for_another_identity(tmp_path: Path) -> None:
    with auth_server(subject="user-44") as server:
        workspace, _ = _local_auth_workspace(tmp_path, server.server_port, _jwt("user-12"))
        refresh_har = _har(
            tmp_path / "changed-refresh.har",
            [
                {
                    "request": {
                        "method": "POST",
                        "url": f"http://127.0.0.1:{server.server_port}/refresh",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {"text": '{"refresh_token":"original-refresh"}'},
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {
                            "text": json.dumps(
                                {
                                    "access_token": _jwt("user-12"),
                                    "refresh_token": "rotated-refresh",
                                }
                            )
                        },
                    },
                }
            ],
        )
        configure_refresh_from_har(workspace, "ACCOUNT_A", refresh_har)

        with pytest.raises(FinsecError, match="AUTH_CONTEXT_CHANGED"):
            refresh_actor_authentication(workspace, "ACCOUNT_A")

        assert len(server.received) == 1
        target = TargetDocument.model_validate(load_yaml(workspace.target))
        assert target.accounts[0].authentication is not None
        assert target.accounts[0].authentication.status == "AUTH_CONTEXT_CHANGED"


def test_target_baseline_check_marks_401_invalid_and_success_ready(tmp_path: Path) -> None:
    with auth_server(get_status=401) as server:
        workspace, _ = _local_auth_workspace(tmp_path, server.server_port, _jwt())
        failed = validate_actor_baseline(workspace, "ACCOUNT_A")
        assert failed.request_count == 1
        assert failed.actor_baseline_matched is False
        assert failed.preflight.status == "INVALID"

        server.get_status = 200
        target = TargetDocument.model_validate(load_yaml(workspace.target))
        assert target.accounts[0].authentication is not None
        target.accounts[0].authentication.status = "AVAILABLE_NOT_VALIDATED"
        write_yaml(workspace.target, target.model_dump(mode="json", exclude_none=True))
        succeeded = validate_actor_baseline(workspace, "ACCOUNT_A")
        assert succeeded.actor_baseline_matched is True
        assert succeeded.preflight.status == "READY"
        assert succeeded.preflight.baseline_identity_confirmed is True


def test_legacy_migration_records_only_variable_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = create_workspace("legacy", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [{"id": "ACCOUNT_A", "ownership": "researcher"}]
    write_yaml(workspace.target, target)
    monkeypatch.setenv("FINSEC_ACCOUNT_A_AUTH", "legacy-synthetic-secret")

    assert migrate_legacy_authentication(workspace) == 1

    text = workspace.target.read_text(encoding="utf-8")
    assert "FINSEC_ACCOUNT_A_AUTH" in text
    assert "legacy-synthetic-secret" not in text
    assert actor_preflight(workspace, "ACCOUNT_A").credential_available is True


def test_out_of_scope_refresh_flow_is_rejected_without_a_request(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, "ACCOUNT_A")
    access = _har(
        tmp_path / "access.har",
        [_entry("https://api.example.test/profile", _jwt())],
    )
    capture_from_har(workspace, "ACCOUNT_A", access, candidate_number=1)
    refresh = _har(
        tmp_path / "outside.har",
        [
            {
                "request": {
                    "method": "POST",
                    "url": "https://outside.example.test/refresh",
                    "headers": [],
                    "postData": {"text": '{"refresh_token":"synthetic-refresh"}'},
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"text": '{"access_token":"synthetic-access"}'},
                },
            }
        ],
    )

    with pytest.raises(FinsecError, match="outside target scope"):
        configure_refresh_from_har(workspace, "ACCOUNT_A", refresh)

    unsafe_scheme = _har(
        tmp_path / "unsafe-scheme.har",
        [
            {
                "request": {
                    "method": "POST",
                    "url": "ftp://api.example.test/refresh",
                    "headers": [],
                    "postData": {"text": '{"refresh_token":"synthetic-refresh"}'},
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"text": '{"access_token":"synthetic-access"}'},
                },
            }
        ],
    )
    with pytest.raises(FinsecError, match=r"safe HTTP\(S\) URL"):
        configure_refresh_from_har(workspace, "ACCOUNT_A", unsafe_scheme)


def test_end_to_end_expiration_replacement_preflight_and_bounded_execution(
    tmp_path: Path,
) -> None:
    with auth_server() as server:
        workspace, hypothesis_id, old_token = _auth_plan_workspace(
            tmp_path, port=server.server_port, active_execution=True
        )
        plan = generate_plan(workspace, hypothesis_id).plan
        approve_plan(workspace, hypothesis_id, approved_by="pytest")
        assert prepare_execution(workspace, hypothesis_id, dry_run=True).runtime_headers == {}

        target = TargetDocument.model_validate(load_yaml(workspace.target))
        actor_b = next(item for item in target.accounts if item.id == "ACCOUNT_B")
        assert actor_b.authentication is not None
        actor_b.authentication.expiration.detectable = True
        actor_b.authentication.expiration.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        actor_b.authentication.status = "EXPIRED"
        write_yaml(workspace.target, target.model_dump(mode="json", exclude_none=True))

        with pytest.raises(FinsecError, match="Execution blocked before mutation"):
            prepare_execution(workspace, hypothesis_id, dry_run=True)
        assert server.received == []

        new_token = _jwt("user-b", expires_in=3600)
        replacement = _har(
            tmp_path / "account-b-new.har",
            [
                _entry(
                    f"http://127.0.0.1:{server.server_port}/rest/basket/7",
                    new_token,
                    response_body={
                        "status": "success",
                        "data": {"id": 7, "UserId": 11, "Products": []},
                    },
                )
            ],
        )
        capture_from_har(workspace, "ACCOUNT_B", replacement, candidate_number=1)

        prepared = prepare_execution(workspace, hypothesis_id, dry_run=False)
        result = execute_prepared(prepared)

        assert plan.authentication[0].actor == "ACCOUNT_B"
        assert result.requests_sent == 2
        assert result.comparison.outcome == "CROSS_OBJECT_RESPONSE_OBSERVED"
        assert [item[1] for item in server.received] == [
            "/rest/basket/7",
            "/rest/basket/6",
        ]
        artifacts = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in workspace.root.rglob("*")
            if path.is_file()
        )
        assert old_token not in artifacts
        assert new_token not in artifacts
