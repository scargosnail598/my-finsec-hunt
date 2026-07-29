"""Actor authentication lifecycle, continuity, preflight, and observed refresh handling."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlencode, urlsplit

from pydantic import ValidationError

from finsec.auth.capture import (
    AuthenticationCandidate,
    CapturedSecret,
    candidate_from_raw_request,
    decode_jwt_metadata,
    detect_har_authentication,
)
from finsec.auth.store import SecretStore
from finsec.config.models import (
    AccountConfig,
    ActorAuthenticationConfig,
    AuthenticationComponentConfig,
    AuthenticationExpirationConfig,
    AuthenticationIdentityConfig,
    AuthenticationRefreshConfig,
    AuthenticationSourceConfig,
    AuthenticationStatus,
    TargetDocument,
)
from finsec.config.scope import host_is_covered
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError, HarFormatError
from finsec.ingest.har_io import load_har_json
from finsec.modeling.merge import stable_fingerprint
from finsec.utils.yaml_store import load_yaml, write_yaml

SECRET_MARKER = "[FINSEC-REFRESH-CREDENTIAL]"


@dataclass(frozen=True)
class AuthenticationPreflight:
    """Redacted local authentication decision for one actor."""

    actor_id: str
    auth_type: str
    status: AuthenticationStatus
    credential_available: bool
    expires_at: datetime | None
    remaining_seconds: int | None
    refresh_available: bool
    target_validated: bool
    baseline_identity_confirmed: bool
    result: Literal["READY_FOR_EXECUTION", "READY_FOR_PLANNING", "BLOCKED_BY_AUTH"]
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class RefreshResult:
    """Redacted result of one bounded observed refresh request."""

    actor_id: str
    status: AuthenticationStatus
    request_count: int
    new_credential_received: bool
    identity_continuity: Literal["CONFIRMED", "CHANGED", "UNKNOWN"]


@dataclass(frozen=True)
class AuthenticationCheckResult:
    """Redacted result of one explicit observed-baseline request."""

    preflight: AuthenticationPreflight
    request_count: int
    status_code: int | None
    actor_baseline_matched: bool


def _load_target(workspace: WorkspacePaths) -> TargetDocument:
    try:
        return TargetDocument.model_validate(load_yaml(workspace.target))
    except (OSError, ValidationError) as error:
        raise FinsecError("Cannot load actor authentication metadata.") from error


def _account(target: TargetDocument, actor_id: str) -> AccountConfig:
    actor = next((item for item in target.accounts if item.id == actor_id), None)
    if actor is None:
        raise FinsecError(f"Actor {actor_id!r} is not configured in target.yaml.")
    return actor


def _write_target(workspace: WorkspacePaths, target: TargetDocument) -> None:
    write_yaml(workspace.target, target.model_dump(mode="json", exclude_none=True))


def _actor_token(actor_id: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "-", actor_id.lower()).strip("-")
    return token or "actor"


def _component_token(name: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return token or "credential"


def _identity_document(identity: AuthenticationIdentityConfig) -> dict[str, Any]:
    return {
        "subject": identity.subject,
        "roles": sorted(identity.roles),
        "tenant": identity.tenant,
        "baseline_identifier_fingerprint": identity.baseline_identifier_fingerprint,
    }


def authentication_context_fingerprint(
    actor_id: str,
    auth_type: str,
    identity: AuthenticationIdentityConfig,
    target_hosts: list[str],
) -> str:
    """Hash only non-secret identity and target context."""

    return stable_fingerprint(
        {
            "actor": actor_id,
            "auth_type": auth_type,
            "identity": _identity_document(identity),
            "target_hosts": sorted(target_hosts),
        }
    )


def _identity_continuity(
    previous: AuthenticationIdentityConfig,
    replacement: AuthenticationIdentityConfig,
) -> Literal["CONFIRMED", "CHANGED", "UNKNOWN"]:
    fields = (
        (previous.subject, replacement.subject),
        (previous.tenant, replacement.tenant),
    )
    for before, after in fields:
        if before is not None and after is not None and before != after:
            return "CHANGED"
    if previous.roles and replacement.roles and set(previous.roles) != set(replacement.roles):
        return "CHANGED"
    comparable = any(before is not None and after is not None for before, after in fields)
    comparable = comparable or bool(previous.roles and replacement.roles)
    return "CONFIRMED" if comparable else "UNKNOWN"


def _invalidate_approvals(workspace: WorkspacePaths) -> None:
    if not workspace.test_plans.is_file():
        return
    document = load_yaml(workspace.test_plans)
    plans = document.get("plans") if isinstance(document, dict) else None
    if not isinstance(plans, list):
        return
    changed = False
    for plan in plans:
        if isinstance(plan, dict) and (
            plan.get("approval") or plan.get("approval_status") == "APPROVED"
        ):
            plan["approval_status"] = "NOT_REQUESTED"
            plan.pop("approval", None)
            note = str(plan.get("notes") or "").strip()
            suffix = "Approval invalidated because the actor authentication context changed."
            plan["notes"] = f"{note}\n{suffix}".strip()
            changed = True
    if changed:
        write_yaml(workspace.test_plans, document)


def anonymous_authentication() -> ActorAuthenticationConfig:
    """Return an explicit no-auth profile that cannot resolve credentials."""

    return ActorAuthenticationConfig(
        auth_type="none",
        source=AuthenticationSourceConfig(type="none"),
        status="NONE",
    )


def missing_authentication() -> ActorAuthenticationConfig:
    """Return an explicit incomplete profile for an authenticated actor."""

    return ActorAuthenticationConfig(
        auth_type="unconfigured",
        source=AuthenticationSourceConfig(type="manual"),
        status="MISSING",
    )


def ensure_authentication_defaults(target: TargetDocument) -> TargetDocument:
    """Populate new setup actors without changing legacy accounts loaded from old workspaces."""

    for actor in target.accounts:
        if actor.actor_type is None:
            actor.actor_type = "authenticated_user" if actor.authenticated else "anonymous"
        if actor.authentication is None:
            actor.authentication = (
                anonymous_authentication()
                if actor.actor_type == "anonymous"
                else missing_authentication()
            )
    return target


def _status_for_expiration(
    expiration: AuthenticationExpirationConfig,
    *,
    threshold_seconds: int,
    otherwise: AuthenticationStatus,
) -> AuthenticationStatus:
    if expiration.expires_at is None:
        return otherwise
    remaining = (expiration.expires_at.astimezone(UTC) - datetime.now(UTC)).total_seconds()
    if remaining <= 0:
        return "EXPIRED"
    if remaining <= threshold_seconds:
        return "EXPIRING_SOON"
    return otherwise


def _candidate_components(
    actor_id: str, candidate: AuthenticationCandidate
) -> tuple[list[AuthenticationComponentConfig], list[tuple[str, str, str, str]]]:
    metadata: list[AuthenticationComponentConfig] = []
    secrets: list[tuple[str, str, str, str]] = []
    used: dict[str, int] = {}
    for captured in candidate.components:
        base = f"actor-auth-{_actor_token(actor_id)}-{_component_token(captured.name)}"
        used[base] = used.get(base, 0) + 1
        reference = base if used[base] == 1 else f"{base}-{used[base]}"
        metadata.append(
            AuthenticationComponentConfig(
                name=captured.name,
                location=cast(Any, captured.location),
                credential_ref=reference,
                purpose=captured.purpose,  # type: ignore[arg-type]
                replay_required=captured.purpose != "refresh",
                value_prefix=captured.value_prefix,
                cookie_domain=captured.cookie_domain,
                cookie_path=captured.cookie_path,
                cookie_session_only=captured.cookie_session_only,
            )
        )
        secrets.append((reference, actor_id, captured.purpose, captured.value))
    return metadata, secrets


def store_candidate(
    workspace: WorkspacePaths,
    actor_id: str,
    candidate: AuthenticationCandidate,
    *,
    source_type: Literal["har", "raw_request", "manual"],
    file_reference: str | None = None,
    observed_renewal: bool = False,
) -> ActorAuthenticationConfig:
    """Bind and atomically store a selected candidate, rejecting cross-identity replacement."""

    target = _load_target(workspace)
    actor = _account(target, actor_id)
    actor_type = actor.actor_type or ("authenticated_user" if actor.authenticated else "anonymous")
    if actor_type == "anonymous" or not actor.authenticated:
        raise FinsecError(f"Anonymous actor {actor_id!r} cannot receive authentication.")
    if candidate.observed_host is not None and not host_is_covered(
        candidate.observed_host, target.scope.hosts
    ):
        raise FinsecError("Authentication capture belongs to a host outside target scope.")
    previous = actor.authentication
    continuity: Literal["CONFIRMED", "CHANGED", "UNKNOWN"] = "CONFIRMED"
    if previous is not None and previous.auth_type not in {"none", "unconfigured"}:
        continuity = _identity_continuity(previous.identity, candidate.identity)
        if continuity == "CHANGED":
            previous.status = "AUTH_CONTEXT_CHANGED"
            actor.authentication = previous
            _write_target(workspace, target)
            _invalidate_approvals(workspace)
            raise FinsecError(
                f"AUTH_CONTEXT_CHANGED: replacement credential does not match actor {actor_id}."
            )

    components, secrets = _candidate_components(actor_id, candidate)
    SecretStore(workspace).put_many(secrets)
    initial: AuthenticationStatus = (
        "READY"
        if candidate.baseline is not None
        and candidate.baseline.expected_status is not None
        and 200 <= candidate.baseline.expected_status < 300
        else "AVAILABLE_NOT_VALIDATED"
    )
    status = _status_for_expiration(
        candidate.expiration,
        threshold_seconds=target.testing.authentication_expiring_soon_seconds,
        otherwise=initial,
    )
    context = authentication_context_fingerprint(
        actor_id, candidate.auth_type, candidate.identity, target.scope.hosts
    )
    refresh = previous.refresh if previous is not None else AuthenticationRefreshConfig()
    authentication = ActorAuthenticationConfig(
        auth_type=candidate.auth_type,
        profile_ref=f"actor-{_actor_token(actor_id)}-default",
        components=components,
        source=AuthenticationSourceConfig(
            type=source_type,
            file_reference=Path(file_reference).name if file_reference else None,
            captured_at=candidate.captured_at,
        ),
        expiration=candidate.expiration,
        refresh=refresh,
        baseline=candidate.baseline,
        identity=candidate.identity,
        status=status,
        context_fingerprint=context,
        target_hosts=target.scope.hosts,
        last_validated_at=candidate.captured_at if initial == "READY" else None,
    )
    actor.actor_type = actor_type
    actor.authentication = authentication
    _write_target(workspace, target)
    if previous is not None and previous.auth_type not in {"none", "unconfigured"}:
        if continuity == "UNKNOWN" and not observed_renewal:
            authentication.status = "AUTH_CONTEXT_CHANGED"
            actor.authentication = authentication
            _write_target(workspace, target)
            _invalidate_approvals(workspace)
        elif previous.context_fingerprint != context:
            _invalidate_approvals(workspace)
    return authentication


def capture_from_har(
    workspace: WorkspacePaths,
    actor_id: str,
    har_path: Path,
    *,
    candidate_number: int | None = None,
    observed_renewal: bool = False,
) -> tuple[ActorAuthenticationConfig, list[AuthenticationCandidate]]:
    candidates = detect_har_authentication(har_path)
    if not candidates:
        raise FinsecError("No replay authentication candidate was detected in the HAR.")
    if candidate_number is None and len(candidates) != 1:
        raise FinsecError(
            f"Multiple authentication candidates were detected ({len(candidates)}); "
            "select one explicitly."
        )
    selected = candidate_number or 1
    if selected < 1 or selected > len(candidates):
        raise FinsecError("Authentication candidate selection is out of range.")
    authentication = store_candidate(
        workspace,
        actor_id,
        candidates[selected - 1],
        source_type="har",
        file_reference=har_path.name,
        observed_renewal=observed_renewal,
    )
    return authentication, candidates


def capture_from_raw_request(
    workspace: WorkspacePaths,
    actor_id: str,
    request_path: Path,
    *,
    observed_renewal: bool = False,
) -> ActorAuthenticationConfig:
    candidate = candidate_from_raw_request(request_path)
    return store_candidate(
        workspace,
        actor_id,
        candidate,
        source_type="raw_request",
        file_reference=request_path.name,
        observed_renewal=observed_renewal,
    )


def set_manual_authentication(
    workspace: WorkspacePaths,
    actor_id: str,
    *,
    auth_type: str,
    header_name: str,
    secret_value: str,
) -> ActorAuthenticationConfig:
    if not header_name.strip() or "\n" in header_name or ":" in header_name:
        raise FinsecError("Authentication header name is invalid.")
    purpose = "access" if header_name.lower() == "authorization" else "api_key"
    stored_value = secret_value
    if auth_type in {"bearer", "bearer_jwt"} and not secret_value.lower().startswith("bearer "):
        stored_value = f"Bearer {secret_value}"
    candidate = AuthenticationCandidate(
        auth_type=auth_type,
        components=(CapturedSecret(header_name, stored_value, purpose),),
        expiration=AuthenticationExpirationConfig(last_checked_at=datetime.now(UTC)),
        identity=AuthenticationIdentityConfig(),
        baseline=None,
        captured_at=datetime.now(UTC),
        source_index=0,
        observed_host=None,
    )
    if auth_type in {"bearer", "bearer_jwt"}:
        raw = (
            secret_value.split(None, 1)[1]
            if secret_value.lower().startswith("bearer ")
            else secret_value
        )
        expiration, identity = decode_jwt_metadata(raw)
        candidate = AuthenticationCandidate(
            auth_type="bearer_jwt" if len(raw.split(".")) == 3 else "bearer",
            components=(CapturedSecret(header_name, stored_value, purpose),),
            expiration=expiration,
            identity=identity,
            baseline=None,
            captured_at=datetime.now(UTC),
            source_index=0,
            observed_host=None,
        )
    return store_candidate(workspace, actor_id, candidate, source_type="manual")


def clear_authentication(workspace: WorkspacePaths, actor_id: str) -> None:
    target = _load_target(workspace)
    actor = _account(target, actor_id)
    authentication = actor.authentication
    if authentication is not None:
        references = [item.credential_ref for item in authentication.components]
        if authentication.refresh.request_template_ref:
            references.append(authentication.refresh.request_template_ref)
        SecretStore(workspace).remove(references, actor_id)
    actor.authentication = (
        anonymous_authentication()
        if (actor.actor_type == "anonymous" or not actor.authenticated)
        else missing_authentication()
    )
    _write_target(workspace, target)
    _invalidate_approvals(workspace)


def mark_authentication_status(
    workspace: WorkspacePaths,
    actor_id: str,
    status: AuthenticationStatus,
    *,
    baseline_confirmed: bool | None = None,
) -> None:
    """Persist only a redacted lifecycle state after target-side classification."""

    target = _load_target(workspace)
    actor = _account(target, actor_id)
    if actor.authentication is None or actor.authentication.auth_type == "none":
        return
    actor.authentication.status = status
    actor.authentication.expiration.last_checked_at = datetime.now(UTC)
    if baseline_confirmed is not None:
        actor.authentication.identity.baseline_confirmed = baseline_confirmed
    if status == "READY":
        actor.authentication.last_validated_at = datetime.now(UTC)
    _write_target(workspace, target)


def _validate_network_destination(host: str, port: int, local_lab: bool) -> None:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise FinsecError("Authentication check DNS resolution failed.") from error
    for record in records:
        address = ipaddress.ip_address(str(record[4][0]))
        if address.is_multicast or address.is_unspecified or address.is_reserved:
            raise FinsecError("Authentication check resolved to a prohibited destination.")
        if (address.is_loopback or address.is_private or address.is_link_local) and not local_lab:
            raise FinsecError("Authentication check resolved to a private destination.")


def _response_is_login(status: int, headers: dict[str, str], body: bytes) -> bool:
    if status in {401, 419}:
        return True
    location = next((value for name, value in headers.items() if name.lower() == "location"), "")
    if 300 <= status < 400 and any(
        marker in location.lower() for marker in ("/login", "/signin", "/auth")
    ):
        return True
    content_type = next(
        (value for name, value in headers.items() if name.lower() == "content-type"), ""
    )
    text = body[:65536].decode("utf-8", errors="ignore").lower()
    return (
        status == 200
        and "html" in content_type.lower()
        and "<form" in text
        and any(marker in text for marker in ("password", "login", "log in", "sign in"))
    )


def validate_actor_baseline(workspace: WorkspacePaths, actor_id: str) -> AuthenticationCheckResult:
    """Send one explicitly requested, previously observed read-only actor baseline."""

    target = _load_target(workspace)
    if not target.testing.active_execution_enabled:
        raise FinsecError("Authentication network check requires active_execution_enabled: true.")
    actor = _account(target, actor_id)
    authentication = actor.authentication
    if authentication is None or authentication.profile_ref is None:
        raise FinsecError("Actor credential profile is not configured.")
    baseline = authentication.baseline
    if baseline is None:
        raise FinsecError("No previously observed read-only actor baseline is configured.")
    if baseline.method not in {"GET", "HEAD"}:
        raise FinsecError("Actor baseline is not read-only.")
    if not host_is_covered(baseline.host, target.scope.hosts):
        raise FinsecError("Actor baseline is outside target scope.")
    preflight = actor_preflight(workspace, actor_id, for_execution=True, request_count=1)
    if preflight.result == "BLOCKED_BY_AUTH":
        return AuthenticationCheckResult(preflight, 0, None, False)
    headers = {
        **baseline.safe_headers,
        **resolve_profile_headers(workspace, actor_id, authentication.profile_ref),
        "User-Agent": "FinSec-Hunt-Authentication-Preflight/1",
        "Connection": "close",
    }
    if any(
        any(character in value for character in ("\r", "\n", "\0")) for value in headers.values()
    ):
        raise FinsecError("Authentication baseline contains unsafe header bytes.")
    port = baseline.port or (443 if baseline.scheme == "https" else 80)
    _validate_network_destination(baseline.host, port, target.testing.local_lab)
    query = urlencode(
        [(name, value) for name, values in baseline.query_parameters.items() for value in values]
    )
    request_target = f"{baseline.path}?{query}" if query else baseline.path
    if baseline.scheme == "https":
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            baseline.host,
            port,
            timeout=target.testing.connection_timeout_seconds,
            context=ssl.create_default_context(),
        )
    else:
        connection = http.client.HTTPConnection(
            baseline.host, port, timeout=target.testing.connection_timeout_seconds
        )
    try:
        connection.request(baseline.method, request_target, headers=headers)
        response = connection.getresponse()
        body = response.read(target.testing.maximum_response_bytes + 1)
        response_headers = {name: value for name, value in response.getheaders()}
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise FinsecError("Authentication baseline network validation failed safely.") from error
    finally:
        connection.close()
    if len(body) > target.testing.maximum_response_bytes:
        raise FinsecError("Authentication baseline response exceeded the size limit.")
    if _response_is_login(response.status, response_headers, body):
        mark_authentication_status(workspace, actor_id, "INVALID", baseline_confirmed=False)
        checked = actor_preflight(workspace, actor_id, for_execution=True)
        return AuthenticationCheckResult(checked, 1, response.status, False)
    matched = 200 <= response.status < 300 and (
        baseline.expected_status is None or response.status == baseline.expected_status
    )
    if matched:
        mark_authentication_status(workspace, actor_id, "READY", baseline_confirmed=True)
    checked = actor_preflight(workspace, actor_id, for_execution=True)
    return AuthenticationCheckResult(checked, 1, response.status, matched)


def actor_preflight(
    workspace: WorkspacePaths,
    actor_id: str,
    *,
    request_count: int = 0,
    for_execution: bool = False,
    expected_profile_ref: str | None = None,
    expected_context_fingerprint: str | None = None,
    request_hosts: set[str] | None = None,
) -> AuthenticationPreflight:
    """Resolve and classify an actor profile locally without sending network traffic."""

    target = _load_target(workspace)
    actor = _account(target, actor_id)
    authentication = actor.authentication
    actor_type = actor.actor_type or ("authenticated_user" if actor.authenticated else "anonymous")
    if actor_type == "anonymous" or not actor.authenticated:
        if authentication is not None and authentication.components:
            raise FinsecError(f"Anonymous actor {actor_id!r} has an unsafe credential assignment.")
        return AuthenticationPreflight(
            actor_id,
            "none",
            "NONE",
            True,
            None,
            None,
            False,
            True,
            True,
            "READY_FOR_EXECUTION" if for_execution else "READY_FOR_PLANNING",
        )
    if authentication is None:
        return AuthenticationPreflight(
            actor_id,
            "legacy_unmanaged",
            "MISSING",
            False,
            None,
            None,
            False,
            False,
            False,
            "BLOCKED_BY_AUTH",
            ("Actor authentication metadata has not been migrated.",),
        )
    if expected_profile_ref and authentication.profile_ref != expected_profile_ref:
        return AuthenticationPreflight(
            actor_id,
            authentication.auth_type,
            "AUTH_CONTEXT_CHANGED",
            False,
            authentication.expiration.expires_at,
            None,
            authentication.refresh.configured,
            False,
            False,
            "BLOCKED_BY_AUTH",
            ("The plan references a different actor credential profile.",),
        )
    if (
        expected_context_fingerprint is not None
        and authentication.context_fingerprint != expected_context_fingerprint
    ):
        return AuthenticationPreflight(
            actor_id,
            authentication.auth_type,
            "AUTH_CONTEXT_CHANGED",
            False,
            authentication.expiration.expires_at,
            None,
            authentication.refresh.configured,
            False,
            False,
            "BLOCKED_BY_AUTH",
            ("Actor authentication context changed after plan generation.",),
        )
    if request_hosts and not request_hosts.issubset(set(authentication.target_hosts)):
        return AuthenticationPreflight(
            actor_id,
            authentication.auth_type,
            "INVALID",
            False,
            authentication.expiration.expires_at,
            None,
            authentication.refresh.configured,
            False,
            False,
            "BLOCKED_BY_AUTH",
            ("Credential profile is not scoped to every planned request host.",),
        )
    store = SecretStore(workspace)
    missing = [
        item.credential_ref
        for item in authentication.components
        if item.replay_required and not store.contains(item.credential_ref, actor_id)
    ]
    if authentication.source.type == "legacy_environment":
        available = any(
            bool(os.environ.get(variable))
            for variable in authentication.legacy_environment.values()
        )
    else:
        available = bool(authentication.components) and not missing
    expiration = authentication.expiration.expires_at
    remaining = (
        int((expiration.astimezone(UTC) - datetime.now(UTC)).total_seconds())
        if expiration is not None
        else None
    )
    margin = max(
        target.testing.authentication_expiring_soon_seconds,
        target.testing.authentication_execution_margin_seconds + (request_count + 1) * 10,
    )
    status = authentication.status
    reasons: list[str] = []
    if not available:
        status = "MISSING"
        reasons.append("One or more actor-bound credential references cannot be resolved.")
    elif remaining is not None and remaining <= 0:
        status = "EXPIRED"
        reasons.append("Known credential expiration has passed.")
    elif remaining is not None and remaining <= margin:
        status = "EXPIRING_SOON"
        reasons.append("Known remaining lifetime is below the bounded execution margin.")
    elif status in {"MISSING", "EXPIRED", "REFRESH_FAILED", "AUTH_CONTEXT_CHANGED", "INVALID"}:
        reasons.append(f"Actor authentication state is {status}.")
    blocked = not available or status in {
        "MISSING",
        "EXPIRED",
        "INVALID",
        "REFRESH_REQUIRED",
        "REFRESH_FAILED",
        "AUTH_CONTEXT_CHANGED",
    }
    if for_execution and status == "EXPIRING_SOON":
        blocked = True
        reasons.append("Refresh or replacement is required before network execution.")
    result: Literal["READY_FOR_EXECUTION", "READY_FOR_PLANNING", "BLOCKED_BY_AUTH"]
    if blocked:
        result = "BLOCKED_BY_AUTH"
    else:
        result = "READY_FOR_EXECUTION" if for_execution else "READY_FOR_PLANNING"
    return AuthenticationPreflight(
        actor_id=actor_id,
        auth_type=authentication.auth_type,
        status=status,
        credential_available=available,
        expires_at=expiration,
        remaining_seconds=remaining,
        refresh_available=authentication.refresh.configured,
        target_validated=authentication.last_validated_at is not None,
        baseline_identity_confirmed=authentication.identity.baseline_confirmed,
        result=result,
        reasons=tuple(dict.fromkeys(reasons)),
    )


def resolve_profile_headers(
    workspace: WorkspacePaths,
    actor_id: str,
    profile_ref: str,
) -> dict[str, str]:
    target = _load_target(workspace)
    actor = _account(target, actor_id)
    authentication = actor.authentication
    if authentication is None or authentication.profile_ref != profile_ref:
        raise FinsecError(f"Actor {actor_id!r} credential profile cannot be resolved.")
    store = SecretStore(workspace)
    headers: dict[str, str] = {}
    for component in authentication.components:
        if not component.replay_required or component.location not in {"header", "cookie"}:
            continue
        value = store.resolve(component.credential_ref, actor_id)
        name = "Cookie" if component.location == "cookie" else component.name
        if name in headers and name.lower() == "cookie":
            headers[name] = f"{headers[name]}; {value}"
        elif name in headers:
            raise FinsecError("Actor profile contains duplicate replay headers.")
        else:
            headers[name] = f"{component.value_prefix}{value}"
    return headers


def _json_paths(value: Any, prefix: str = "$") -> list[tuple[str, Any]]:
    result: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            result.extend(_json_paths(item, f"{prefix}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.extend(_json_paths(item, f"{prefix}[{index}]"))
    else:
        result.append((prefix, value))
    return result


def _json_path(value: Any, path: str | None) -> Any | None:
    if path is None or not path.startswith("$.") or "[" in path:
        return None
    current = value
    for part in path[2:].split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _set_json_path(value: Any, path: str, replacement: Any) -> bool:
    if not path.startswith("$.") or "[" in path:
        return False
    current = value
    parts = path[2:].split(".")
    for part in parts[:-1]:
        if not isinstance(current, dict) or not isinstance(current.get(part), dict):
            return False
        current = current[part]
    if not isinstance(current, dict) or parts[-1] not in current:
        return False
    current[parts[-1]] = replacement
    return True


def configure_refresh_from_har(
    workspace: WorkspacePaths,
    actor_id: str,
    har_path: Path,
    *,
    entry_number: int | None = None,
    auto_refresh: bool = False,
) -> AuthenticationRefreshConfig:
    """Store exactly one observed in-scope refresh request template."""

    _source, _raw, document = load_har_json(har_path)
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise HarFormatError("HAR must contain a log.entries array.")
    matches: list[tuple[int, dict[str, Any], str, str | None, str, Any]] = []
    forbidden = {"password", "otp", "mfa", "captcha", "verification_code"}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        response = entry.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        if str(request.get("method", "")).upper() not in {"POST", "PUT"}:
            continue
        post_data = request.get("postData")
        request_body: Any = None
        if isinstance(post_data, dict) and isinstance(post_data.get("text"), str):
            try:
                request_body = json.loads(post_data["text"])
            except json.JSONDecodeError:
                continue
        response_content = response.get("content")
        response_body: Any = None
        if isinstance(response_content, dict) and isinstance(response_content.get("text"), str):
            try:
                response_body = json.loads(response_content["text"])
            except json.JSONDecodeError:
                continue
        if request_body is None or response_body is None:
            continue
        request_paths = _json_paths(request_body)
        if any(path.rsplit(".", 1)[-1].lower() in forbidden for path, _ in request_paths):
            continue
        refresh = next(
            (
                (path, value)
                for path, value in request_paths
                if path.rsplit(".", 1)[-1].lower() in {"refresh_token", "refreshtoken"}
                and isinstance(value, str)
                and value
            ),
            None,
        )
        access = next(
            (
                (path, value)
                for path, value in _json_paths(response_body)
                if path.rsplit(".", 1)[-1].lower() in {"access_token", "accesstoken", "token"}
                and isinstance(value, str)
                and value
            ),
            None,
        )
        if refresh is None or access is None:
            continue
        refresh_response = next(
            (
                path
                for path, value in _json_paths(response_body)
                if path.rsplit(".", 1)[-1].lower() in {"refresh_token", "refreshtoken"}
                and isinstance(value, str)
                and value
            ),
            None,
        )
        matches.append((index, entry, access[0], refresh_response, refresh[0], refresh[1]))
    if not matches:
        raise FinsecError("No deterministic observed refresh flow was detected in the HAR.")
    if entry_number is None and len(matches) != 1:
        raise FinsecError(f"Multiple refresh flows were detected ({len(matches)}); select one.")
    selected = entry_number or 1
    if selected < 1 or selected > len(matches):
        raise FinsecError("Refresh-flow selection is out of range.")
    _index, entry, access_path, response_refresh_path, refresh_path, refresh_value = matches[
        selected - 1
    ]
    request = entry["request"]
    response = entry["response"]
    parsed = urlsplit(str(request.get("url", "")))
    target = _load_target(workspace)
    actor = _account(target, actor_id)
    if actor.authentication is None or actor.authentication.auth_type in {"none", "unconfigured"}:
        raise FinsecError("Configure actor access authentication before a refresh flow.")
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise FinsecError("Observed refresh endpoint must be a safe HTTP(S) URL.")
    if not host_is_covered(parsed.hostname, target.scope.hosts):
        raise FinsecError("Observed refresh endpoint is outside target scope.")
    post_data = request.get("postData")
    request_body = json.loads(post_data["text"])
    if not _set_json_path(request_body, refresh_path, SECRET_MARKER):
        raise FinsecError("Observed refresh credential path is unsupported.")
    headers = {
        str(item["name"]): str(item.get("value", ""))
        for item in request.get("headers", [])
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and item["name"].lower() not in {"content-length", "host", "connection"}
    }
    if any(
        any(character in value for character in ("\r", "\n", "\0")) for value in headers.values()
    ):
        raise FinsecError("Observed refresh request contains unsafe header bytes.")
    template = {
        "headers": headers,
        "body": request_body,
        "refresh_path": refresh_path,
    }
    actor_token = _actor_token(actor_id)
    template_ref = f"actor-auth-{actor_token}-refresh-template"
    refresh_ref = f"actor-auth-{actor_token}-refresh-token"
    SecretStore(workspace).put_many(
        [
            (
                template_ref,
                actor_id,
                "refresh_template",
                json.dumps(template, separators=(",", ":")),
            ),
            (refresh_ref, actor_id, "refresh", str(refresh_value)),
        ]
    )
    actor.authentication.components = [
        item for item in actor.authentication.components if item.purpose != "refresh"
    ]
    actor.authentication.components.append(
        AuthenticationComponentConfig(
            name="refresh_token",
            location="body",
            credential_ref=refresh_ref,
            purpose="refresh",
            replay_required=False,
        )
    )
    content_type = next(
        (
            str(item.get("value"))
            for item in response.get("headers", [])
            if isinstance(item, dict) and str(item.get("name", "")).lower() == "content-type"
        ),
        None,
    )
    try:
        port = parsed.port
    except ValueError as error:
        raise FinsecError("Observed refresh endpoint contains an invalid port.") from error
    request_path = parsed.path or "/"
    if parsed.query:
        request_path = f"{request_path}?{parsed.query}"
    actor.authentication.refresh = AuthenticationRefreshConfig(
        configured=True,
        flow_ref=f"actor-{actor_token}-refresh-flow",
        request_template_ref=template_ref,
        mode="observed_request",
        method=str(request.get("method", "POST")).upper(),
        scheme=parsed.scheme,
        host=parsed.hostname,
        port=port,
        path=request_path,
        response_access_path=access_path,
        response_refresh_path=response_refresh_path,
        expected_status=(
            int(response.get("status")) if isinstance(response.get("status"), int) else None
        ),
        expected_content_type=content_type,
        request_budget=1,
        auto_refresh=auto_refresh,
    )
    _write_target(workspace, target)
    return actor.authentication.refresh


def _replace_marker(value: Any, secret: str) -> Any:
    if isinstance(value, dict):
        return {key: _replace_marker(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_marker(item, secret) for item in value]
    return secret if value == SECRET_MARKER else value


def refresh_actor_authentication(workspace: WorkspacePaths, actor_id: str) -> RefreshResult:
    """Perform one observed in-scope refresh request and fail closed on any drift."""

    target = _load_target(workspace)
    actor = _account(target, actor_id)
    authentication = actor.authentication
    if authentication is None or not authentication.refresh.configured:
        raise FinsecError(f"No safe observed refresh flow is configured for {actor_id}.")
    refresh = authentication.refresh
    if not all(
        (refresh.request_template_ref, refresh.method, refresh.scheme, refresh.host, refresh.path)
    ):
        raise FinsecError("Observed refresh configuration is incomplete.")
    if not host_is_covered(str(refresh.host), target.scope.hosts):
        raise FinsecError("Observed refresh endpoint is outside target scope.")
    store = SecretStore(workspace)
    template_text = store.resolve(str(refresh.request_template_ref), actor_id)
    refresh_component = next(
        (item for item in authentication.components if item.purpose == "refresh"), None
    )
    if refresh_component is None:
        raise FinsecError("Observed refresh credential reference is missing.")
    refresh_secret = store.resolve(refresh_component.credential_ref, actor_id)
    try:
        template = json.loads(template_text)
        body = json.dumps(_replace_marker(template["body"], refresh_secret), separators=(",", ":"))
        headers = dict(template["headers"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise FinsecError("Observed refresh template cannot be resolved safely.") from error
    port = refresh.port or (443 if refresh.scheme == "https" else 80)
    refresh_host = cast(str, refresh.host)
    _validate_network_destination(refresh_host, port, target.testing.local_lab)
    connection: http.client.HTTPConnection
    if refresh.scheme == "https":
        connection = http.client.HTTPSConnection(
            refresh_host,
            port,
            timeout=target.testing.connection_timeout_seconds,
            context=ssl.create_default_context(),
        )
    else:
        connection = http.client.HTTPConnection(
            refresh_host, port, timeout=target.testing.connection_timeout_seconds
        )
    try:
        connection.request(str(refresh.method), str(refresh.path), body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(target.testing.maximum_response_bytes + 1)
        if len(raw) > target.testing.maximum_response_bytes:
            raise FinsecError("Authentication refresh response exceeded the size limit.")
        if refresh.expected_status is not None and response.status != refresh.expected_status:
            raise FinsecError("Authentication refresh response status changed materially.")
        content_type = response.getheader("Content-Type", "")
        if (
            refresh.expected_content_type
            and refresh.expected_content_type.split(";", 1)[0] not in content_type
        ):
            raise FinsecError("Authentication refresh response type changed materially.")
        document = json.loads(raw.decode("utf-8"))
    except (
        FinsecError,
        OSError,
        ssl.SSLError,
        http.client.HTTPException,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        authentication.status = "REFRESH_FAILED"
        _write_target(workspace, target)
        raise FinsecError(
            "Authentication refresh failed safely; no vulnerability mutation was sent."
        ) from error
    finally:
        connection.close()
    access = _json_path(document, refresh.response_access_path)
    if not isinstance(access, str) or not access:
        authentication.status = "REFRESH_FAILED"
        _write_target(workspace, target)
        raise FinsecError(
            "Authentication refresh response did not contain the observed access credential."
        )
    access_component = next(
        (item for item in authentication.components if item.purpose == "access"), None
    )
    if access_component is None:
        authentication.status = "REFRESH_FAILED"
        _write_target(workspace, target)
        raise FinsecError("Actor access credential reference is missing.")
    new_expiration, new_identity = decode_jwt_metadata(access)
    continuity = _identity_continuity(authentication.identity, new_identity)
    if continuity == "CHANGED":
        authentication.status = "AUTH_CONTEXT_CHANGED"
        _write_target(workspace, target)
        _invalidate_approvals(workspace)
        raise FinsecError("AUTH_CONTEXT_CHANGED: refreshed credential belongs to another identity.")
    stored_access = (
        f"Bearer {access}"
        if authentication.auth_type in {"bearer", "bearer_jwt"}
        and access_component.name.lower() == "authorization"
        else access
    )
    updates = [(access_component.credential_ref, actor_id, "access", stored_access)]
    new_refresh = _json_path(document, refresh.response_refresh_path)
    if isinstance(new_refresh, str) and new_refresh:
        updates.append((refresh_component.credential_ref, actor_id, "refresh", new_refresh))
    store.put_many(updates)
    authentication.expiration = new_expiration
    if continuity == "CONFIRMED":
        authentication.identity = new_identity
        authentication.context_fingerprint = authentication_context_fingerprint(
            actor_id, authentication.auth_type, new_identity, authentication.target_hosts
        )
        authentication.status = _status_for_expiration(
            new_expiration,
            threshold_seconds=target.testing.authentication_expiring_soon_seconds,
            otherwise="AVAILABLE_NOT_VALIDATED",
        )
    else:
        authentication.status = "AUTH_CONTEXT_CHANGED"
        _invalidate_approvals(workspace)
    _write_target(workspace, target)
    return RefreshResult(
        actor_id=actor_id,
        status=authentication.status,
        request_count=1,
        new_credential_received=True,
        identity_continuity=continuity,
    )


def migrate_legacy_authentication(workspace: WorkspacePaths) -> int:
    """Add explicit legacy references without copying environment values into workspace files."""

    target = _load_target(workspace)
    changed = 0
    for actor in target.accounts:
        if actor.authentication is not None:
            continue
        actor.actor_type = actor.actor_type or (
            "authenticated_user" if actor.authenticated else "anonymous"
        )
        if actor.actor_type == "anonymous" or not actor.authenticated:
            actor.authentication = anonymous_authentication()
            changed += 1
            continue
        actor_token = re.sub(r"[^A-Za-z0-9]+", "_", actor.id).strip("_").upper() or "ACTOR"
        variables = {
            "Authorization": f"FINSEC_{actor_token}_AUTH",
            "Cookie": f"FINSEC_{actor_token}_COOKIE",
        }
        available = any(os.environ.get(value) for value in variables.values())
        actor.authentication = ActorAuthenticationConfig(
            auth_type="legacy_environment",
            profile_ref=f"actor-{_actor_token(actor.id)}-legacy",
            source=AuthenticationSourceConfig(type="legacy_environment"),
            status="AVAILABLE_NOT_VALIDATED" if available else "MISSING",
            target_hosts=target.scope.hosts,
            legacy_environment=variables,
        )
        changed += 1
    if changed:
        _write_target(workspace, target)
    return changed
