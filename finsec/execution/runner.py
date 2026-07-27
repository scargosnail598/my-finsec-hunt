"""Sequential bounded HTTP runner with redacted evidence and immutable audit output."""

import copy
import hashlib
import http.client
import json
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit

import yaml

from finsec import __version__
from finsec.config.scope import host_is_covered
from finsec.errors import FinsecError
from finsec.evidence.domain import EvidenceKind
from finsec.evidence.manager import add_generated_evidence
from finsec.execution.domain import (
    EvidenceHash,
    ExecutionAuditRecord,
    ExecutionComparison,
    ExecutionOutcome,
    ExecutionResponseSummary,
    ExecutionStatus,
)
from finsec.execution.policy import PreparedExecution, _resolve_scope
from finsec.testing.domain import RequestExpectation, StructuredRequest
from finsec.utils.redaction import REDACTED, redact_data
from finsec.utils.yaml_store import write_yaml

USER_AGENT = f"FinSec-Hunt-Authorized-Validation/{__version__}"


@dataclass(frozen=True)
class HTTPResponseData:
    """One bounded transport result held only long enough to redact and compare."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    oversized: bool = False


@dataclass(frozen=True)
class ExecutionResult:
    """Completed bounded execution returned to the CLI."""

    comparison: ExecutionComparison
    status: ExecutionStatus
    requests_sent: int
    evidence_root: str
    audit_path: str


def _request_target(request: StructuredRequest) -> str:
    query = urlencode(
        [(name, value) for name, values in request.query_parameters.items() for value in values]
    )
    return f"{request.path}?{query}" if query else request.path


def _send_request(
    prepared: PreparedExecution,
    request: StructuredRequest,
    on_sent: Callable[[], None],
) -> HTTPResponseData:
    _resolve_scope(prepared.target, [request])
    port = request.port or (443 if request.scheme == "https" else 80)
    if request.scheme == "https":
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            request.host,
            port,
            timeout=prepared.plan.execution.connection_timeout_seconds,
            context=ssl.create_default_context(),
        )
    else:
        connection = http.client.HTTPConnection(
            request.host,
            port,
            timeout=prepared.plan.execution.connection_timeout_seconds,
        )
    headers = {
        **request.headers,
        **prepared.runtime_headers.get(request.id, {}),
        "User-Agent": USER_AGENT,
        "Connection": "close",
    }
    for name in request.remove_headers:
        headers.pop(name, None)
    try:
        connection.request(request.method, _request_target(request), headers=headers)
        on_sent()
        response = connection.getresponse()
        if connection.sock is not None:
            connection.sock.settimeout(prepared.plan.execution.read_timeout_seconds)
        response_headers = {name: value for name, value in response.getheaders()}
        maximum = prepared.plan.execution.maximum_response_bytes
        content_length = response_headers.get("Content-Length") or response_headers.get(
            "content-length"
        )
        if (
            content_length is not None
            and content_length.isdigit()
            and int(content_length) > maximum
        ):
            return HTTPResponseData(response.status, response_headers, b"", oversized=True)
        body = bytearray()
        while True:
            chunk = response.read(min(65536, maximum + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > maximum:
                return HTTPResponseData(response.status, response_headers, b"", oversized=True)
        return HTTPResponseData(response.status, response_headers, bytes(body))
    finally:
        connection.close()


def _json_body(response: HTTPResponseData) -> Any | None:
    content_type = next(
        (value for name, value in response.headers.items() if name.lower() == "content-type"),
        "",
    )
    if "json" not in content_type.lower() or not response.body:
        return None
    try:
        return json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _json_path(value: Any, path: str | None) -> Any | None:
    if path is None or not path.startswith("$.") or "[*]" in path:
        return None
    current = value
    for part in path[2:].split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _replace_json_path(value: Any, path: str | None, replacement: Any) -> Any:
    document = copy.deepcopy(value)
    if path is None or not path.startswith("$.") or "[*]" in path:
        return document
    current = document
    parts = path[2:].split(".")
    for part in parts[:-1]:
        if not isinstance(current, dict) or not isinstance(current.get(part), dict):
            return document
        current = current[part]
    if isinstance(current, dict) and parts[-1] in current:
        current[parts[-1]] = replacement
    return document


def _owner_fingerprint(path: str, value: Any) -> str:
    return hashlib.sha256(f"{path}\0{value}".encode()).hexdigest()


def _scalar_paths(value: Any, prefix: str = "$") -> list[str]:
    result: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            result.extend(_scalar_paths(item, f"{prefix}.{key}"))
    elif isinstance(value, list):
        for item in value:
            result.extend(_scalar_paths(item, f"{prefix}[*]"))
    elif value is not None:
        result.append(prefix)
    return result


def _first_item_count(value: Any) -> int | None:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for item in value.values():
            count = _first_item_count(item)
            if count is not None:
                return count
    return None


def _content_type(response: HTTPResponseData) -> str | None:
    return next(
        (value for name, value in response.headers.items() if name.lower() == "content-type"),
        None,
    )


def _summary(
    request: StructuredRequest,
    response: HTTPResponseData,
) -> ExecutionResponseSummary:
    document = _json_body(response)
    returned = _json_path(document, request.expected.object_path)
    owner = _json_path(document, request.expected.owner_path)
    owner_fingerprint = (
        _owner_fingerprint(request.expected.owner_path, owner)
        if request.expected.owner_path is not None and owner is not None
        else None
    )
    return ExecutionResponseSummary(
        request_id=request.id,
        status_code=response.status_code,
        content_type=_content_type(response),
        response_length=len(response.body),
        json_paths=sorted(_scalar_paths(document)) if document is not None else [],
        requested_object_id=request.expected.object_value,
        returned_object_id=str(returned) if returned is not None else None,
        owner_fingerprint=owner_fingerprint,
        resource_item_count=_first_item_count(document),
        redirect_location=next(
            (value for name, value in response.headers.items() if name.lower() == "location"),
            None,
        ),
        error_class="RESPONSE_SIZE_EXCEEDED" if response.oversized else None,
    )


def _baseline_identity_matches(
    expectation: RequestExpectation,
    summary: ExecutionResponseSummary,
) -> bool:
    if (
        expectation.object_path is not None
        and summary.returned_object_id != expectation.object_value
    ):
        return False
    return not (
        expectation.owner_fingerprint is not None
        and summary.owner_fingerprint != expectation.owner_fingerprint
    )


def _redirect_outcome(
    prepared: PreparedExecution,
    request: StructuredRequest,
    summary: ExecutionResponseSummary,
) -> ExecutionOutcome | None:
    if summary.status_code is None or not 300 <= summary.status_code < 400:
        return None
    if summary.redirect_location is None:
        return "STOPPED_BY_POLICY"
    port = request.port or (443 if request.scheme == "https" else 80)
    base = f"{request.scheme}://{request.host}:{port}{request.path}"
    destination = urlsplit(urljoin(base, summary.redirect_location))
    if destination.scheme not in {"http", "https"} or destination.hostname is None:
        return "OUT_OF_SCOPE_REDIRECT"
    if not host_is_covered(destination.hostname, prepared.target.scope.hosts):
        return "OUT_OF_SCOPE_REDIRECT"
    return "STOPPED_BY_POLICY"


def _compare(
    prepared: PreparedExecution,
    baseline: ExecutionResponseSummary,
    comparison: ExecutionResponseSummary,
) -> ExecutionComparison:
    pattern = prepared.plan.execution.pattern
    if comparison.status_code is not None and 500 <= comparison.status_code < 600:
        return ExecutionComparison(
            outcome="STOPPED_BY_POLICY",
            baseline=baseline,
            comparison=comparison,
            reasons=["The comparison request returned an unexpected server error."],
        )
    if pattern == "OBJECT_SUBSTITUTION":
        expected = prepared.plan.requests[1].expected
        if comparison.status_code in {401, 403, 404}:
            outcome: ExecutionOutcome = "NO_CROSS_OBJECT_ACCESS"
            reasons = ["The substituted object request was rejected or not exposed."]
        elif (
            comparison.status_code is not None
            and 200 <= comparison.status_code < 300
            and comparison.returned_object_id == expected.object_value
            and comparison.owner_fingerprint == expected.owner_fingerprint
            and comparison.owner_fingerprint != baseline.owner_fingerprint
            and bool(comparison.json_paths)
        ):
            outcome = "CROSS_OBJECT_RESPONSE_OBSERVED"
            reasons = [
                "The read-only substituted request returned the controlled target object "
                "and owner baseline."
            ]
        else:
            outcome = "INCONCLUSIVE"
            reasons = [
                "The response did not match a conservative cross-object or rejection signal."
            ]
    elif pattern == "AUTHENTICATION_COMPARISON":
        if comparison.status_code in {401, 403}:
            outcome = "AUTHENTICATION_ENFORCED"
            reasons = ["Removing the one authentication marker caused an authorization rejection."]
        elif comparison.status_code is not None and 200 <= comparison.status_code < 300:
            outcome = "ANONYMOUS_RESPONSE_OBSERVED"
            reasons = [
                "The matched request returned success after the authentication marker was removed."
            ]
        else:
            outcome = "INCONCLUSIVE"
            reasons = [
                "The unauthenticated comparison did not produce a decisive control response."
            ]
    else:
        outcome = "COMPARISON_OBSERVED"
        reasons = [
            "Both explicitly planned read-only routes were compared; human review is required."
        ]
    return ExecutionComparison(
        outcome=outcome,
        baseline=baseline,
        comparison=comparison,
        reasons=reasons,
    )


def _request_evidence(request: StructuredRequest) -> str:
    port = request.port or (443 if request.scheme == "https" else 80)
    lines = [
        f"{request.method} {_request_target(request)} HTTP/1.1",
        f"Host: {request.host}:{port}",
        f"User-Agent: {USER_AGENT}",
    ]
    lines.extend(f"{name}: {value}" for name, value in sorted(request.headers.items()))
    lines.extend(f"{item.header}: {REDACTED}" for item in request.runtime_secrets)
    return f"{'\n'.join(lines)}\n"


def _response_evidence(
    request: StructuredRequest,
    response: HTTPResponseData,
    summary: ExecutionResponseSummary,
) -> str:
    document = _json_body(response)
    if document is not None:
        owner_label = (
            f"[OWNER-FINGERPRINT:{summary.owner_fingerprint[:12]}]"
            if summary.owner_fingerprint is not None
            else REDACTED
        )
        body: Any = _replace_json_path(document, request.expected.owner_path, owner_label)
        body = redact_data(body)
    elif response.oversized:
        body = {"body": "[NOT STORED: RESPONSE SIZE EXCEEDED]"}
    else:
        try:
            text = response.body.decode("utf-8")
        except UnicodeDecodeError:
            text = "[BINARY RESPONSE NOT STORED]"
        body = {"body": text}
    artifact = {
        "status": response.status_code,
        "headers": redact_data(response.headers),
        "body": body,
    }
    return f"{json.dumps(artifact, indent=2, sort_keys=True)}\n"


def _next_revision(prepared: PreparedExecution) -> int:
    audit_root = prepared.workspace.executions_for(prepared.hypothesis.id)
    evidence_root = prepared.workspace.evidence_for(prepared.hypothesis.id) / "executions"
    values: list[int] = []
    for path in audit_root.glob("execution-v*.yaml") if audit_root.is_dir() else []:
        suffix = path.stem.removeprefix("execution-v")
        if suffix.isdigit():
            values.append(int(suffix))
    for path in evidence_root.glob("execution-v*") if evidence_root.is_dir() else []:
        suffix = path.name.removeprefix("execution-v")
        if suffix.isdigit():
            values.append(int(suffix))
    return max(values, default=0) + 1


def _execution_status(outcome: ExecutionOutcome) -> ExecutionStatus:
    if outcome == "INCONCLUSIVE":
        return "INCONCLUSIVE"
    if outcome in {
        "BASELINE_FAILED",
        "BASELINE_MISMATCH",
        "OUT_OF_SCOPE_REDIRECT",
        "RESPONSE_SIZE_EXCEEDED",
        "STOPPED_BY_POLICY",
        "INTERRUPTED",
        "TRANSPORT_FAILED",
    }:
        return "STOPPED"
    return "COMPLETED"


def _write_outputs(
    prepared: PreparedExecution,
    started_at: datetime,
    comparison: ExecutionComparison,
    requests_sent: int,
    responses: list[tuple[StructuredRequest, HTTPResponseData, ExecutionResponseSummary]],
    notes: list[str],
) -> tuple[str, str, ExecutionStatus]:
    revision = _next_revision(prepared)
    relative_root = f"executions/execution-v{revision}"
    evidence_revision = prepared.workspace.evidence_for(prepared.hypothesis.id) / relative_root
    audit_root = prepared.workspace.executions_for(prepared.hypothesis.id)
    audit_path = audit_root / f"execution-v{revision}.yaml"
    if evidence_revision.exists() or audit_path.exists():
        raise FinsecError(f"Execution revision already exists: execution-v{revision}")
    generated: list[tuple[str, EvidenceKind, str, str]] = []
    for index, (request, response, summary) in enumerate(responses):
        prefix = "baseline" if index == 0 else "mutated"
        generated.append(
            (
                f"{relative_root}/{prefix}-request.txt",
                "request",
                _request_evidence(request),
                f"Bounded execution {prefix} request.",
            )
        )
        generated.append(
            (
                f"{relative_root}/{prefix}-response.json",
                "response",
                _response_evidence(request, response, summary),
                f"Redacted bounded execution {prefix} response.",
            )
        )
    comparison_text = yaml.safe_dump(
        comparison.model_dump(mode="json", exclude_none=True),
        sort_keys=False,
        allow_unicode=False,
    )
    metadata = {
        "hypothesis_id": prepared.hypothesis.id,
        "plan_id": prepared.plan.id,
        "plan_checksum": prepared.plan_checksum,
        "target_policy_checksum": prepared.target_policy_checksum,
        "request_count": requests_sent,
        "outcome": comparison.outcome,
        "final_vulnerability_status": "NOT CONFIRMED",
    }
    generated.extend(
        [
            (
                f"{relative_root}/comparison.yaml",
                "other",
                comparison_text,
                "Conservative machine comparison requiring human validation.",
            ),
            (
                f"{relative_root}/execution-metadata.yaml",
                "other",
                yaml.safe_dump(metadata, sort_keys=False, allow_unicode=False),
                "Bounded execution metadata without credentials.",
            ),
        ]
    )
    evidence = add_generated_evidence(
        prepared.workspace,
        prepared.hypothesis.id,
        generated,
    )
    hashes = [
        EvidenceHash(path=item.path, sha256=item.sha256)
        for item in evidence.metadata.artifacts
        if item.path.startswith(f"{relative_root}/")
    ]
    completed_at = datetime.now(UTC)
    status = _execution_status(comparison.outcome)
    audit = ExecutionAuditRecord(
        hypothesis_id=prepared.hypothesis.id,
        plan_id=prepared.plan.id,
        plan_checksum=prepared.plan_checksum,
        target_policy_checksum=prepared.target_policy_checksum,
        started_at=started_at,
        completed_at=completed_at,
        status=status,
        outcome=comparison.outcome,
        actor_labels=sorted({item.actor for item in prepared.plan.requests}),
        request_count=requests_sent,
        methods=sorted({item.method for item in prepared.plan.requests[:requests_sent]}),
        hosts=sorted({item.host for item in prepared.plan.requests[:requests_sent]}),
        paths=[item.path for item in prepared.plan.requests[:requests_sent]],
        mutation_dimensions=[str(item) for item in prepared.plan.execution.mutation_dimensions],
        stop_conditions=prepared.plan.execution.stop_conditions,
        evidence=hashes,
        tool_version=__version__,
        notes=notes,
    )
    audit_root.mkdir(parents=True, exist_ok=True)
    if audit_path.exists():
        raise FinsecError(f"Execution audit revision already exists: {audit_path}")
    write_yaml(audit_path, audit.model_dump(mode="json", exclude_none=True))
    return str(evidence.root), str(audit_path), status


def execute_prepared(prepared: PreparedExecution) -> ExecutionResult:
    """Execute one approved sequential plan and never update vulnerability status."""

    started_at = datetime.now(UTC)
    responses: list[tuple[StructuredRequest, HTTPResponseData, ExecutionResponseSummary]] = []
    requests_sent = 0
    notes: list[str] = []
    comparison: ExecutionComparison

    def mark_sent() -> None:
        nonlocal requests_sent
        requests_sent += 1

    try:
        baseline_request = prepared.plan.requests[0]
        baseline_response = _send_request(prepared, baseline_request, mark_sent)
        baseline_summary = _summary(baseline_request, baseline_response)
        responses.append((baseline_request, baseline_response, baseline_summary))
        redirect = _redirect_outcome(prepared, baseline_request, baseline_summary)
        if baseline_response.oversized:
            comparison = ExecutionComparison(
                outcome="RESPONSE_SIZE_EXCEEDED",
                baseline=baseline_summary,
                reasons=["The baseline response exceeded the configured size limit."],
            )
        elif redirect is not None:
            comparison = ExecutionComparison(
                outcome=redirect,
                baseline=baseline_summary,
                reasons=["Redirects are disabled; the destination was not followed."],
            )
        elif baseline_summary.status_code is None or not 200 <= baseline_summary.status_code < 300:
            comparison = ExecutionComparison(
                outcome="BASELINE_FAILED",
                baseline=baseline_summary,
                reasons=["The baseline request did not return a successful response."],
            )
        elif not _baseline_identity_matches(baseline_request.expected, baseline_summary):
            comparison = ExecutionComparison(
                outcome="BASELINE_MISMATCH",
                baseline=baseline_summary,
                reasons=["The baseline response did not match its passive object identity."],
            )
        else:
            comparison_request = prepared.plan.requests[1]
            comparison_response = _send_request(prepared, comparison_request, mark_sent)
            comparison_summary = _summary(comparison_request, comparison_response)
            responses.append((comparison_request, comparison_response, comparison_summary))
            redirect = _redirect_outcome(prepared, comparison_request, comparison_summary)
            if comparison_response.oversized:
                comparison = ExecutionComparison(
                    outcome="RESPONSE_SIZE_EXCEEDED",
                    baseline=baseline_summary,
                    comparison=comparison_summary,
                    reasons=["The comparison response exceeded the configured size limit."],
                )
            elif redirect is not None:
                comparison = ExecutionComparison(
                    outcome=redirect,
                    baseline=baseline_summary,
                    comparison=comparison_summary,
                    reasons=["Redirects are disabled; the destination was not followed."],
                )
            else:
                comparison = _compare(prepared, baseline_summary, comparison_summary)
    except KeyboardInterrupt:
        comparison = ExecutionComparison(
            outcome="INTERRUPTED",
            baseline=responses[0][2] if responses else None,
            reasons=["Execution was interrupted; no additional request was sent."],
        )
        notes.append("The researcher interrupted execution.")
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        comparison = ExecutionComparison(
            outcome="TRANSPORT_FAILED",
            baseline=responses[0][2] if responses else None,
            reasons=[f"Transport stopped safely: {type(error).__name__}."],
        )
        notes.append(type(error).__name__)
    evidence_root, audit_path, status = _write_outputs(
        prepared,
        started_at,
        comparison,
        requests_sent,
        responses,
        notes,
    )
    return ExecutionResult(
        comparison=comparison,
        status=status,
        requests_sent=requests_sent,
        evidence_root=evidence_root,
        audit_path=audit_path,
    )
