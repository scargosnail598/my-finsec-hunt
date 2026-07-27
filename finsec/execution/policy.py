"""Fail-closed approval, plan integrity, scope, DNS, and request-budget policy."""

import hashlib
import ipaddress
import os
import re
import socket
from dataclasses import dataclass

from pydantic import ValidationError

from finsec.config.models import TargetDocument
from finsec.config.scope import host_is_covered
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.hypotheses.domain import HypothesisRecord
from finsec.hypotheses.generator import find_hypothesis
from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import Endpoint, EndpointStore
from finsec.testing.domain import PlanApproval, StructuredRequest, TestPlanRecord, TestPlanStore
from finsec.testing.templates import PUBLIC_READ_RESOURCES
from finsec.utils.redaction import REDACTED, is_sensitive_name
from finsec.utils.yaml_store import load_yaml, write_yaml

FORBIDDEN_PLAN_LANGUAGE = re.compile(
    r"\b(?:enumerat(?:e|ion)|brute[ -]?force|spray(?:ing)?|fuzz(?:ing)?)\b",
    re.IGNORECASE,
)
ENVIRONMENT_VARIABLE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
CLOUD_METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}


@dataclass(frozen=True)
class PreparedExecution:
    """Fully validated execution inputs; no HTTP request has been sent yet."""

    workspace: WorkspacePaths
    target: TargetDocument
    hypothesis: HypothesisRecord
    plan: TestPlanRecord
    endpoints: list[Endpoint]
    resolved_addresses: dict[str, tuple[str, ...]]
    plan_checksum: str
    target_policy_checksum: str
    runtime_headers: dict[str, dict[str, str]]


def plan_checksum(plan: TestPlanRecord) -> str:
    """Fingerprint generated plan content while excluding human lifecycle annotations."""

    document = plan.model_dump(mode="json", exclude_none=True)
    payload = {
        key: value
        for key, value in document.items()
        if key not in {"approval", "approval_status", "generation", "notes"}
    }
    return stable_fingerprint(payload)


def target_policy_checksum(target: TargetDocument) -> str:
    """Bind approval to the exact scope, accounts, restrictions, and execution policy."""

    return stable_fingerprint(
        {
            "target": target.target.model_dump(mode="json"),
            "scope": target.scope.model_dump(mode="json"),
            "accounts": [item.model_dump(mode="json") for item in target.accounts],
            "testing": target.testing.model_dump(mode="json"),
            "restrictions": target.restrictions.model_dump(mode="json"),
        }
    )


def _load_plan(workspace: WorkspacePaths, hypothesis_id: str) -> TestPlanRecord:
    if not workspace.test_plans.is_file():
        raise FinsecError("Execution refused: no generated test plan exists.")
    try:
        store = TestPlanStore.model_validate(load_yaml(workspace.test_plans))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Execution refused: cannot load test plans: {error}") from error
    plan = next(
        (item for item in store.plans if item.hypothesis_id.upper() == hypothesis_id.upper()),
        None,
    )
    if plan is None:
        raise FinsecError(f"Execution refused: no plan exists for {hypothesis_id.upper()}.")
    return plan


def _load_inputs(
    workspace: WorkspacePaths, hypothesis_id: str
) -> tuple[TargetDocument, HypothesisRecord, TestPlanRecord, list[Endpoint]]:
    try:
        target = TargetDocument.model_validate(load_yaml(workspace.target))
        endpoint_store = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Execution refused: cannot load policy inputs: {error}") from error
    hypothesis = find_hypothesis(workspace, hypothesis_id)
    plan = _load_plan(workspace, hypothesis.id)
    by_id = {item.id: item for item in endpoint_store.endpoints}
    endpoints = [by_id[item] for item in hypothesis.source.endpoints if item in by_id]
    return target, hypothesis, plan, endpoints


def _researcher_accounts(target: TargetDocument) -> set[str]:
    return {item.id for item in target.accounts if item.ownership == "researcher"}


def _plan_text(plan: TestPlanRecord) -> str:
    return "\n".join(
        [
            plan.purpose,
            *plan.preconditions,
            *plan.setup,
            *plan.actions,
            *plan.stop_conditions,
            *plan.cleanup,
            *plan.execution.blockers,
        ]
    )


def _validate_request_secrets(request: StructuredRequest) -> None:
    for name, value in request.headers.items():
        if is_sensitive_name(name) or REDACTED in value:
            raise FinsecError(
                f"Execution refused: request {request.id} contains a stored secret header."
            )
    for name, values in request.query_parameters.items():
        if is_sensitive_name(name) or any(REDACTED in value for value in values):
            raise FinsecError(
                f"Execution refused: request {request.id} contains a secret-bearing URL value."
            )
    for secret in request.runtime_secrets:
        if not ENVIRONMENT_VARIABLE.fullmatch(secret.variable):
            raise FinsecError(
                f"Execution refused: invalid runtime secret variable {secret.variable!r}."
            )


def _path_matches_template(template: str, concrete: str) -> bool:
    expected = [item for item in template.split("/") if item]
    actual = [item for item in concrete.split("/") if item]
    if len(expected) != len(actual):
        return False
    return all(
        bool(value) if item.startswith("{") and item.endswith("}") else item == value
        for item, value in zip(expected, actual, strict=True)
    )


def _request_matches_endpoint(request: StructuredRequest, endpoint: Endpoint) -> bool:
    return (
        request.method == endpoint.method
        and request.host in endpoint.hosts
        and _path_matches_template(endpoint.path, request.path)
    )


def _validate_request_pair(
    baseline: StructuredRequest,
    comparison: StructuredRequest,
    *,
    comparison_role: str,
) -> None:
    if baseline.role != "BASELINE" or comparison.role != comparison_role:
        raise FinsecError("Execution refused: request roles do not match the execution pattern.")
    if baseline.mutations or comparison.clone_of != baseline.id:
        raise FinsecError("Execution refused: comparison request is not bound to its baseline.")


def _same_request_surface(
    baseline: StructuredRequest,
    comparison: StructuredRequest,
    *,
    excluded: set[str],
) -> bool:
    fields = {
        "method",
        "scheme",
        "host",
        "port",
        "path",
        "query_parameters",
        "headers",
        "runtime_secrets",
        "remove_headers",
        "body",
        "actor",
        "channel",
        "expected",
    }
    return all(
        getattr(baseline, field) == getattr(comparison, field) for field in fields - excluded
    )


def _matching_endpoint(request: StructuredRequest, endpoints: list[Endpoint]) -> Endpoint | None:
    return next(
        (endpoint for endpoint in endpoints if _request_matches_endpoint(request, endpoint)),
        None,
    )


def _shared_template_parameters_are_unchanged(
    baseline: StructuredRequest,
    baseline_endpoint: Endpoint,
    comparison: StructuredRequest,
    comparison_endpoint: Endpoint,
) -> bool:
    before_template = baseline_endpoint.path.split("/")
    after_template = comparison_endpoint.path.split("/")
    before_path = baseline.path.split("/")
    after_path = comparison.path.split("/")
    if not (len(before_template) == len(after_template) == len(before_path) == len(after_path)):
        return False
    route_changed = False
    for before_item, after_item, before_value, after_value in zip(
        before_template,
        after_template,
        before_path,
        after_path,
        strict=True,
    ):
        before_parameter = before_item.startswith("{") and before_item.endswith("}")
        after_parameter = after_item.startswith("{") and after_item.endswith("}")
        if before_parameter or after_parameter:
            if not before_parameter or not after_parameter or before_value != after_value:
                return False
        elif before_item != after_item:
            route_changed = True
    return route_changed


def _validate_object_binding(
    plan: TestPlanRecord,
    endpoints: list[Endpoint],
    controlled_accounts: set[str],
) -> None:
    if len(plan.requests) != 2 or not endpoints:
        raise FinsecError("Execution refused: object substitution requires exactly two requests.")
    endpoint = endpoints[0]
    if endpoint.resource.type.lower() in PUBLIC_READ_RESOURCES:
        raise FinsecError("Execution refused: known-public resources cannot use BOLA execution.")
    baseline, mutated = plan.requests
    _validate_request_pair(baseline, mutated, comparison_role="MUTATED")
    if not _request_matches_endpoint(baseline, endpoint) or not _request_matches_endpoint(
        mutated, endpoint
    ):
        raise FinsecError("Execution refused: request templates do not match the source endpoint.")
    if not _same_request_surface(baseline, mutated, excluded={"path", "expected"}):
        raise FinsecError("Execution refused: object substitution changes more than the object ID.")
    if len(mutated.mutations) != 1 or mutated.mutations[0].dimension != "OBJECT":
        raise FinsecError("Execution refused: exactly one OBJECT mutation is required.")
    mutation = mutated.mutations[0]
    if mutation.location != "path" or mutation.to_value is None:
        raise FinsecError("Execution refused: object substitution requires one path mutation.")
    if (
        mutation.source_actor not in controlled_accounts
        or mutation.target_actor not in controlled_accounts
        or mutation.source_actor != baseline.actor
        or mutation.target_actor == baseline.actor
        or mutation.from_value == mutation.to_value
    ):
        raise FinsecError("Execution refused: object mutation references an uncontrolled actor.")
    binding = next(
        (
            item
            for item in endpoint.object_access
            if item.identifier == mutation.parameter and item.actor_object_binding_observed
        ),
        None,
    )
    if binding is None:
        raise FinsecError("Execution refused: passive actor-object-owner binding is missing.")
    available = {
        (item.actor, item.requested_value, item.owner_value_fingerprint)
        for item in binding.baselines
    }
    source = (
        mutation.source_actor,
        mutation.from_value,
        baseline.expected.owner_fingerprint or "",
    )
    target = (
        mutation.target_actor,
        mutation.to_value or "",
        mutated.expected.owner_fingerprint or "",
    )
    if source not in available or target not in available:
        raise FinsecError(
            "Execution refused: mutation values are not controlled passive baselines."
        )
    template = endpoint.path.split("/")
    before = baseline.path.split("/")
    after = mutated.path.split("/")
    marker = f"{{{mutation.parameter}}}"
    if template.count(marker) != 1 or not (len(template) == len(before) == len(after)):
        raise FinsecError(
            "Execution refused: mutation parameter is not the endpoint path identifier."
        )
    parameter_index = template.index(marker)
    if (
        before[parameter_index] != mutation.from_value
        or after[parameter_index] != mutation.to_value
        or any(
            before[index] != after[index]
            for index in range(len(before))
            if index != parameter_index
        )
    ):
        raise FinsecError(
            "Execution refused: object substitution changed an unapproved path value."
        )


def _validate_authentication_comparison(
    plan: TestPlanRecord,
    endpoints: list[Endpoint],
) -> None:
    if len(plan.requests) != 2:
        raise FinsecError("Execution refused: malformed authentication comparison.")
    baseline, comparison = plan.requests
    _validate_request_pair(baseline, comparison, comparison_role="MUTATED")
    if len(comparison.mutations) != 1:
        raise FinsecError("Execution refused: malformed authentication comparison.")
    mutation = comparison.mutations[0]
    if mutation.dimension != "AUTHENTICATION" or mutation.location != "header":
        raise FinsecError("Execution refused: authentication comparison changed another dimension.")
    if not endpoints or any(
        not _request_matches_endpoint(request, endpoints[0]) for request in plan.requests
    ):
        raise FinsecError(
            "Execution refused: authentication requests do not match the source endpoint."
        )
    if len(baseline.runtime_secrets) != 1:
        raise FinsecError("Execution refused: exactly one authentication marker is required.")
    secret = baseline.runtime_secrets[0]
    if (
        not _same_request_surface(
            baseline,
            comparison,
            excluded={"runtime_secrets", "remove_headers"},
        )
        or baseline.remove_headers
        or comparison.runtime_secrets
        or comparison.remove_headers != [secret.header]
        or mutation.parameter != secret.header
        or mutation.from_value != f"environment:{secret.variable}"
        or mutation.to_value is not None
        or mutation.source_actor != baseline.actor
        or mutation.target_actor != baseline.actor
    ):
        raise FinsecError(
            "Execution refused: authentication comparison must remove exactly one marker."
        )


def _validate_route_comparison(plan: TestPlanRecord, endpoints: list[Endpoint]) -> None:
    if len(plan.requests) != 2:
        raise FinsecError("Execution refused: malformed route comparison.")
    baseline, comparison = plan.requests
    _validate_request_pair(baseline, comparison, comparison_role="COMPARISON")
    if len(comparison.mutations) != 1:
        raise FinsecError("Execution refused: malformed route comparison.")
    mutation = comparison.mutations[0]
    dimension = "VERSION" if plan.execution.pattern == "VERSION_COMPARISON" else "CHANNEL"
    if mutation.dimension != dimension:
        raise FinsecError("Execution refused: route comparison changed another dimension.")
    baseline_endpoint = _matching_endpoint(baseline, endpoints)
    comparison_endpoint = _matching_endpoint(comparison, endpoints)
    if baseline_endpoint is None or comparison_endpoint is None:
        raise FinsecError("Execution refused: comparison request is not a source endpoint.")
    if dimension == "VERSION":
        valid = (
            mutation.location == "route"
            and mutation.parameter == "path"
            and mutation.from_value == baseline.path
            and mutation.to_value == comparison.path
            and baseline.path != comparison.path
            and _same_request_surface(baseline, comparison, excluded={"path"})
            and _shared_template_parameters_are_unchanged(
                baseline,
                baseline_endpoint,
                comparison,
                comparison_endpoint,
            )
        )
    else:
        valid = (
            mutation.location == "channel"
            and mutation.parameter == "channel"
            and mutation.from_value == baseline.channel
            and mutation.to_value == comparison.channel
            and baseline.channel != comparison.channel
            and _same_request_surface(baseline, comparison, excluded={"channel"})
            and baseline_endpoint.id == comparison_endpoint.id
        )
    if (
        not valid
        or mutation.source_actor != baseline.actor
        or mutation.target_actor != comparison.actor
    ):
        raise FinsecError(
            f"Execution refused: {dimension.lower()} comparison changes more than one dimension."
        )


def _validate_supported_shape(
    plan: TestPlanRecord,
    endpoints: list[Endpoint],
    controlled_accounts: set[str],
) -> None:
    if not plan.execution.supported or plan.execution.pattern == "UNSUPPORTED":
        detail = "; ".join(plan.execution.blockers) or "plan is manual-only"
        raise FinsecError(f"Execution refused: {detail}")
    if len(plan.execution.mutation_dimensions) != 1:
        raise FinsecError("Execution refused: exactly one mutation dimension is permitted.")
    if plan.execution.pattern == "OBJECT_SUBSTITUTION":
        _validate_object_binding(plan, endpoints, controlled_accounts)
    elif plan.execution.pattern == "AUTHENTICATION_COMPARISON":
        _validate_authentication_comparison(plan, endpoints)
    elif plan.execution.pattern in {"VERSION_COMPARISON", "CHANNEL_COMPARISON"}:
        _validate_route_comparison(plan, endpoints)
    else:
        raise FinsecError("Execution refused: unsupported execution pattern.")


def _validate_static_policy(
    target: TargetDocument,
    hypothesis: HypothesisRecord,
    plan: TestPlanRecord,
    endpoints: list[Endpoint],
) -> None:
    if hypothesis.kind != "SECURITY_HYPOTHESIS" or hypothesis.disposition != "ACTIVE":
        raise FinsecError("Execution refused: hypothesis is not an active security hypothesis.")
    if hypothesis.status in {"REFUTED", "CONFIRMED"}:
        raise FinsecError(f"Execution refused: hypothesis status is {hypothesis.status}.")
    if plan.status != "READY_FOR_REVIEW" or plan.risk.decision == "BLOCKED":
        raise FinsecError(f"Execution refused: plan status is {plan.status}.")
    if not plan.human_approval_required or not target.testing.human_approval_required:
        raise FinsecError("Execution refused: human approval must remain mandatory.")
    if plan.execution_default != "DO_NOT_EXECUTE":
        raise FinsecError("Execution refused: invalid execution-default policy.")
    if FORBIDDEN_PLAN_LANGUAGE.search(_plan_text(plan)):
        raise FinsecError(
            "Execution refused: plan contains enumeration, brute force, spraying, or fuzzing."
        )
    if target.restrictions.real_user_testing:
        raise FinsecError("Execution refused: real-user testing cannot be enabled for this runner.")
    if target.testing.destructive_testing or target.restrictions.destructive_actions:
        raise FinsecError(
            "Execution refused: destructive-testing policy is incompatible with this runner."
        )
    if target.testing.maximum_parallel_requests != 1 or plan.execution.parallelism != 1:
        raise FinsecError(
            "Execution refused: bounded execution requires parallelism of exactly one."
        )
    if not target.testing.read_only_only:
        raise FinsecError("Execution refused: read_only_only must remain enabled.")
    if any(
        request.method not in {"GET", "HEAD"} or request.body is not None
        for request in plan.requests
    ):
        raise FinsecError("Execution refused: first-version execution supports GET and HEAD only.")
    if len({request.id for request in plan.requests}) != len(plan.requests):
        raise FinsecError("Execution refused: request IDs must be unique.")
    if any(
        not request.path.startswith("/")
        or "?" in request.path
        or "#" in request.path
        or any(ord(character) < 32 for character in request.path)
        for request in plan.requests
    ):
        raise FinsecError("Execution refused: request paths must be normalized URL paths.")
    if any(item.state_change for item in endpoints):
        raise FinsecError("Execution refused: state-changing endpoints are unsupported.")
    if any(
        item.resource.type.lower() in {"payment", "refund", "withdrawal", "transfer"}
        and item.state_change
        for item in endpoints
    ):
        raise FinsecError("Execution refused: financial mutations are unsupported.")
    count = len(plan.requests)
    if count == 0 or count != plan.execution.request_budget or count > plan.risk.request_budget:
        raise FinsecError(
            "Execution refused: request count does not match the approved plan budget."
        )
    if count > target.testing.maximum_requests_per_plan:
        raise FinsecError("Execution refused: plan exceeds target maximum_requests_per_plan.")
    if target.testing.production and count > 3:
        raise FinsecError("Execution refused: production plans are limited to three requests.")
    controlled = _researcher_accounts(target)
    if not controlled:
        raise FinsecError("Execution refused: no researcher-controlled account is configured.")
    if any(request.actor not in controlled for request in plan.requests):
        raise FinsecError("Execution refused: a request targets an uncontrolled actor.")
    for request in plan.requests:
        _validate_request_secrets(request)
    _validate_supported_shape(plan, endpoints, controlled)


def _resolve_host(host: str, port: int, local_lab: bool) -> tuple[str, ...]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise FinsecError(
            f"Execution refused: DNS resolution failed for {host}: {error}"
        ) from error
    addresses = sorted({str(item[4][0]) for item in records})
    if not addresses:
        raise FinsecError(f"Execution refused: DNS returned no addresses for {host}.")
    for text in addresses:
        address = ipaddress.ip_address(text)
        if address in CLOUD_METADATA_ADDRESSES:
            raise FinsecError("Execution refused: cloud metadata destinations are prohibited.")
        if address.is_multicast or address.is_unspecified or address.is_reserved:
            raise FinsecError(f"Execution refused: prohibited destination address {address}.")
        if (address.is_loopback or address.is_private or address.is_link_local) and not local_lab:
            raise FinsecError(
                f"Execution refused: local/private destination {address} requires local_lab: true."
            )
    return tuple(addresses)


def _resolve_scope(
    target: TargetDocument, requests: list[StructuredRequest]
) -> dict[str, tuple[str, ...]]:
    resolved: dict[str, tuple[str, ...]] = {}
    for request in requests:
        if request.scheme not in {"http", "https"}:
            raise FinsecError("Execution refused: only HTTP and HTTPS schemes are supported.")
        if not host_is_covered(request.host, target.scope.hosts):
            raise FinsecError(f"Execution refused: host {request.host} is outside target scope.")
        port = request.port or (443 if request.scheme == "https" else 80)
        resolved[request.id] = _resolve_host(request.host, port, target.testing.local_lab)
    return resolved


def _runtime_headers(plan: TestPlanRecord) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for request in plan.requests:
        headers: dict[str, str] = {}
        for secret in request.runtime_secrets:
            value = os.environ.get(secret.variable)
            if value is None or not value:
                raise FinsecError(
                    f"Execution refused: required runtime secret {secret.variable} is missing."
                )
            headers[secret.header] = value
        result[request.id] = headers
    return result


def _validate_approval(
    target: TargetDocument,
    plan: TestPlanRecord,
    current_plan_checksum: str,
    current_target_checksum: str,
    *,
    non_interactive: bool,
    approval_token_env: str | None,
) -> None:
    if not target.testing.active_execution_enabled:
        raise FinsecError("Execution refused: active_execution_enabled is false in target.yaml.")
    if plan.approval_status != "APPROVED" or plan.approval is None or not plan.approval.enabled:
        raise FinsecError(
            "Execution refused: approval_status alone is not sufficient. "
            f"Run 'hunt approve {plan.hypothesis_id}' to create a checksum-bound approval record."
        )
    if plan.approval.plan_checksum != current_plan_checksum:
        raise FinsecError("Execution refused: plan content changed after approval.")
    if plan.approval.target_policy_checksum != current_target_checksum:
        raise FinsecError("Execution refused: target policy changed after approval.")
    if non_interactive:
        if target.testing.production or not target.testing.local_lab:
            raise FinsecError("Execution refused: non-interactive mode is local-lab only.")
        if approval_token_env is None or not ENVIRONMENT_VARIABLE.fullmatch(approval_token_env):
            raise FinsecError(
                "Execution refused: --approval-token must name an environment variable."
            )
        token = os.environ.get(approval_token_env)
        if not token or plan.approval.approval_token_sha256 is None:
            raise FinsecError("Execution refused: non-interactive approval token is unavailable.")
        digest = hashlib.sha256(token.encode()).hexdigest()
        if digest != plan.approval.approval_token_sha256:
            raise FinsecError("Execution refused: non-interactive approval token does not match.")


def approve_plan(
    workspace: WorkspacePaths,
    hypothesis_id: str,
    *,
    approved_by: str,
    approval_token: str | None = None,
) -> TestPlanRecord:
    """Record human approval bound to current plan and target policy; never send requests."""

    target, hypothesis, plan, endpoints = _load_inputs(workspace, hypothesis_id)
    _validate_static_policy(target, hypothesis, plan, endpoints)
    if not target.testing.active_execution_enabled:
        raise FinsecError(
            "Approval refused: set active_execution_enabled: true before approving execution."
        )
    reviewer = approved_by.strip()
    if not reviewer:
        raise FinsecError("Approval refused: approved_by must be a non-empty researcher label.")
    from datetime import UTC, datetime

    plan.approval_status = "APPROVED"
    plan.approval = PlanApproval(
        approved_by=reviewer,
        approved_at=datetime.now(UTC),
        plan_checksum=plan_checksum(plan),
        target_policy_checksum=target_policy_checksum(target),
        approval_token_sha256=(
            hashlib.sha256(approval_token.encode()).hexdigest() if approval_token else None
        ),
    )
    store = TestPlanStore.model_validate(load_yaml(workspace.test_plans))
    for index, item in enumerate(store.plans):
        if item.id == plan.id:
            store.plans[index] = plan
            break
    write_yaml(workspace.test_plans, store.model_dump(mode="json", exclude_none=True))
    return plan


def prepare_execution(
    workspace: WorkspacePaths,
    hypothesis_id: str,
    *,
    dry_run: bool,
    non_interactive: bool = False,
    approval_token_env: str | None = None,
) -> PreparedExecution:
    """Validate every safety boundary before the runner is allowed to send HTTP."""

    target, hypothesis, plan, endpoints = _load_inputs(workspace, hypothesis_id)
    _validate_static_policy(target, hypothesis, plan, endpoints)
    current_plan_checksum = plan_checksum(plan)
    current_target_checksum = target_policy_checksum(target)
    resolved = _resolve_scope(target, plan.requests)
    runtime_headers: dict[str, dict[str, str]] = {}
    if not dry_run:
        _validate_approval(
            target,
            plan,
            current_plan_checksum,
            current_target_checksum,
            non_interactive=non_interactive,
            approval_token_env=approval_token_env,
        )
        runtime_headers = _runtime_headers(plan)
    return PreparedExecution(
        workspace=workspace,
        target=target,
        hypothesis=hypothesis,
        plan=plan,
        endpoints=endpoints,
        resolved_addresses=resolved,
        plan_checksum=current_plan_checksum,
        target_policy_checksum=current_target_checksum,
        runtime_headers=runtime_headers,
    )
