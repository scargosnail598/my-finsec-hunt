"""Generate bounded request templates only from redacted passive observations."""

import json
import re
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlsplit

from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.hypotheses.domain import HypothesisRecord
from finsec.modeling.models import (
    ActorObjectBaseline,
    Endpoint,
    ObjectAccessEvidence,
    Observation,
    ObservationStore,
)
from finsec.modeling.semantics import execution_ownership_supported
from finsec.testing.domain import (
    PlanExecutionConfig,
    RequestExpectation,
    RequestMutation,
    RuntimeSecretReference,
    StructuredRequest,
)
from finsec.utils.redaction import REDACTED, is_sensitive_name

PUBLIC_READ_RESOURCES = {"category", "challenge", "product", "staticasset"}
SAFE_STORED_HEADERS = {"accept", "content-type"}
MANDATORY_STOP_CONDITIONS = [
    "baseline request fails",
    "unexpected HTTP 5xx",
    "response size limit is exceeded",
    "redirect destination is out of scope",
    "DNS resolves to a prohibited destination",
    "TLS validation fails",
    "baseline object identity does not match",
    "request budget would be exceeded",
    "more than one mutation dimension is present",
    "an unexpected state-changing response is detected",
    "the researcher interrupts execution",
]


@dataclass(frozen=True)
class ExecutionTemplateResult:
    """Structured execution material returned to the static plan generator."""

    requests: list[StructuredRequest]
    execution: PlanExecutionConfig
    object_owner: str | None = None
    actor: str | None = None


def _environment_name(actor: str, header: str) -> str:
    actor_token = re.sub(r"[^A-Za-z0-9]+", "_", actor).strip("_").upper() or "ACTOR"
    header_token = "AUTH" if header.lower() == "authorization" else "COOKIE"
    return f"FINSEC_{actor_token}_{header_token}"


def _har_entry(workspace: WorkspacePaths, observation: Observation) -> dict[str, Any] | None:
    if observation.source != "HAR":
        return None
    reference, marker, index_text = observation.source_reference.partition("#entry-")
    if not marker or not index_text.isdigit():
        return None
    source = (workspace.root / reference).resolve()
    if not source.is_relative_to(workspace.root.resolve()) or not source.is_file():
        return None
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    index = int(index_text)
    if (
        not isinstance(entries, list)
        or index >= len(entries)
        or not isinstance(entries[index], dict)
    ):
        return None
    return cast(dict[str, Any], entries[index])


def _request_details(
    workspace: WorkspacePaths,
    target: TargetDocument,
    observation: Observation,
) -> tuple[int | None, dict[str, str], list[RuntimeSecretReference]]:
    entry = _har_entry(workspace, observation)
    request = entry.get("request") if isinstance(entry, dict) else None
    if not isinstance(request, dict):
        return None, {}, []
    url = request.get("url")
    parsed = urlsplit(url) if isinstance(url, str) else None
    try:
        port = parsed.port if parsed is not None else None
    except ValueError:
        port = None
    headers: dict[str, str] = {}
    secrets: list[RuntimeSecretReference] = []
    raw_headers = request.get("headers")
    observed_names: set[str] = set()
    if isinstance(raw_headers, list):
        for item in raw_headers:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            name = str(item["name"])
            normalized = name.strip().lower()
            observed_names.add(normalized)
            value = item.get("value")
            if (
                normalized in SAFE_STORED_HEADERS
                and isinstance(value, str)
                and value != REDACTED
                and not is_sensitive_name(name)
            ):
                canonical = "Accept" if normalized == "accept" else "Content-Type"
                headers[canonical] = value
    if isinstance(request.get("cookies"), list) and request["cookies"]:
        observed_names.add("cookie")
    account = next((item for item in target.accounts if item.id == observation.actor), None)
    authentication = account.authentication if account is not None else None
    if authentication is not None and authentication.profile_ref is not None:
        if authentication.source.type == "legacy_environment":
            for header, variable in authentication.legacy_environment.items():
                if header.lower() in observed_names:
                    secrets.append(
                        RuntimeSecretReference(
                            header=header,
                            source="environment",
                            variable=variable,
                            actor=observation.actor,
                        )
                    )
        else:
            for component in authentication.components:
                header = "Cookie" if component.location == "cookie" else component.name
                if (
                    component.replay_required
                    and component.location in {"header", "cookie"}
                    and header.lower() in observed_names
                ):
                    secrets.append(
                        RuntimeSecretReference(
                            header=header,
                            source="actor_store",
                            reference=component.credential_ref,
                            actor=observation.actor,
                        )
                    )
    else:
        for normalized in sorted(observed_names & {"authorization", "cookie"}):
            canonical = "Authorization" if normalized == "authorization" else "Cookie"
            secrets.append(
                RuntimeSecretReference(
                    header=canonical,
                    source="environment",
                    variable=_environment_name(observation.actor, canonical),
                    actor=observation.actor,
                )
            )
    return port, headers, sorted(secrets, key=lambda item: item.header)


def _observation_by_id(store: ObservationStore) -> dict[str, Observation]:
    return {item.id: item for item in store.observations}


def _template(
    workspace: WorkspacePaths,
    target: TargetDocument,
    observation: Observation,
    *,
    request_id: str,
    role: str,
    expected: RequestExpectation | None = None,
) -> StructuredRequest | None:
    if observation.method not in {"GET", "HEAD"} or observation.scheme not in {"http", "https"}:
        return None
    if any(
        REDACTED in value for values in observation.query_parameters.values() for value in values
    ):
        return None
    port, headers, secrets = _request_details(workspace, target, observation)
    return StructuredRequest(
        id=request_id,
        role=cast(Any, role),
        method=cast(Any, observation.method),
        scheme=cast(Any, observation.scheme),
        host=observation.host,
        port=port,
        path=observation.path,
        query_parameters=observation.query_parameters,
        headers=headers,
        runtime_secrets=secrets,
        actor=observation.actor,
        channel=observation.channel,
        expected=expected or RequestExpectation(),
    )


def _execution(
    target: TargetDocument,
    pattern: str,
    requests: list[StructuredRequest],
    dimension: str | None,
    blockers: list[str],
) -> PlanExecutionConfig:
    return PlanExecutionConfig(
        supported=not blockers and bool(requests),
        pattern=cast(Any, pattern if not blockers else "UNSUPPORTED"),
        blockers=blockers,
        request_budget=len(requests),
        parallelism=1,
        mutation_dimensions=[cast(Any, dimension)] if dimension is not None else [],
        connection_timeout_seconds=target.testing.connection_timeout_seconds,
        read_timeout_seconds=target.testing.read_timeout_seconds,
        maximum_response_bytes=target.testing.maximum_response_bytes,
        stop_conditions=MANDATORY_STOP_CONDITIONS,
    )


def _value_key(value: str) -> tuple[int, int | str]:
    return (0, int(value)) if value.isdigit() else (1, value)


def _replace_path_value(path: str, old: str, new: str) -> str | None:
    segments = path.split("/")
    matches = [index for index, segment in enumerate(segments) if segment == old]
    if len(matches) != 1:
        return None
    segments[matches[0]] = new
    return "/".join(segments)


def _baseline_expectation(
    binding: ObjectAccessEvidence,
    baseline: ActorObjectBaseline,
) -> RequestExpectation:
    if binding.source == "PATH_PARENT_SCOPE":
        return RequestExpectation(
            ownership_source="PATH_PARENT_SCOPE",
            scope_parameter=binding.scope_parameter or binding.identifier,
            nonempty_json_required=True,
            object_value=baseline.requested_value,
        )
    if binding.source == "CONTROLLED_LIFECYCLE":
        return RequestExpectation(
            ownership_source="CONTROLLED_LIFECYCLE",
            object_path=baseline.response_object_path,
            object_value=baseline.requested_value,
            baseline_id=baseline.baseline_id,
            subject_resource_id=baseline.subject_resource_id,
            parent_resource_id=baseline.parent_resource_id,
            relationship_ids=baseline.relationship_ids,
        )
    return RequestExpectation(
        ownership_source="RESPONSE_BODY",
        object_path=baseline.response_object_path,
        object_value=baseline.requested_value,
        owner_path=binding.owner_field_path,
        owner_fingerprint=baseline.owner_value_fingerprint,
    )


def _distinct_controlled_baselines(
    binding: ObjectAccessEvidence,
    source: ActorObjectBaseline,
    target: ActorObjectBaseline,
) -> bool:
    if source.actor == target.actor or source.requested_value == target.requested_value:
        return False
    if binding.source == "PATH_PARENT_SCOPE":
        return (
            source.scope_value_fingerprint is not None
            and target.scope_value_fingerprint is not None
            and source.scope_value_fingerprint != target.scope_value_fingerprint
        )
    if binding.source == "CONTROLLED_LIFECYCLE":
        return (
            source.subject_resource_id is not None
            and target.subject_resource_id is not None
            and source.subject_resource_id != target.subject_resource_id
            and source.baseline_id is not None
            and target.baseline_id is not None
        )
    return (
        source.owner_value_fingerprint is not None
        and target.owner_value_fingerprint is not None
        and source.owner_value_fingerprint != target.owner_value_fingerprint
    )


def _object_substitution(
    workspace: WorkspacePaths,
    target: TargetDocument,
    hypothesis: HypothesisRecord,
    endpoint: Endpoint,
    observations: ObservationStore,
) -> ExecutionTemplateResult:
    blockers: list[str] = []
    if endpoint.method not in {"GET", "HEAD"} or endpoint.state_change:
        blockers.append("Object substitution execution supports GET or HEAD read-only endpoints.")
    if endpoint.resource.type.lower() in PUBLIC_READ_RESOURCES:
        blockers.append("Known-public resources are not eligible for BOLA execution plans.")
    mutation_target = hypothesis.mutation_target
    if mutation_target.parameter is None:
        blockers.append("The hypothesis does not identify an exact mutation parameter.")
    elif not execution_ownership_supported(mutation_target.semantics):
        blockers.append(
            f"Identifier {mutation_target.parameter} is {mutation_target.semantics.semantic_class} "
            f"with ownership state {mutation_target.semantics.ownership_state}; strong "
            "owned-object evidence is required."
        )
    if mutation_target.location != "path" or mutation_target.json_path is not None:
        blockers.append(
            "Automated object substitution supports exact path targets only; the semantic "
            "target remains available for manual review."
        )
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))
    binding = next(
        (
            item
            for item in endpoint.object_access
            if item.actor_object_binding_observed
            and mutation_target.parameter is not None
            and item.identifier.lower() == mutation_target.parameter.lower()
        ),
        None,
    )
    if binding is None:
        blockers.append("Two controlled actor-object-owner baselines are required for execution.")
        blockers.extend(
            reason
            for decision in endpoint.ownership_inference
            for reason in decision.reasons
            if reason not in blockers
        )
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))

    source_baseline: ActorObjectBaseline | None
    target_baseline: ActorObjectBaseline | None
    if binding.source == "CONTROLLED_LIFECYCLE":
        baselines = sorted(
            binding.baselines,
            key=lambda item: (
                0 if item.endpoint_id == endpoint.id else 1,
                item.actor,
                _value_key(item.requested_value),
            ),
        )
        source_baseline = next(
            (item for item in baselines if item.endpoint_id == endpoint.id),
            None,
        )
        target_baseline = (
            next(
                (
                    item
                    for item in baselines
                    if source_baseline is not None
                    and _distinct_controlled_baselines(binding, source_baseline, item)
                ),
                None,
            )
            if source_baseline is not None
            else None
        )
    elif binding.source == "PATH_PARENT_SCOPE":
        baselines = sorted(
            binding.baselines, key=lambda item: (item.actor, _value_key(item.requested_value))
        )
        source_baseline = baselines[0]
        target_baseline = next(
            (
                item
                for item in baselines[1:]
                if _distinct_controlled_baselines(binding, source_baseline, item)
            ),
            None,
        )
    else:
        baselines = sorted(
            binding.baselines, key=lambda item: (_value_key(item.requested_value), item.actor)
        )
        target_baseline = baselines[0]
        source_baseline = next(
            (
                item
                for item in reversed(baselines)
                if _distinct_controlled_baselines(binding, item, target_baseline)
            ),
            None,
        )
    if source_baseline is None or target_baseline is None:
        blockers.append("No distinct controlled source and target baselines are available.")
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))

    by_id = _observation_by_id(observations)
    source_observation = next(
        (by_id[item] for item in source_baseline.observations if item in by_id),
        None,
    )
    if source_observation is None:
        blockers.append("The baseline observation cannot be resolved.")
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))

    baseline = _template(
        workspace,
        target,
        source_observation,
        request_id="baseline",
        role="BASELINE",
        expected=_baseline_expectation(binding, source_baseline),
    )
    mutated_path = _replace_path_value(
        source_observation.path,
        source_baseline.requested_value,
        target_baseline.requested_value,
    )
    if baseline is None or mutated_path is None:
        blockers.append("A safe structured baseline request cannot be reconstructed.")
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))

    mutated = baseline.model_copy(deep=True)
    mutated.id = "object-substitution"
    mutated.role = "MUTATED"
    mutated.clone_of = baseline.id
    mutated.path = mutated_path
    mutated.expected = _baseline_expectation(binding, target_baseline)
    mutated.mutations = [
        RequestMutation(
            dimension="OBJECT",
            location="path",
            parameter=binding.identifier,
            from_value=source_baseline.requested_value,
            to_value=target_baseline.requested_value,
            source_actor=source_baseline.actor,
            target_actor=target_baseline.actor,
            source_resource_id=source_baseline.subject_resource_id,
            target_resource_id=target_baseline.subject_resource_id,
            source_parent_resource_id=source_baseline.parent_resource_id,
            target_parent_resource_id=target_baseline.parent_resource_id,
            substitution_scope="SUBJECT_ONLY",
        )
    ]
    requests = [baseline, mutated]
    return ExecutionTemplateResult(
        requests,
        _execution(target, "OBJECT_SUBSTITUTION", requests, "OBJECT", blockers),
        object_owner=target_baseline.actor,
        actor=source_baseline.actor,
    )


def _authentication_comparison(
    workspace: WorkspacePaths,
    target: TargetDocument,
    endpoint: Endpoint,
    observations: ObservationStore,
) -> ExecutionTemplateResult:
    by_id = _observation_by_id(observations)
    runtime = [by_id[item] for item in endpoint.sources if item in by_id]
    authenticated = next(
        (
            item
            for item in runtime
            if item.authentication.present
            and item.status_code is not None
            and 200 <= item.status_code < 300
        ),
        None,
    )
    blockers: list[str] = []
    if endpoint.method not in {"GET", "HEAD"} or endpoint.state_change:
        blockers.append("Authentication comparison supports read-only GET or HEAD endpoints.")
    if authenticated is None:
        blockers.append("An authenticated successful runtime baseline is required.")
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))
    baseline = _template(
        workspace,
        target,
        authenticated,
        request_id="authenticated-baseline",
        role="BASELINE",
    )
    if baseline is None or not baseline.runtime_secrets:
        blockers.append("At least one runtime authentication marker is required.")
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))
    secrets = baseline.runtime_secrets
    comparison = baseline.model_copy(deep=True)
    comparison.id = "authentication-removed"
    comparison.role = "MUTATED"
    comparison.clone_of = baseline.id
    comparison.runtime_secrets = []
    comparison.remove_headers = sorted({secret.header for secret in secrets})
    profile = next(
        (
            account.authentication.profile_ref
            for account in target.accounts
            if account.id == baseline.actor and account.authentication is not None
        ),
        None,
    )
    source_reference = (
        f"actor_profile:{profile}"
        if profile is not None
        else "environment:" + ",".join(secret.variable or "" for secret in secrets)
    )
    comparison.mutations = [
        RequestMutation(
            dimension="AUTHENTICATION",
            location="header",
            parameter="credential_profile",
            from_value=source_reference,
            to_value=None,
            source_actor=baseline.actor,
            target_actor=baseline.actor,
        )
    ]
    requests = [baseline, comparison]
    return ExecutionTemplateResult(
        requests,
        _execution(target, "AUTHENTICATION_COMPARISON", requests, "AUTHENTICATION", blockers),
        actor=baseline.actor,
    )


def _comparison_observation(
    endpoint: Endpoint,
    observations: ObservationStore,
    *,
    excluded_channels: set[str] | None = None,
) -> Observation | None:
    by_id = _observation_by_id(observations)
    return next(
        (
            by_id[item]
            for item in endpoint.sources
            if item in by_id
            and by_id[item].method in {"GET", "HEAD"}
            and (excluded_channels is None or by_id[item].channel not in excluded_channels)
        ),
        None,
    )


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


def _route_comparison(
    workspace: WorkspacePaths,
    target: TargetDocument,
    endpoints: list[Endpoint],
    observations: ObservationStore,
    dimension: str,
) -> ExecutionTemplateResult:
    blockers: list[str] = []
    first: Observation | None = None
    second: Observation | None = None
    if dimension == "VERSION" and len(endpoints) >= 2:
        first = _comparison_observation(endpoints[0], observations)
        second = _comparison_observation(endpoints[1], observations)
    elif dimension == "CHANNEL" and endpoints:
        first = _comparison_observation(endpoints[0], observations)
        if first is not None:
            second = _comparison_observation(
                endpoints[0], observations, excluded_channels={first.channel}
            )
    if first is None or second is None:
        blockers.append(f"Two matched read-only {dimension.lower()} baselines are required.")
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))
    baseline = _template(workspace, target, first, request_id="baseline", role="BASELINE")
    comparison = _template(workspace, target, second, request_id="comparison", role="COMPARISON")
    if baseline is None or comparison is None or baseline.method != comparison.method:
        blockers.append("Matched structured read-only requests cannot be reconstructed.")
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))
    comparison.clone_of = baseline.id
    if dimension == "VERSION":
        matched = baseline.path != comparison.path and _same_request_surface(
            baseline,
            comparison,
            excluded={"path"},
        )
    else:
        matched = baseline.channel != comparison.channel and _same_request_surface(
            baseline,
            comparison,
            excluded={"channel"},
        )
    if not matched:
        blockers.append(
            f"The observed requests differ by more than the {dimension.lower()} dimension."
        )
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))
    comparison.mutations = [
        RequestMutation(
            dimension=cast(Any, dimension),
            location="route" if dimension == "VERSION" else "channel",
            parameter="path" if dimension == "VERSION" else "channel",
            from_value=baseline.path if dimension == "VERSION" else baseline.channel,
            to_value=comparison.path if dimension == "VERSION" else comparison.channel,
            source_actor=baseline.actor,
            target_actor=comparison.actor,
        )
    ]
    requests = [baseline, comparison]
    pattern = "VERSION_COMPARISON" if dimension == "VERSION" else "CHANNEL_COMPARISON"
    return ExecutionTemplateResult(
        requests,
        _execution(target, pattern, requests, dimension, blockers),
        actor=baseline.actor,
    )


def build_execution_templates(
    workspace: WorkspacePaths,
    target: TargetDocument,
    hypothesis: HypothesisRecord,
    endpoints: list[Endpoint],
    observations: ObservationStore,
) -> ExecutionTemplateResult:
    """Build only the four explicitly supported bounded comparison shapes."""

    if not endpoints:
        blockers = ["No source endpoint is available for structured request generation."]
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))
    if hypothesis.generation_rule.get("id") == "JWT_ALGORITHM_VALIDATION":
        blockers = [
            "JWT algorithm validation is manual-only; unsigned-token fabrication is not "
            "supported by bounded execution."
        ]
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))
    if hypothesis.generation_rule.get("id") == "FUNCTION_AUTHORIZATION":
        blockers = [
            "Function-authorization validation is manual-only; state-changing role replay is "
            "not supported by bounded execution."
        ]
        return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))
    if hypothesis.category == "authorization":
        return _object_substitution(workspace, target, hypothesis, endpoints[0], observations)
    if hypothesis.category == "authentication":
        return _authentication_comparison(workspace, target, endpoints[0], observations)
    if hypothesis.category == "version_parity":
        return _route_comparison(workspace, target, endpoints, observations, "VERSION")
    if hypothesis.category == "channel_parity":
        return _route_comparison(workspace, target, endpoints, observations, "CHANNEL")
    blockers = ["The hypothesis category is manual-only in the first execution version."]
    return ExecutionTemplateResult([], _execution(target, "UNSUPPORTED", [], None, blockers))
