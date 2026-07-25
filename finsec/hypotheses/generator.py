"""Deterministic, evidence-backed Phase 3 hypothesis generation."""

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStatus, HypothesisStore
from finsec.modeling.domain import InvariantRecord, InvariantStore, ResourceRecord, ResourceStore
from finsec.modeling.invariants import FINANCIAL_RESOURCES
from finsec.modeling.merge import merge_generated_records, stable_fingerprint
from finsec.modeling.models import (
    Confidence,
    Endpoint,
    EndpointStore,
    KnowledgeStatus,
    ObservationStore,
)
from finsec.utils.yaml_store import load_yaml, write_yaml

VERSION_PATTERN = re.compile(r"(?P<prefix>/(?:api/)?)v(?P<version>\d+)(?=/|$)", re.IGNORECASE)


@dataclass(frozen=True)
class HypothesisResult:
    """Summary returned after backlog generation."""

    hypotheses: int
    conflicts: tuple[str, ...]


def _load_inputs(
    workspace: WorkspacePaths,
) -> tuple[TargetDocument, ObservationStore, EndpointStore, ResourceStore, InvariantStore]:
    try:
        target = TargetDocument.model_validate(load_yaml(workspace.target))
        observations = ObservationStore.model_validate(load_yaml(workspace.observations))
        endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))
        resources = ResourceStore.model_validate(load_yaml(workspace.resources))
        invariants = InvariantStore.model_validate(load_yaml(workspace.invariants))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load hypothesis inputs: {error}") from error
    if not invariants.invariants:
        raise FinsecError("Invariant model is empty; run 'hunt invariants' first.")
    return target, observations, endpoints, resources, invariants


def _priority(impact: int, likelihood: int, confidence: int, testability: int) -> str:
    total = impact + likelihood + confidence + testability
    if impact >= 4 and total >= 14:
        return "P1"
    if total >= 10:
        return "P2"
    return "P3"


def _score(impact: int, likelihood: int, confidence: int, testability: int) -> dict[str, int]:
    return {
        "impact": impact,
        "likelihood": likelihood,
        "confidence": confidence,
        "testability": testability,
        "total": impact + likelihood + confidence + testability,
    }


def _confidence_score(confidence: Confidence) -> int:
    return {Confidence.LOW: 2, Confidence.MEDIUM: 3, Confidence.HIGH: 4}[confidence]


def _observations(invariant: InvariantRecord) -> list[str]:
    return sorted(item for item in invariant.evidence if item.startswith("OBS-"))


def _source(invariant: InvariantRecord) -> dict[str, list[str]]:
    return {
        "endpoints": invariant.endpoints,
        "invariants": [invariant.id],
        "observations": _observations(invariant),
    }


def _resource_by_name(resources: ResourceStore) -> dict[str, ResourceRecord]:
    return {item.name: item for item in resources.resources}


def _authentication_hypothesis(
    invariant: InvariantRecord,
    endpoint: Endpoint,
    resource: ResourceRecord,
    researcher_accounts: int,
) -> dict[str, Any]:
    sensitive = bool(resource.sensitive_fields) or resource.name.lower() in FINANCIAL_RESOURCES
    impact = 4 if endpoint.method == "GET" and sensitive else 3
    likelihood = 2
    confidence = _confidence_score(invariant.confidence)
    testability = 4 if researcher_accounts >= 1 else 2
    scores = _score(impact, likelihood, confidence, testability)
    return {
        "key": f"auth-bypass:{endpoint.id}",
        "title": (
            f"Observed authentication requirement may not be enforced on "
            f"{endpoint.method} {endpoint.path}"
        ),
        "category": "authentication",
        "component": f"{resource.name} / {endpoint.id}",
        "source": _source(invariant),
        "invariant": [invariant.id],
        "observations": _observations(invariant),
        "mutation_dimensions": ["ACTOR"],
        "required_state": ["A researcher-controlled account can reproduce the observed request."],
        "attacker_capability": ["Can send one request without the observed credential context."],
        "evidence_status": KnowledgeStatus.INFERRED,
        "hypothesis": (
            f"The server may accept {endpoint.method} {endpoint.path} when the observed "
            "authentication credential is omitted, expired, or replaced with an "
            "unauthenticated context."
        ),
        "reasoning": (
            f"{endpoint.id} was observed with authentication, but traffic alone cannot confirm "
            "that the server enforces the same requirement."
        ),
        "preconditions": [
            "Use only a researcher-controlled account and object.",
            "Establish one successful authenticated baseline request.",
            "Program scope permits a single authentication-control request.",
        ],
        "expected_secure_behavior": (
            "The server rejects the unauthenticated request without returning protected data or "
            "changing server state."
        ),
        "possible_vulnerable_behavior": (
            "The server returns protected resource data or performs the operation without the "
            "required authenticated context."
        ),
        "potential_impact": {
            "confidentiality": "high" if endpoint.method == "GET" and sensitive else "medium",
            "integrity": "high" if endpoint.state_change else "none",
            "availability": "none",
            "financial": "unknown" if resource.name.lower() in FINANCIAL_RESOURCES else "none",
        },
        "evidence_to_collect": [
            "Redacted authenticated baseline request and response.",
            "Redacted unauthenticated control request and response.",
            "Before and after object state when the endpoint can change state.",
        ],
        "scores": scores,
        "priority": _priority(impact, likelihood, confidence, testability),
        "status": "NOT_TESTED",
        "safety_notes": [
            "Send at most one modified request after the baseline.",
            "Stop if unrelated user data or unexpected financial state appears.",
        ],
    }


def _object_authorization_hypothesis(
    invariant: InvariantRecord,
    endpoint: Endpoint,
    resource: ResourceRecord,
    parameter: str,
    researcher_accounts: int,
) -> dict[str, Any]:
    financial = resource.name.lower() in FINANCIAL_RESOURCES
    impact = 5 if endpoint.state_change and financial else 4
    likelihood = 3 if endpoint.authentication.required else 2
    confidence = _confidence_score(invariant.confidence)
    testability = 5 if researcher_accounts >= 2 else 2
    scores = _score(impact, likelihood, confidence, testability)
    action = "modification" if endpoint.state_change else "access"
    return {
        "key": f"cross-account:{endpoint.id}:{parameter}",
        "title": (
            f"Cross-account {resource.name} {action} through {parameter} on "
            f"{endpoint.method} {endpoint.path}"
        ),
        "category": "authorization",
        "component": f"{resource.name} / {endpoint.id}",
        "source": _source(invariant),
        "invariant": [invariant.id],
        "observations": _observations(invariant),
        "mutation_dimensions": ["ACTOR", "OBJECT"],
        "required_state": [f"Researcher Account A owns a reachable {resource.name} object."],
        "attacker_capability": [
            "Researcher Account B is separately authenticated.",
            f"Can substitute Account A's {parameter} into Account B's request.",
        ],
        "evidence_status": KnowledgeStatus.ASSUMED,
        "hypothesis": (
            f"Researcher Account B may be able to use Account A's {parameter} with "
            f"{endpoint.method} {endpoint.path} to cross the object-ownership boundary."
        ),
        "reasoning": (
            f"{endpoint.id} accepts the caller-controlled path identifier {parameter}, while "
            "ownership, delegation, tenant, and role conditions remain unconfirmed."
        ),
        "preconditions": [
            "Both accounts and the target object belong to the researcher.",
            f"Account A owns a non-sensitive test {resource.name} in a safe state.",
            "Account B can reproduce the same operation against its own object when applicable.",
        ],
        "expected_secure_behavior": (
            "The server rejects Account B's request and leaves Account A's object and "
            "data unchanged."
        ),
        "possible_vulnerable_behavior": (
            f"The server returns Account A's {resource.name} data or applies the requested "
            "operation to Account A's object."
        ),
        "potential_impact": {
            "confidentiality": "high" if not endpoint.state_change else "low",
            "integrity": "high" if endpoint.state_change else "none",
            "availability": "low" if endpoint.state_change else "none",
            "financial": "high" if endpoint.state_change and financial else "unknown",
        },
        "evidence_to_collect": [
            "Account A ownership evidence for the test object.",
            "Account B redacted request containing only the substituted identifier.",
            "Server response and Account A before/after state.",
        ],
        "scores": scores,
        "priority": _priority(impact, likelihood, confidence, testability),
        "status": "NOT_TESTED",
        "safety_notes": [
            "Use only researcher-owned accounts and objects.",
            "Change exactly one identifier and submit one request.",
            "Stop immediately after minimum proof of boundary behavior.",
        ],
    }


def _state_hypothesis(
    invariant: InvariantRecord, endpoint: Endpoint, resource: ResourceRecord, production: bool
) -> dict[str, Any]:
    financial = resource.name.lower() in FINANCIAL_RESOURCES
    impact = 5 if financial else 3
    likelihood = 2
    confidence = _confidence_score(invariant.confidence)
    testability = 4 if resource.states and not production else 1
    scores = _score(impact, likelihood, confidence, testability)
    return {
        "key": f"invalid-state:{endpoint.id}",
        "title": (
            f"{endpoint.method} {endpoint.path} may accept an invalid "
            f"{resource.name} state transition"
        ),
        "category": "state_integrity",
        "component": f"{resource.name} / {endpoint.id}",
        "source": _source(invariant),
        "invariant": [invariant.id],
        "observations": _observations(invariant),
        "mutation_dimensions": ["STATE", "TIME"],
        "required_state": [
            "A researcher-confirmed lifecycle and a reversible object state are available."
        ],
        "attacker_capability": ["Can invoke the observed state-changing operation once."],
        "evidence_status": KnowledgeStatus.ASSUMED,
        "hypothesis": (
            f"The server may accept {endpoint.method} {endpoint.path} when the {resource.name} "
            "is in a state where the operation should be forbidden."
        ),
        "reasoning": (
            "The endpoint appears state-changing, but allowed states, transition guards, and "
            "execution ordering are not yet confirmed."
        ),
        "preconditions": [
            "Researcher documents the intended lifecycle from direct evidence or "
            "program documentation.",
            "Use a researcher-owned object in a reversible, non-financial state.",
        ],
        "expected_secure_behavior": (
            "The server rejects the operation and preserves the original state."
        ),
        "possible_vulnerable_behavior": (
            "The server accepts the operation and creates a forbidden or inconsistent "
            "state transition."
        ),
        "potential_impact": {
            "confidentiality": "none",
            "integrity": "high",
            "availability": "low",
            "financial": "high" if financial else "none",
        },
        "evidence_to_collect": [
            "Evidence for the starting state and expected transition rule.",
            "One redacted request and response.",
            "Before and after state from an independent read operation.",
        ],
        "scores": scores,
        "priority": _priority(impact, likelihood, confidence, testability),
        "status": "NOT_TESTED",
        "safety_notes": [
            "Do not test until lifecycle evidence and reversibility are established.",
            "Do not use a real financial operation in production.",
        ],
    }


def _replay_hypothesis(
    invariant: InvariantRecord, endpoint: Endpoint, resource: ResourceRecord, production: bool
) -> dict[str, Any]:
    impact = 5
    likelihood = 2
    confidence = _confidence_score(invariant.confidence)
    testability = 2 if production else 4
    scores = _score(impact, likelihood, confidence, testability)
    return {
        "key": f"replay:{endpoint.id}",
        "title": (
            f"Duplicate {endpoint.method} {endpoint.path} may apply the financial effect twice"
        ),
        "category": "replay",
        "component": f"{resource.name} / {endpoint.id}",
        "source": _source(invariant),
        "invariant": [invariant.id],
        "observations": _observations(invariant),
        "mutation_dimensions": ["TIME"],
        "required_state": [
            "A negligible-value, researcher-owned, reversible operation is available."
        ],
        "attacker_capability": ["Can replay one previously valid request once."],
        "evidence_status": KnowledgeStatus.ASSUMED,
        "hypothesis": (
            f"Replaying the same logical request to {endpoint.method} {endpoint.path} may create "
            "more than one successful financial effect."
        ),
        "reasoning": (
            "The operation targets a financial resource, while idempotency keys, replay handling, "
            "and atomic accounting effects remain unobserved."
        ),
        "preconditions": [
            "Program rules explicitly permit a duplicate-request test.",
            "Use the smallest permitted value and a researcher-owned destination.",
        ],
        "expected_secure_behavior": (
            "The duplicate is rejected or returns the original result without a second "
            "financial effect."
        ),
        "possible_vulnerable_behavior": (
            "Both requests succeed independently and apply duplicate debits, credits, "
            "rewards, or refunds."
        ),
        "potential_impact": {
            "confidentiality": "none",
            "integrity": "high",
            "availability": "low",
            "financial": "high",
        },
        "evidence_to_collect": [
            "Request identifiers and idempotency fields with secrets redacted.",
            "Both responses and authoritative before/after accounting state.",
        ],
        "scores": scores,
        "priority": _priority(impact, likelihood, confidence, testability),
        "status": "NOT_TESTED",
        "safety_notes": [
            "Never use unbounded concurrency; a later approved plan may use at most two requests.",
            "Do not test against production without explicit financial-testing permission.",
        ],
    }


def _version(path: str) -> str | None:
    match = VERSION_PATTERN.search(path)
    return f"v{match.group('version')}" if match else None


def _version_signature(path: str) -> str | None:
    """Return a route signature only when one explicit API version is present."""

    match = VERSION_PATTERN.search(path)
    if match is None:
        return None
    replacement = f"{match.group('prefix')}v{{version}}"
    return f"{path[: match.start()]}{replacement}{path[match.end() :]}"


def _value_hypotheses(
    target: TargetDocument,
    endpoints: EndpointStore,
    invariants: InvariantStore,
    resources: ResourceStore,
) -> list[dict[str, Any]]:
    endpoint_by_id = {item.id: item for item in endpoints.endpoints}
    invariants_by_endpoint: dict[str, list[InvariantRecord]] = defaultdict(list)
    for invariant in invariants.invariants:
        for endpoint_id in invariant.endpoints:
            invariants_by_endpoint[endpoint_id].append(invariant)

    drafts: list[dict[str, Any]] = []
    for resource in resources.resources:
        boundary_fields = sorted(
            {
                field
                for field in resource.sensitive_fields
                if any(
                    name in field.lower()
                    for name in ("amount", "currency", "fee", "rate", "precision")
                )
            }
        )
        if not boundary_fields:
            continue
        for operation in resource.operations:
            endpoint = endpoint_by_id.get(operation.endpoint)
            if endpoint is None or not endpoint.state_change:
                continue
            related = invariants_by_endpoint.get(endpoint.id, [])
            invariant_ids = sorted(item.id for item in related)
            observations = sorted({source for item in related for source in _observations(item)})
            financial = resource.name.lower() in FINANCIAL_RESOURCES
            impact = 5 if financial else 3
            likelihood = 2
            confidence = 2
            testability = 2 if target.testing.production else 4
            scores = _score(impact, likelihood, confidence, testability)
            fields = ", ".join(boundary_fields)
            drafts.append(
                {
                    "key": f"value-boundary:{endpoint.id}:{'-'.join(boundary_fields)}",
                    "title": (
                        f"Boundary values in {fields} may bypass validation on "
                        f"{endpoint.method} {endpoint.path}"
                    ),
                    "category": "value_validation",
                    "component": f"{resource.name} / {endpoint.id}",
                    "source": {
                        "endpoints": [endpoint.id],
                        "invariants": invariant_ids,
                        "observations": observations,
                    },
                    "invariant": invariant_ids,
                    "observations": observations,
                    "mutation_dimensions": ["VALUE"],
                    "required_state": [
                        "A documented safe boundary and reversible researcher-owned "
                        "object are available."
                    ],
                    "attacker_capability": [
                        f"Can modify one observed value field ({fields}) in a valid request."
                    ],
                    "evidence_status": KnowledgeStatus.ASSUMED,
                    "hypothesis": (
                        f"The server may accept an invalid zero, boundary, precision, or currency "
                        f"combination in {fields} on {endpoint.method} {endpoint.path}."
                    ),
                    "reasoning": (
                        "Financially relevant field names are observed, but server-side range, "
                        "precision, currency, and consistency rules are not confirmed."
                    ),
                    "preconditions": [
                        "Program rules permit a single boundary-value request.",
                        "The researcher selects a non-dangerous documented boundary rather than an "
                        "automatically generated extreme value.",
                    ],
                    "expected_secure_behavior": (
                        "The server rejects invalid combinations without reserving, moving, or "
                        "misaccounting value."
                    ),
                    "possible_vulnerable_behavior": (
                        "The server accepts an invalid value combination and creates an incorrect "
                        "state or financial result."
                    ),
                    "potential_impact": {
                        "confidentiality": "none",
                        "integrity": "high",
                        "availability": "low",
                        "financial": "high" if financial else "unknown",
                    },
                    "evidence_to_collect": [
                        "The documented or observed valid boundary.",
                        "One redacted modified request and response.",
                        "Authoritative before/after state and accounting values.",
                    ],
                    "scores": scores,
                    "priority": _priority(impact, likelihood, confidence, testability),
                    "status": "NOT_TESTED",
                    "safety_notes": [
                        "Do not generate or execute extreme values automatically.",
                        "Use the smallest safe test value and one request only.",
                    ],
                }
            )
    return drafts


def _version_hypotheses(
    endpoints: EndpointStore, invariants: InvariantStore, resources: ResourceStore
) -> list[dict[str, Any]]:
    resource_names = {item.name for item in resources.resources}
    grouped: dict[tuple[str, str, str], list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints.endpoints:
        signature = _version_signature(endpoint.path)
        if endpoint.resource.type in resource_names and signature is not None:
            grouped[(endpoint.resource.type, endpoint.method, signature)].append(endpoint)
    invariants_by_endpoint: dict[str, list[InvariantRecord]] = defaultdict(list)
    for invariant in invariants.invariants:
        for endpoint_id in invariant.endpoints:
            invariants_by_endpoint[endpoint_id].append(invariant)

    drafts: list[dict[str, Any]] = []
    for (resource, method, signature), items in grouped.items():
        versions = sorted(
            {version for item in items if (version := _version(item.path)) is not None}
        )
        if len(versions) < 2:
            continue
        endpoint_ids = sorted(item.id for item in items)
        related = sorted(
            {
                invariant.id
                for endpoint_id in endpoint_ids
                for invariant in invariants_by_endpoint[endpoint_id]
            }
        )
        observations = sorted({source for item in items for source in item.sources})
        scores = _score(4, 3, 3, 4)
        drafts.append(
            {
                "key": (
                    f"version-parity:{resource.lower()}:{method.lower()}:"
                    f"{signature}:{'-'.join(versions)}"
                ),
                "title": (
                    f"Authorization or validation parity may differ across {', '.join(versions)} "
                    f"for {method} {signature}"
                ),
                "category": "version_parity",
                "component": f"{resource} / {', '.join(endpoint_ids)}",
                "source": {
                    "endpoints": endpoint_ids,
                    "invariants": related,
                    "observations": observations,
                },
                "invariant": related,
                "observations": observations,
                "mutation_dimensions": ["VERSION"],
                "required_state": [
                    "Equivalent researcher-owned objects exist across API versions."
                ],
                "attacker_capability": [
                    "Can send one equivalent request to each observed API version."
                ],
                "evidence_status": KnowledgeStatus.INFERRED,
                "hypothesis": (
                    f"The observed {', '.join(versions)} endpoints may enforce different "
                    "authentication, "
                    f"authorization, or input validation for equivalent {resource} operations."
                ),
                "reasoning": (
                    "Multiple API versions expose the same normalized route, resource, "
                    "and HTTP method."
                ),
                "preconditions": [
                    "Both versions are explicitly in scope.",
                    "Requests use the same researcher-controlled actor, object, and safe values.",
                ],
                "expected_secure_behavior": (
                    "Equivalent versions enforce the same security boundary or document "
                    "a safe difference."
                ),
                "possible_vulnerable_behavior": (
                    "An older or alternate version accepts an action rejected by the "
                    "stronger version."
                ),
                "potential_impact": {
                    "confidentiality": "high",
                    "integrity": "high",
                    "availability": "low",
                    "financial": "unknown",
                },
                "evidence_to_collect": [
                    "Matched redacted requests and responses for each version.",
                    "The exact authorization or validation difference.",
                ],
                "scores": scores,
                "priority": _priority(4, 3, 3, 4),
                "status": "NOT_TESTED",
                "safety_notes": [
                    "Use one request per version and identical researcher-owned data."
                ],
            }
        )
    return drafts


def _channel_hypotheses(
    endpoints: EndpointStore, invariants: InvariantStore, resources: ResourceStore
) -> list[dict[str, Any]]:
    resource_names = {item.name for item in resources.resources}
    invariants_by_endpoint: dict[str, list[InvariantRecord]] = defaultdict(list)
    for invariant in invariants.invariants:
        for endpoint_id in invariant.endpoints:
            invariants_by_endpoint[endpoint_id].append(invariant)

    drafts: list[dict[str, Any]] = []
    for endpoint in endpoints.endpoints:
        channels = sorted(channel for channel in endpoint.channels if channel != "UNKNOWN")
        if endpoint.resource.type not in resource_names or len(channels) < 2:
            continue
        related = sorted(item.id for item in invariants_by_endpoint[endpoint.id])
        observations = sorted(endpoint.sources)
        scores = _score(4, 3, 3, 4)
        drafts.append(
            {
                "key": f"channel-parity:{endpoint.id}:{'-'.join(channels)}",
                "title": (
                    f"Authorization or validation parity may differ across "
                    f"{', '.join(channels)} for {endpoint.method} {endpoint.path}"
                ),
                "category": "channel_parity",
                "component": f"{endpoint.resource.type} / {endpoint.id}",
                "source": {
                    "endpoints": [endpoint.id],
                    "invariants": related,
                    "observations": observations,
                },
                "invariant": related,
                "observations": observations,
                "mutation_dimensions": ["CHANNEL"],
                "required_state": [
                    "Equivalent researcher-owned objects and credentials are available "
                    "in both channels."
                ],
                "attacker_capability": [
                    "Can reproduce one semantically equivalent request through each "
                    "observed channel."
                ],
                "evidence_status": KnowledgeStatus.INFERRED,
                "hypothesis": (
                    f"{', '.join(channels)} may enforce different authentication, authorization, "
                    f"or input validation for {endpoint.method} {endpoint.path}."
                ),
                "reasoning": (
                    "The same normalized endpoint was directly observed through multiple labeled "
                    "client channels."
                ),
                "preconditions": [
                    "Both channels and the endpoint host are explicitly in scope.",
                    "Use identical researcher-owned accounts, objects, and safe values.",
                ],
                "expected_secure_behavior": (
                    "Both channels enforce an equivalent security boundary or a documented "
                    "safe difference."
                ),
                "possible_vulnerable_behavior": (
                    "One channel accepts an action or object reference rejected by the other."
                ),
                "potential_impact": {
                    "confidentiality": "high",
                    "integrity": "high",
                    "availability": "low",
                    "financial": "unknown",
                },
                "evidence_to_collect": [
                    "Matched redacted requests and responses from both channels.",
                    "The exact authentication, authorization, or validation difference.",
                ],
                "scores": scores,
                "priority": _priority(4, 3, 3, 4),
                "status": "NOT_TESTED",
                "safety_notes": [
                    "Use one request per channel and do not bypass device protections "
                    "unless permitted."
                ],
            }
        )
    return drafts


def _drafts(
    target: TargetDocument,
    endpoints: EndpointStore,
    resources: ResourceStore,
    invariants: InvariantStore,
) -> list[dict[str, Any]]:
    endpoint_by_id = {item.id: item for item in endpoints.endpoints}
    resource_by_name = _resource_by_name(resources)
    researcher_accounts = sum(1 for account in target.accounts if account.ownership == "researcher")
    drafts: list[dict[str, Any]] = []
    for invariant in invariants.invariants:
        if not invariant.endpoints or not invariant.resources:
            continue
        endpoint = endpoint_by_id.get(invariant.endpoints[0])
        resource = resource_by_name.get(invariant.resources[0])
        if endpoint is None or resource is None:
            continue
        if invariant.category == "authentication":
            drafts.append(
                _authentication_hypothesis(invariant, endpoint, resource, researcher_accounts)
            )
        elif invariant.category == "authorization":
            parameter = invariant.key.rsplit(":", 1)[-1]
            drafts.append(
                _object_authorization_hypothesis(
                    invariant,
                    endpoint,
                    resource,
                    parameter,
                    researcher_accounts,
                )
            )
        elif invariant.category == "state_integrity":
            drafts.append(
                _state_hypothesis(invariant, endpoint, resource, target.testing.production)
            )
        elif invariant.category == "single_execution":
            drafts.append(
                _replay_hypothesis(invariant, endpoint, resource, target.testing.production)
            )
    drafts.extend(_value_hypotheses(target, endpoints, invariants, resources))
    drafts.extend(_version_hypotheses(endpoints, invariants, resources))
    drafts.extend(_channel_hypotheses(endpoints, invariants, resources))
    return drafts


def generate_hypotheses(workspace: WorkspacePaths) -> HypothesisResult:
    """Generate a specific backlog without changing lifecycle status or notes."""

    target, observations, endpoints, resources, invariants = _load_inputs(workspace)
    fingerprint = stable_fingerprint(
        {
            "target": target.model_dump(mode="json"),
            "observations": observations.model_dump(mode="json", exclude_none=True),
            "endpoints": endpoints.model_dump(mode="json", exclude_none=True),
            "resources": resources.model_dump(mode="json", exclude_none=True),
            "invariants": invariants.model_dump(mode="json", exclude_none=True),
        }
    )
    merge = merge_generated_records(
        workspace.hypotheses,
        "hypotheses",
        "HYP",
        "phase3-hypothesis-generator",
        fingerprint,
        _drafts(target, endpoints, resources, invariants),
        preserved_fields=("status", "notes"),
    )
    try:
        store = HypothesisStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(
            f"Cannot validate hypothesis backlog {workspace.hypotheses}: {error}"
        ) from error
    write_yaml(workspace.hypotheses, store.model_dump(mode="json", exclude_none=True))
    return HypothesisResult(len(store.hypotheses), merge.conflicts)


def load_hypotheses(workspace: WorkspacePaths) -> HypothesisStore:
    """Load and validate the hypothesis backlog."""

    try:
        return HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load hypotheses: {error}") from error


def find_hypothesis(workspace: WorkspacePaths, hypothesis_id: str) -> HypothesisRecord:
    """Find one hypothesis by case-insensitive ID."""

    wanted = hypothesis_id.upper()
    for hypothesis in load_hypotheses(workspace).hypotheses:
        if hypothesis.id.upper() == wanted:
            return hypothesis
    raise FinsecError(f"Hypothesis not found: {hypothesis_id}")


def update_hypothesis_status(
    workspace: WorkspacePaths, hypothesis_id: str, status: HypothesisStatus
) -> HypothesisRecord:
    """Update only the human workflow status of one hypothesis."""

    store = load_hypotheses(workspace)
    for hypothesis in store.hypotheses:
        if hypothesis.id.upper() == hypothesis_id.upper():
            hypothesis.status = status
            write_yaml(workspace.hypotheses, store.model_dump(mode="json", exclude_none=True))
            return hypothesis
    raise FinsecError(f"Hypothesis not found: {hypothesis_id}")
