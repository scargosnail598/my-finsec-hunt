"""Deterministic, evidence-backed hypothesis generation."""

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from finsec.captures.domain import observation_supports_passive_baseline
from finsec.config.models import FunctionAuthorizationRule, JwtAlgorithmRule, TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.hypotheses.clustering import finalize_hypothesis_store
from finsec.hypotheses.domain import (
    BusinessEpistemicStatus,
    HypothesisRecord,
    HypothesisStatus,
    HypothesisStore,
)
from finsec.modeling.domain import InvariantRecord, InvariantStore, ResourceRecord, ResourceStore
from finsec.modeling.invariants import FINANCIAL_RESOURCES
from finsec.modeling.merge import merge_generated_records, stable_fingerprint
from finsec.modeling.models import (
    Confidence,
    Endpoint,
    EndpointPrimaryClassification,
    EndpointStore,
    KnowledgeStatus,
    ObjectAccessEvidence,
    Observation,
    ObservationStore,
)
from finsec.readiness.provenance import hypothesis_source_fingerprint, record_stage_provenance
from finsec.utils.yaml_store import load_yaml, write_yaml

VERSION_PATTERN = re.compile(r"(?P<prefix>/(?:api/)?)v(?P<version>\d+)(?=/|$)", re.IGNORECASE)
MUTABLE_PARAMETER_LOCATIONS = {"path", "query", "body", "header", "graphql_variable"}
RUNTIME_OBSERVATION_SOURCES = {"HAR", "BURP_XML", "CAIDO_JSON"}


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
    return {item.name: item for item in resources.resources if item.disposition == "ACTIVE"}


def _runtime_observations(
    endpoint: Endpoint, observations: dict[str, Observation]
) -> list[Observation]:
    """Return traffic observations, excluding documentation-only OpenAPI records."""

    return [
        observations[source]
        for source in endpoint.sources
        if source in observations
        and observations[source].source in RUNTIME_OBSERVATION_SOURCES
        and observation_supports_passive_baseline(observations[source])
    ]


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
            f"Anonymous access may expose protected {resource.name} data on "
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
            f"{endpoint.id} has an authenticated baseline and an anonymous HTTP 2xx response "
            "containing structured response data."
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
    binding: ObjectAccessEvidence | None = None,
) -> dict[str, Any]:
    financial = resource.name.lower() in FINANCIAL_RESOURCES
    impact = 5 if endpoint.state_change and financial else 4
    likelihood = 3 if endpoint.authentication.required or binding is not None else 2
    confidence = _confidence_score(invariant.confidence)
    if binding is not None:
        confidence = max(confidence, 3)
    testability = 5 if researcher_accounts >= 2 else 2
    scores = _score(impact, likelihood, confidence, testability)
    action = "modification" if endpoint.state_change else "access"
    unauthenticated_binding = binding is not None and not endpoint.authentication.required
    title = (
        f"Potential cross-account {resource.name} {action} through {parameter} on "
        f"{endpoint.method} {endpoint.path}"
    )
    if unauthenticated_binding:
        title = (
            f"Potential unauthenticated cross-account {resource.name} {action} through "
            f"{parameter} on {endpoint.method} {endpoint.path}"
        )
    attacker_capability = [
        "Researcher Account B is separately authenticated.",
        f"Can substitute Account A's {parameter} into Account B's request.",
    ]
    hypothesis = (
        f"An authenticated Researcher Account B may be able to use Account A's {parameter} with "
        f"{endpoint.method} {endpoint.path} to cross the object-ownership boundary."
    )
    reasoning = (
        f"{endpoint.id} accepts the client-controlled identifier {parameter}, while ownership, "
        "delegation, tenant, and role conditions remain unconfirmed."
    )
    required_state = [f"Researcher Account A owns a reachable {resource.name} object."]
    if binding is not None and binding.source == "PATH_PARENT_SCOPE":
        required_state = [f"Researcher Account A controls a reachable {parameter} parent scope."]
        attacker_capability = [
            "Researcher Account A is separately authenticated.",
            (
                f"Can replace Account A's {parameter} only with Account B's passively observed "
                "researcher-controlled value."
            ),
        ]
        hypothesis = (
            f"An authenticated Researcher Account A may be able to use Account B's {parameter} "
            f"with {endpoint.method} {endpoint.path} to cross the controlled parent-scope "
            "authorization boundary."
        )
        reasoning = (
            f"{binding.distinct_actors} researcher-controlled actors were passively observed "
            f"using distinct authenticated {parameter} parent scopes with successful non-empty "
            "JSON responses. The response did not supply ownership metadata, so ownership is "
            "inferred only from the explicitly trusted path scope. Cross-substitution has not "
            "yet been tested."
        )
    elif binding is not None and binding.source == "RESPONSE_BODY":
        owner_field = (binding.owner_field_path or "owner association").rsplit(".", 1)[-1]
        reasoning = (
            f"{binding.distinct_actors} researcher-controlled actors were passively observed "
            f"using distinct authenticated {parameter} values. Successful JSON responses matched "
            f"the requested object IDs and contained {binding.distinct_owner_values} distinct "
            f"{owner_field} values. Cross-substitution has not yet been tested."
        )
    elif unauthenticated_binding and binding is not None:
        owner_field = (binding.owner_field_path or "owner association").rsplit(".", 1)[-1]
        attacker_capability = [
            f"Can request {resource.name} objects without an observed request credential.",
            f"Can substitute one researcher-controlled actor's {parameter} into another baseline.",
        ]
        hypothesis = (
            f"An unauthenticated caller may be able to substitute another account's {parameter} "
            f"with {endpoint.method} {endpoint.path} and cross the {resource.name} ownership "
            "boundary."
        )
        reasoning = (
            f"{binding.distinct_actors} researcher-controlled actors were passively observed "
            f"retrieving distinct {resource.name} objects through {parameter}. Successful JSON "
            f"responses matched the requested object IDs and contained "
            f"{binding.distinct_owner_values} distinct {owner_field} values. No request "
            "authentication credential was observed. Cross-substitution has not yet been tested."
        )
    return {
        "key": (
            f"auth-object-access:{endpoint.method.lower()}:{endpoint.path}:"
            f"{resource.name.lower()}:{parameter.lower()}"
        ),
        "title": title,
        "category": "authorization",
        "component": f"{resource.name} / {endpoint.id}",
        "source": _source(invariant),
        "invariant": [invariant.id],
        "observations": _observations(invariant),
        "mutation_dimensions": ["ACTOR", "OBJECT"],
        "required_state": required_state,
        "attacker_capability": attacker_capability,
        "evidence_status": (
            KnowledgeStatus.INFERRED if binding is not None else KnowledgeStatus.ASSUMED
        ),
        "hypothesis": hypothesis,
        "reasoning": reasoning,
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


def _research_task(endpoint: Endpoint, reason: str) -> dict[str, Any]:
    """Create a non-vulnerability task for an interesting but under-evidenced endpoint."""

    title = f"Determine security semantics of {endpoint.method} {endpoint.path}"
    lowered = endpoint.path.lower()
    if "code/consume" in lowered:
        title = "Determine authentication code replay and binding semantics"
        reason = (
            "Code consumption is security-sensitive, but replay, challenge, session, and account "
            "binding have not been observed together."
        )
    elif "change-wallet" in lowered:
        title = "Determine whether change-wallet persists server-side state"
        reason = (
            "The route is mutation-like, but no authoritative before/after state or lifecycle "
            "evidence proves that it persists a server-side change."
        )
    elif "/user/verification" in lowered or "user_verification" in lowered:
        title = "Determine lifecycle and security impact of user verification"
        reason = (
            "The verification route is security-sensitive, but the supplied response does not "
            "prove a verification-state transition."
        )
    elif "wallet" in lowered:
        title = f"Determine wallet operation behavior for {endpoint.method} {endpoint.path}"
    elif "my-posts" in lowered:
        title = "Capture an authenticated account baseline for the post collection operation"
    scores = _score(2, 2, max(2, endpoint.security_relevance // 3), 2)
    return {
        "key": f"research:{endpoint.method.lower()}:{endpoint.path}",
        "title": title,
        "kind": "RESEARCH_TASK",
        "disposition": "NEEDS_RESEARCH",
        "category": "research",
        "component": f"{endpoint.resource.type} / {endpoint.id}",
        "source": {
            "endpoints": [endpoint.id],
            "invariants": [],
            "observations": endpoint.sources,
        },
        "invariant": [],
        "observations": endpoint.sources,
        "mutation_dimensions": [],
        "required_state": [],
        "attacker_capability": [],
        "evidence_status": KnowledgeStatus.INFERRED,
        "hypothesis": title,
        "reasoning": reason,
        "preconditions": ["Collect only authorized passive evidence or researcher annotations."],
        "expected_secure_behavior": "Not yet defined; this task discovers the intended boundary.",
        "possible_vulnerable_behavior": "Not asserted until the missing evidence is collected.",
        "potential_impact": {
            "confidentiality": "unknown",
            "integrity": "unknown",
            "availability": "none",
            "financial": (
                "unknown"
                if EndpointPrimaryClassification.FINANCIAL in endpoint.classification.tags
                else "none"
            ),
        },
        "evidence_to_collect": (
            [
                "Whether a consumed code can be replayed after successful consumption.",
                "Whether the code is bound to its challenge, session, account, and purpose.",
                "Matched Account A and Account B challenge baselines without brute force.",
            ]
            if "code/consume" in lowered
            else [
                "Authenticated baseline request and response field structure.",
                "Researcher-confirmed resource ownership, action, and lifecycle semantics.",
            ]
        ),
        "eligibility_evidence": endpoint.relevance_reasons,
        "missing_evidence": [reason],
        "generation_rule": {"id": "RESEARCH_DISCOVERY", "version": "1"},
        "priority_rationale": ["Research tasks are not vulnerability priorities."],
        "scores": scores,
        "priority": "P3",
        "status": "NOT_TESTED",
        "safety_notes": ["This task does not authorize sending requests or executing a test."],
    }


def _authentication_research_task(
    resource_name: str,
    endpoints: list[Endpoint],
    invariants: list[InvariantRecord],
) -> dict[str, Any]:
    """Group authenticated baselines that lack a concrete enforcement failure signal."""

    first = endpoints[0]
    title = f"Determine whether authentication is enforced on sensitive {resource_name} endpoints"
    reason = (
        "Authenticated baselines are observed, but no anonymous, malformed, expired, or revoked "
        "credential success demonstrates inconsistent enforcement."
    )
    task = _research_task(first, reason)
    endpoint_ids = sorted(item.id for item in endpoints)
    invariant_ids = sorted(item.id for item in invariants)
    observations = sorted({source for item in endpoints for source in item.sources})
    task.update(
        {
            "key": f"auth-enforcement-research:{resource_name.lower()}",
            "title": title,
            "component": f"{resource_name} / {', '.join(endpoint_ids)}",
            "source": {
                "endpoints": endpoint_ids,
                "invariants": invariant_ids,
                "observations": observations,
            },
            "invariant": invariant_ids,
            "observations": observations,
            "hypothesis": title,
            "reasoning": reason,
            "evidence_to_collect": [
                "One authorized unauthenticated or invalid-credential control response.",
                "Whether the response contains protected data or applies protected state.",
            ],
            "eligibility_evidence": ["authenticated baseline requests are observed"],
            "missing_evidence": ["no concrete authentication-enforcement failure is observed"],
            "generation_rule": {"id": "AUTH_ENFORCEMENT_RESEARCH", "version": "1"},
        }
    )
    return task


def _looks_like_outbound_destination(name: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    return compact.endswith(("api", "endpoint", "host", "domain", "url", "uri")) or any(
        marker in compact for marker in ("callback", "webhook")
    )


def _outbound_request_research_task(
    endpoint: Endpoint, parameter_names: list[str]
) -> dict[str, Any]:
    """Create a passive lead for inputs that may select a server-side destination."""

    fields = ", ".join(parameter_names)
    reason = (
        f"The request contains destination-like field(s) {fields}, but passive traffic does not "
        "establish whether the server resolves or contacts those values."
    )
    task = _research_task(endpoint, reason)
    task.update(
        {
            "key": f"research:outbound-request:{endpoint.id}:{'-'.join(parameter_names)}",
            "title": (
                f"Determine whether {fields} controls a server-side outbound request on "
                f"{endpoint.method} {endpoint.path}"
            ),
            "mutation_dimensions": ["VALUE"],
            "attacker_capability": [
                f"Can supply a researcher-controlled value in {fields} after explicit approval."
            ],
            "hypothesis": (
                f"Determine whether {fields} controls a server-side outbound request on "
                f"{endpoint.method} {endpoint.path}"
            ),
            "reasoning": reason,
            "evidence_to_collect": [
                "Documentation or researcher annotation describing each destination-like field.",
                "Whether the server performs DNS resolution or an outbound connection.",
                "The destination allowlist, redirect policy, and retry limits if outbound "
                "access exists.",
            ],
            "eligibility_evidence": [
                f"client-controlled destination-like field observed: {name}"
                for name in parameter_names
            ],
            "missing_evidence": [
                "server-side outbound request behavior is not established by passive evidence"
            ],
            "generation_rule": {"id": "OUTBOUND_REQUEST_RESEARCH", "version": "1"},
        }
    )
    return task


def _identity_change_research_task(endpoint: Endpoint) -> dict[str, Any]:
    """Create a passive lead for account-identity changes with old/new value fields."""

    reason = (
        "An authenticated identity-change operation is observed, but reauthentication, challenge "
        "binding, notification, and session invalidation semantics are not recorded."
    )
    task = _research_task(endpoint, reason)
    task.update(
        {
            "key": f"research:identity-change:{endpoint.id}",
            "title": (
                f"Determine reauthentication and verification binding for "
                f"{endpoint.method} {endpoint.path}"
            ),
            "mutation_dimensions": ["ACTOR", "STATE"],
            "hypothesis": (
                f"Determine reauthentication and verification binding for "
                f"{endpoint.method} {endpoint.path}"
            ),
            "reasoning": reason,
            "evidence_to_collect": [
                "Whether the current credential or a fresh challenge is required.",
                "Which old and new identity values the challenge is bound to.",
                "Notification, rollback, and existing-session invalidation behavior.",
            ],
            "eligibility_evidence": [
                "authenticated identity-change operation observed",
                "old/new identity value fields are client controlled",
            ],
            "missing_evidence": [
                "reauthentication and verification-binding requirements are not observed"
            ],
            "generation_rule": {"id": "IDENTITY_CHANGE_RESEARCH", "version": "1"},
        }
    )
    return task


def _business_logic_research_tasks(
    target: TargetDocument, endpoints: EndpointStore
) -> list[dict[str, Any]]:
    if "business_logic" not in target.focus:
        return []

    drafts: list[dict[str, Any]] = []
    for endpoint in endpoints.endpoints:
        if endpoint.disposition != "ACTIVE" or endpoint.method in {"HEAD", "OPTIONS"}:
            continue
        request_parameters = [
            item
            for item in endpoint.parameters
            if item.source == "request" and item.client_controlled
        ]
        outbound = sorted(
            {
                item.name
                for item in request_parameters
                if _looks_like_outbound_destination(item.name)
            }
        )
        if outbound:
            drafts.append(_outbound_request_research_task(endpoint, outbound))

        names = {re.sub(r"[^a-z0-9]", "", item.name.lower()) for item in request_parameters}
        identity_change = (
            "change" in endpoint.path.lower()
            and any(name.startswith("old") for name in names)
            and any(name.startswith("new") for name in names)
        )
        if endpoint.authentication.required and identity_change:
            drafts.append(_identity_change_research_task(endpoint))
    return drafts


def _function_action(rule: FunctionAuthorizationRule) -> str:
    return {
        "GET": "access",
        "POST": "creation",
        "PUT": "replacement",
        "PATCH": "update",
        "DELETE": "deletion",
    }[rule.method]


def _function_authorization_research_task(
    rule: FunctionAuthorizationRule,
    endpoint: Endpoint | None,
    runtime: list[Observation],
    disallowed_roles: list[str],
) -> dict[str, Any]:
    allowed = ", ".join(rule.allowed_roles)
    actor_label = ", ".join(disallowed_roles) if disallowed_roles else "a non-allowed role"
    action = _function_action(rule)
    endpoint_ids = [endpoint.id] if endpoint is not None else []
    observations = sorted(item.id for item in runtime)
    missing_evidence = [
        f"a successful runtime {rule.method} {rule.path} request from a non-allowed role is absent"
    ]
    if endpoint is None:
        missing_evidence.insert(0, "the configured function endpoint is not present in inventory")
    return {
        "key": f"function-authorization-research:{rule.method.lower()}:{rule.path}",
        "title": (
            f"Determine whether {actor_label} can invoke role-restricted {rule.resource} "
            f"{action} on {rule.method} {rule.path}"
        ),
        "kind": "RESEARCH_TASK",
        "disposition": "NEEDS_RESEARCH",
        "category": "research",
        "component": (
            f"{rule.resource} / {endpoint.id}"
            if endpoint is not None
            else f"{rule.resource} / {rule.method} {rule.path}"
        ),
        "source": {
            "endpoints": endpoint_ids,
            "invariants": [],
            "observations": observations,
        },
        "invariant": [],
        "observations": observations,
        "mutation_dimensions": [],
        "required_state": [],
        "attacker_capability": [],
        "evidence_status": KnowledgeStatus.INFERRED,
        "hypothesis": (
            f"Determine whether roles outside {allowed} can invoke {rule.method} {rule.path}."
        ),
        "reasoning": (
            f"Researcher policy marks {rule.resource} {action} as restricted to {allowed}. "
            f"{rule.rationale} Runtime evidence does not yet demonstrate a non-allowed role "
            "successfully invoking the function."
        ),
        "preconditions": [
            "Collect a redacted runtime baseline using only a researcher-controlled account.",
            "Do not create persistent state without an explicit cleanup plan and approval.",
        ],
        "expected_secure_behavior": (
            f"Roles outside {allowed} are rejected and no {rule.resource} state is created "
            "or changed."
        ),
        "possible_vulnerable_behavior": (
            f"A role outside {allowed} receives a success response and the {rule.resource} "
            f"{action} effect persists."
        ),
        "potential_impact": {
            "confidentiality": "low" if rule.method == "GET" else "none",
            "integrity": "high" if rule.method != "GET" else "none",
            "availability": "low" if rule.method != "GET" else "none",
            "financial": "unknown",
        },
        "evidence_to_collect": [
            f"Researcher-controlled account role evidence for {actor_label}.",
            f"Redacted {rule.method} {rule.path} request and response.",
            f"Authoritative {rule.resource} state before and after the request.",
            f"Policy evidence that allowed roles are limited to {allowed}.",
        ],
        "eligibility_evidence": [
            f"researcher-authored function policy allows only: {allowed}",
            rule.rationale,
        ],
        "missing_evidence": missing_evidence,
        "generation_rule": {"id": "FUNCTION_AUTHORIZATION_RESEARCH", "version": "1"},
        "priority_rationale": ["Research tasks are not vulnerability priorities."],
        "scores": _score(3, 2, 3, 2),
        "priority": "P3",
        "status": "NOT_TESTED",
        "safety_notes": [
            "This task does not authorize sending a state-changing request.",
            "Use only researcher-controlled roles and reversible local-lab state.",
        ],
    }


def _function_authorization_hypothesis(
    rule: FunctionAuthorizationRule,
    endpoint: Endpoint,
    successes: list[tuple[Observation, str]],
) -> dict[str, Any]:
    allowed = ", ".join(rule.allowed_roles)
    observed_roles = sorted({role for _, role in successes})
    roles = ", ".join(observed_roles)
    role_key = "-".join(observed_roles)
    action = _function_action(rule)
    observation_ids = sorted(item.id for item, _ in successes)
    scores = _score(4, 3, 4, 4)
    return {
        "key": f"function-authorization:{rule.method.lower()}:{rule.path}:{role_key}",
        "title": (
            f"Potential {roles} access to role-restricted {rule.resource} {action} on "
            f"{rule.method} {rule.path}"
        ),
        "category": "authorization",
        "component": f"{rule.resource} / {endpoint.id}",
        "source": {
            "endpoints": [endpoint.id],
            "invariants": [],
            "observations": observation_ids,
        },
        "invariant": [],
        "observations": observation_ids,
        "mutation_dimensions": ["ACTOR"],
        "required_state": [
            f"A harmless, reversible {rule.resource} input is available in the authorized lab."
        ],
        "attacker_capability": [
            f"Can authenticate as a researcher-controlled account with role {role}."
            for role in observed_roles
        ],
        "evidence_status": KnowledgeStatus.INFERRED,
        "hypothesis": (
            f"A researcher-controlled {roles} account may invoke {rule.method} {rule.path}, "
            f"although policy restricts {rule.resource} {action} to {allowed}."
        ),
        "reasoning": (
            f"Runtime traffic records HTTP success for role(s) {roles}. Researcher policy allows "
            f"only {allowed}. {rule.rationale} Persistence and complete function-level "
            "authorization behavior remain to be validated."
        ),
        "preconditions": [
            "The account and any created state are researcher controlled.",
            "The role policy is supported by documentation, source, or an authoritative "
            "annotation.",
            "A cleanup path exists before any further state-changing validation.",
        ],
        "expected_secure_behavior": (
            f"Roles outside {allowed} are rejected and no {rule.resource} state is created "
            "or changed."
        ),
        "possible_vulnerable_behavior": (
            f"The {roles} request succeeds and the {rule.resource} {action} effect persists."
        ),
        "potential_impact": {
            "confidentiality": "low" if rule.method == "GET" else "none",
            "integrity": "high" if rule.method != "GET" else "none",
            "availability": "low" if rule.method != "GET" else "none",
            "financial": "unknown",
        },
        "evidence_to_collect": [
            f"Role evidence for each observed non-allowed role: {roles}.",
            f"Redacted successful {rule.method} {rule.path} request and response.",
            f"Authoritative {rule.resource} state before and after the request.",
            f"Policy evidence that allowed roles are limited to {allowed}.",
        ],
        "eligibility_evidence": [
            f"researcher-authored function policy allows only: {allowed}",
            f"successful runtime request observed from non-allowed role(s): {roles}",
            rule.rationale,
        ],
        "missing_evidence": [
            f"confirm that the {rule.resource} {action} effect persisted",
            "confirm that no narrower delegation or role exception applies",
        ],
        "generation_rule": {"id": "FUNCTION_AUTHORIZATION", "version": "1"},
        "priority_rationale": [
            "A non-allowed role reached a policy-restricted state-changing function.",
            "Function-level authorization failure can affect shared application integrity.",
        ],
        "scores": scores,
        "priority": _priority(4, 3, 4, 4),
        "status": "NOT_TESTED",
        "safety_notes": [
            "Do not repeat the state-changing request without an approved cleanup plan.",
            "Use only researcher-controlled accounts and local-lab objects.",
        ],
    }


def _function_authorization_hypotheses(
    target: TargetDocument,
    observations: dict[str, Observation],
    endpoints: EndpointStore,
) -> list[dict[str, Any]]:
    endpoint_by_key = {
        (item.method, item.path): item
        for item in endpoints.endpoints
        if item.disposition == "ACTIVE"
    }
    roles_by_actor = {
        account.id: account.role.strip()
        for account in target.accounts
        if account.ownership == "researcher" and account.role.strip()
    }
    drafts: list[dict[str, Any]] = []
    for rule in sorted(
        target.analysis.function_authorization_rules,
        key=lambda item: (item.method, item.path),
    ):
        endpoint = endpoint_by_key.get((rule.method, rule.path))
        runtime = _runtime_observations(endpoint, observations) if endpoint is not None else []
        allowed = {item.casefold() for item in rule.allowed_roles}
        disallowed_roles = sorted(
            {role for role in roles_by_actor.values() if role.casefold() not in allowed}
        )
        successes = [
            (item, roles_by_actor[item.actor])
            for item in runtime
            if item.actor in roles_by_actor
            and roles_by_actor[item.actor].casefold() not in allowed
            and item.status_code is not None
            and 200 <= item.status_code < 300
        ]
        if successes and endpoint is not None:
            drafts.append(_function_authorization_hypothesis(rule, endpoint, successes))
            continue
        rejected = any(
            item.actor in roles_by_actor
            and roles_by_actor[item.actor].casefold() not in allowed
            and item.status_code in {401, 403, 404}
            for item in runtime
        )
        if not rejected:
            drafts.append(
                _function_authorization_research_task(
                    rule,
                    endpoint,
                    runtime,
                    disallowed_roles,
                )
            )
    return drafts


def _jwt_algorithms(rule: JwtAlgorithmRule) -> str:
    return ", ".join(f"alg={item}" for item in rule.rejected_algorithms)


def _jwt_baseline_matches(rule: JwtAlgorithmRule, observation: Observation) -> bool:
    if observation.status_code is None or not 200 <= observation.status_code < 300:
        return False
    if rule.token_location == "body":
        return rule.token_parameter in observation.request_fields
    if rule.token_location == "query":
        return rule.token_parameter in observation.query_parameters
    return True


def _jwt_algorithm_research_task(
    rule: JwtAlgorithmRule,
    endpoint: Endpoint | None,
    runtime: list[Observation],
) -> dict[str, Any]:
    algorithms = _jwt_algorithms(rule)
    endpoint_ids = [endpoint.id] if endpoint is not None else []
    observations = sorted(item.id for item in runtime)
    missing_evidence = [
        (
            f"a successful signed-JWT baseline using {rule.token_location} field "
            f"{rule.token_parameter} is absent"
        ),
        f"no controlled {algorithms} rejection or acceptance response is recorded",
    ]
    if endpoint is None:
        missing_evidence.insert(0, "the configured JWT verification endpoint is not in inventory")
    return {
        "key": f"jwt-algorithm-research:{rule.method.lower()}:{rule.path}",
        "title": (
            f"Determine whether {rule.method} {rule.path} rejects unsigned JWTs using {algorithms}"
        ),
        "kind": "RESEARCH_TASK",
        "disposition": "NEEDS_RESEARCH",
        "category": "research",
        "component": (
            f"JWT verification / {endpoint.id}"
            if endpoint is not None
            else f"JWT verification / {rule.method} {rule.path}"
        ),
        "source": {
            "endpoints": endpoint_ids,
            "invariants": [],
            "observations": observations,
        },
        "invariant": [],
        "observations": observations,
        "mutation_dimensions": [],
        "required_state": [],
        "attacker_capability": [],
        "evidence_status": KnowledgeStatus.ASSUMED,
        "hypothesis": (
            f"Determine whether {rule.method} {rule.path} accepts a JWT whose header selects "
            f"{algorithms} and whose signature is absent."
        ),
        "reasoning": (
            f"Researcher policy requires rejection of {algorithms} for the configured "
            f"{rule.token_location} field {rule.token_parameter}. {rule.rationale} A suitable "
            "successful baseline is not yet available for a bounded comparison."
        ),
        "preconditions": [
            "Collect a redacted successful signed-JWT baseline for a researcher-owned account.",
            "Do not retain the signed or unsigned token value in workspace artifacts.",
        ],
        "expected_secure_behavior": (
            f"The server rejects {algorithms} JWTs regardless of supplied claims and does not "
            "create or accept an authenticated context."
        ),
        "possible_vulnerable_behavior": (
            "The server accepts an unsigned JWT and trusts its attacker-controlled claims."
        ),
        "potential_impact": {
            "confidentiality": "high",
            "integrity": "high",
            "availability": "none",
            "financial": "unknown",
        },
        "evidence_to_collect": [
            "Redacted successful signed-JWT baseline request and response.",
            f"Redacted {algorithms} control response without retaining token material.",
            "A safe identity check showing which subject and roles the server accepted.",
        ],
        "eligibility_evidence": [
            f"researcher-authored JWT policy rejects: {algorithms}",
            rule.rationale,
        ],
        "missing_evidence": missing_evidence,
        "generation_rule": {"id": "JWT_ALGORITHM_VALIDATION_RESEARCH", "version": "1"},
        "priority_rationale": ["Research tasks are not vulnerability priorities."],
        "scores": _score(5, 2, 2, 2),
        "priority": "P3",
        "status": "NOT_TESTED",
        "safety_notes": [
            "This task does not authorize constructing or sending an unsigned token.",
            "Use only a researcher-controlled identity and stop after minimum proof.",
        ],
    }


def _jwt_algorithm_hypothesis(
    rule: JwtAlgorithmRule,
    endpoint: Endpoint,
    baselines: list[Observation],
) -> dict[str, Any]:
    algorithms = _jwt_algorithms(rule)
    observation_ids = sorted(item.id for item in baselines)
    scores = _score(5, 3, 3, 4)
    return {
        "key": f"jwt-algorithm:{rule.method.lower()}:{rule.path}",
        "title": f"Unsigned JWT may be accepted by the verifier on {rule.method} {rule.path}",
        "category": "authentication",
        "component": f"JWT verification / {endpoint.id}",
        "source": {
            "endpoints": [endpoint.id],
            "invariants": [],
            "observations": observation_ids,
        },
        "invariant": [],
        "observations": observation_ids,
        "mutation_dimensions": ["VALUE"],
        "required_state": [
            "A valid signed JWT issued to a researcher-controlled account is available outside "
            "the workspace."
        ],
        "attacker_capability": [
            f"Can replace the JWT header algorithm with {algorithms} and omit the signature."
        ],
        "evidence_status": KnowledgeStatus.INFERRED,
        "hypothesis": (
            f"{rule.method} {rule.path} may report an unsigned JWT using {algorithms} as valid. "
            "That verifier result does not establish an authenticated identity, session, role, "
            "or protected-resource access."
        ),
        "reasoning": (
            f"Successful runtime requests show that {endpoint.id} processes the configured "
            f"{rule.token_location} field {rule.token_parameter}. Researcher policy requires "
            f"rejection of {algorithms}. {rule.rationale} The unsigned-token mutation has not "
            "yet been tested."
        ),
        "preconditions": [
            "Use only a JWT issued to a researcher-controlled account as the baseline.",
            "Keep token material outside generated workspace artifacts.",
            "Obtain explicit human approval before sending the one modified request.",
        ],
        "expected_secure_behavior": (
            f"The server rejects {algorithms} JWTs regardless of supplied claims and does not "
            "create or accept an authenticated context."
        ),
        "possible_vulnerable_behavior": (
            "The verifier reports the unsigned JWT as valid; separate downstream evidence is "
            "required before claiming authentication or authorization impact."
        ),
        "potential_impact": {
            "confidentiality": "high",
            "integrity": "high",
            "availability": "none",
            "financial": "unknown",
        },
        "evidence_to_collect": [
            "Redacted successful signed-JWT baseline request and response.",
            f"Redacted {algorithms} control response without retaining token material.",
            "A safe identity endpoint response showing which subject and roles were accepted.",
            "Whether the verification endpoint issues or enables any authenticated session.",
        ],
        "eligibility_evidence": [
            f"successful runtime request contains configured JWT field: {rule.token_parameter}",
            f"researcher-authored JWT policy rejects: {algorithms}",
            rule.rationale,
        ],
        "missing_evidence": [
            f"the response to one controlled unsigned {algorithms} JWT is not recorded",
            "the resulting accepted subject, role, or session state is not confirmed",
        ],
        "generation_rule": {"id": "JWT_ALGORITHM_VALIDATION", "version": "1"},
        "priority_rationale": [
            "Verifier acceptance can indicate a signature-validation weakness.",
            "Authentication or authorization impact requires downstream identity or access "
            "evidence.",
            "A successful verifier baseline exists for a researcher-controlled account.",
        ],
        "scores": scores,
        "priority": _priority(5, 3, 3, 4),
        "status": "NOT_TESTED",
        "safety_notes": [
            "JWT fabrication is manual-only and is not supported by bounded execution.",
            "Use only researcher-controlled identity claims and send at most one modified request.",
            "Stop immediately if the token is accepted or any external identity becomes visible.",
        ],
    }


def _jwt_algorithm_hypotheses(
    target: TargetDocument,
    observations: dict[str, Observation],
    endpoints: EndpointStore,
) -> list[dict[str, Any]]:
    endpoint_by_key = {
        (item.method, item.path): item
        for item in endpoints.endpoints
        if item.disposition == "ACTIVE"
    }
    drafts: list[dict[str, Any]] = []
    for rule in sorted(
        target.analysis.jwt_algorithm_rules,
        key=lambda item: (item.method, item.path, item.token_location, item.token_parameter),
    ):
        endpoint = endpoint_by_key.get((rule.method, rule.path))
        runtime = _runtime_observations(endpoint, observations) if endpoint is not None else []
        baselines = [item for item in runtime if _jwt_baseline_matches(rule, item)]
        if endpoint is not None and baselines:
            drafts.append(_jwt_algorithm_hypothesis(rule, endpoint, baselines))
        else:
            drafts.append(_jwt_algorithm_research_task(rule, endpoint, runtime))
    return drafts


def _state_research_task(
    invariant: InvariantRecord, endpoint: Endpoint, resource: ResourceRecord
) -> dict[str, Any]:
    """Request one concrete forbidden edge instead of asserting a generic transition flaw."""

    action = endpoint.action.name
    from_state: str | None = None
    if action == "confirm" and "cancelled" in resource.states:
        from_state = "cancelled"
    elif action == "cancel" and "confirmed" in resource.states:
        from_state = "confirmed"
    elif action == "confirm" and "completed" in resource.states:
        from_state = "completed"

    if from_state is not None:
        title = (
            f"Determine whether the {action} operation rejects {from_state} {resource.name} objects"
        )
        evidence = [
            f"Researcher-confirmed relevance of {from_state} -> {action} for {resource.name}.",
            f"The expected state after a rejected {action} attempt from {from_state}.",
        ]
    else:
        title = f"Determine the permitted starting states for {action} on {resource.name}"
        evidence = [
            f"The allowed from_state and to_state for {action}.",
            "At least one specific forbidden transition supported by documentation or annotation.",
        ]
    reason = (
        f"The {action} operation and lifecycle state names are recorded, but no specific "
        "forbidden transition is supported strongly enough for an active hypothesis."
    )
    task = _research_task(endpoint, reason)
    task.update(
        {
            "key": f"research:state-transition:{endpoint.id}",
            "title": title,
            "component": f"{resource.name} / {endpoint.id}",
            "source": _source(invariant),
            "invariant": [invariant.id],
            "observations": _observations(invariant),
            "hypothesis": title,
            "reasoning": reason,
            "evidence_to_collect": evidence,
            "eligibility_evidence": [
                "mutation-like action observed",
                "resource lifecycle state names are recorded",
            ],
            "missing_evidence": ["a concrete forbidden from_state/action/to_state is not recorded"],
            "generation_rule": {"id": "STATE_TRANSITION_RESEARCH", "version": "1"},
        }
    )
    return task


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
    observations: dict[str, Observation],
) -> list[dict[str, Any]]:
    endpoint_by_id = {item.id: item for item in endpoints.endpoints}
    invariants_by_endpoint: dict[str, list[InvariantRecord]] = defaultdict(list)
    for invariant in invariants.invariants:
        if invariant.disposition != "ACTIVE":
            continue
        for endpoint_id in invariant.endpoints:
            invariants_by_endpoint[endpoint_id].append(invariant)

    drafts: list[dict[str, Any]] = []
    for resource in resources.resources:
        if resource.disposition != "ACTIVE":
            continue
        for operation in resource.operations:
            endpoint = endpoint_by_id.get(operation.endpoint)
            boundary_parameters = (
                [
                    item
                    for item in endpoint.parameters
                    if item.source == "request"
                    and item.client_controlled
                    and item.location in MUTABLE_PARAMETER_LOCATIONS
                    and item.semantic_type == "monetary_value"
                ]
                if endpoint is not None
                else []
            )
            boundary_fields = sorted(
                {
                    (
                        item.json_path.removeprefix("$.").replace("[*]", "[]")
                        if item.json_path
                        else item.name
                    )
                    for item in boundary_parameters
                }
            )
            mutation_candidate = endpoint is not None and endpoint.state_change
            runtime_ids = (
                {item.id for item in _runtime_observations(endpoint, observations)}
                if endpoint is not None
                else set()
            )
            runtime_boundary_evidence = {
                source
                for parameter in boundary_parameters
                for source in parameter.evidence
                if source in runtime_ids
            }
            if (
                endpoint is None
                or endpoint.disposition != "ACTIVE"
                or not mutation_candidate
                or not boundary_fields
                or not runtime_boundary_evidence
                or endpoint.security_relevance
                < target.analysis.hypothesis_gates.financial_minimum_score
            ):
                continue
            related = invariants_by_endpoint.get(endpoint.id, [])
            invariant_ids = sorted(item.id for item in related)
            observation_ids = sorted(runtime_boundary_evidence)
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
                        "observations": observation_ids,
                    },
                    "invariant": invariant_ids,
                    "observations": observation_ids,
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
                        "Financially relevant fields are directly observed in the request, but "
                        "server-side range, precision, currency, and consistency rules are not "
                        "confirmed."
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
    endpoints: EndpointStore,
    invariants: InvariantStore,
    resources: ResourceStore,
    observations: dict[str, Observation],
) -> list[dict[str, Any]]:
    resource_names = {item.name for item in resources.resources if item.disposition == "ACTIVE"}
    grouped: dict[tuple[str, str, str], list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints.endpoints:
        if endpoint.disposition != "ACTIVE" or not _runtime_observations(endpoint, observations):
            continue
        signature = _version_signature(endpoint.path)
        if endpoint.resource.type in resource_names and signature is not None:
            grouped[(endpoint.resource.type, endpoint.method, signature)].append(endpoint)
    invariants_by_endpoint: dict[str, list[InvariantRecord]] = defaultdict(list)
    for invariant in invariants.invariants:
        if invariant.disposition != "ACTIVE":
            continue
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
        observation_ids = sorted(
            {
                observation.id
                for item in items
                for observation in _runtime_observations(item, observations)
            }
        )
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
                    "observations": observation_ids,
                },
                "invariant": related,
                "observations": observation_ids,
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
    endpoints: EndpointStore,
    invariants: InvariantStore,
    resources: ResourceStore,
    observations: dict[str, Observation],
) -> list[dict[str, Any]]:
    resource_names = {item.name for item in resources.resources if item.disposition == "ACTIVE"}
    invariants_by_endpoint: dict[str, list[InvariantRecord]] = defaultdict(list)
    for invariant in invariants.invariants:
        if invariant.disposition != "ACTIVE":
            continue
        for endpoint_id in invariant.endpoints:
            invariants_by_endpoint[endpoint_id].append(invariant)

    drafts: list[dict[str, Any]] = []
    for endpoint in endpoints.endpoints:
        if endpoint.disposition != "ACTIVE":
            continue
        runtime = _runtime_observations(endpoint, observations)
        channels = sorted({item.channel for item in runtime if item.channel != "UNKNOWN"})
        if endpoint.resource.type not in resource_names or len(channels) < 2:
            continue
        related = sorted(item.id for item in invariants_by_endpoint[endpoint.id])
        observation_ids = sorted(item.id for item in runtime)
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
                    "observations": observation_ids,
                },
                "invariant": related,
                "observations": observation_ids,
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
    observations: ObservationStore,
    endpoints: EndpointStore,
    resources: ResourceStore,
    invariants: InvariantStore,
) -> list[dict[str, Any]]:
    endpoint_by_id = {item.id: item for item in endpoints.endpoints}
    observation_by_id = {item.id: item for item in observations.observations}
    resource_by_name = _resource_by_name(resources)
    researcher_accounts = sum(1 for account in target.accounts if account.ownership == "researcher")
    drafts: list[dict[str, Any]] = []
    active_endpoint_ids: set[str] = set()
    authentication_research: dict[str, list[tuple[InvariantRecord, Endpoint, ResourceRecord]]] = (
        defaultdict(list)
    )
    for invariant in invariants.invariants:
        if invariant.disposition != "ACTIVE":
            continue
        if not invariant.endpoints or not invariant.resources:
            continue
        endpoint = endpoint_by_id.get(invariant.endpoints[0])
        resource = resource_by_name.get(invariant.resources[0])
        if endpoint is None or resource is None:
            continue
        if endpoint.disposition != "ACTIVE":
            continue
        runtime = _runtime_observations(endpoint, observation_by_id)
        authenticated_runtime = any(item.authentication.present for item in runtime)
        anonymous_runtime_success = any(
            not item.authentication.present
            and item.status_code is not None
            and 200 <= item.status_code < 300
            and bool(item.response_fields)
            for item in runtime
        )
        if invariant.category == "authentication":
            if (
                endpoint.security_relevance >= 4
                and authenticated_runtime
                and anonymous_runtime_success
            ):
                draft = _authentication_hypothesis(
                    invariant, endpoint, resource, researcher_accounts
                )
                draft.update(
                    {
                        "eligibility_evidence": [
                            "authenticated baseline observed",
                            "anonymous 2xx response with structured protected data observed",
                            *endpoint.relevance_reasons,
                        ],
                        "missing_evidence": [
                            "confirm that the anonymous response exposes protected data or state"
                        ],
                        "generation_rule": {"id": "AUTH_ENFORCEMENT", "version": "3"},
                        "priority_rationale": endpoint.relevance_reasons,
                    }
                )
                drafts.append(draft)
                active_endpoint_ids.add(endpoint.id)
            elif (
                endpoint.security_relevance >= 4
                and authenticated_runtime
                and "code/consume" not in endpoint.path.lower()
            ):
                authentication_research[resource.name].append((invariant, endpoint, resource))
        elif invariant.category == "authorization":
            parameter = invariant.key.rsplit(":", 1)[-1]
            parameter_record = next(
                (
                    item
                    for item in endpoint.parameters
                    if item.name == parameter and item.semantic_type == "object_identifier"
                ),
                None,
            )
            binding = next(
                (
                    item
                    for item in endpoint.object_access
                    if item.identifier == parameter and item.actor_object_binding_observed
                ),
                None,
            )
            gate = target.analysis.hypothesis_gates.bola_minimum_score
            if (
                parameter_record is not None
                and parameter_record.source == "request"
                and parameter_record.client_controlled
                and parameter_record.location in MUTABLE_PARAMETER_LOCATIONS
                and (authenticated_runtime or binding is not None)
                and researcher_accounts >= 2
                and endpoint.security_relevance >= gate
                and endpoint.classification.primary
                in {
                    EndpointPrimaryClassification.FIRST_PARTY_API,
                    EndpointPrimaryClassification.AUTHENTICATION,
                    EndpointPrimaryClassification.FINANCIAL,
                }
            ):
                draft = _object_authorization_hypothesis(
                    invariant,
                    endpoint,
                    resource,
                    parameter,
                    researcher_accounts,
                    binding,
                )
                eligibility_evidence = [
                    "authenticated endpoint observed",
                    f"client-controlled {parameter} found in {parameter_record.location}",
                    "two researcher-controlled actors are configured",
                    *endpoint.relevance_reasons,
                ]
                missing_evidence = [
                    "ownership relationship is not confirmed",
                    "a second controlled actor baseline is not yet captured",
                ]
                if binding is not None:
                    owner_field = (binding.owner_field_path or "owner association").rsplit(".", 1)[
                        -1
                    ]
                    if binding.source == "PATH_PARENT_SCOPE":
                        eligibility_evidence = [
                            "authenticated first-party JSON API",
                            f"client-controlled {parameter} path parameter",
                            (
                                f"{binding.distinct_actors} researcher-controlled actors have "
                                "successful authenticated baselines"
                            ),
                            (
                                f"{binding.distinct_scope_values} distinct controlled parent "
                                "scope values were observed"
                            ),
                            (
                                f"{parameter} is explicitly allowlisted as an ownership scope "
                                "parameter"
                            ),
                            "ownership provenance is PATH_PARENT_SCOPE",
                            *endpoint.relevance_reasons,
                        ]
                    else:
                        eligibility_evidence = [
                            "first-party JSON API",
                            f"client-controlled {parameter} path parameter",
                            f"{binding.distinct_actors} researcher-controlled actors observed",
                            "distinct controlled object IDs are linked to actor baselines",
                            "successful resource-specific JSON responses",
                            "response object IDs match requested object IDs",
                            (
                                f"{binding.distinct_owner_values} distinct {owner_field} values "
                                "observed across actor baselines"
                            ),
                            "ownership provenance is RESPONSE_BODY",
                            *endpoint.relevance_reasons,
                        ]
                    if not authenticated_runtime:
                        eligibility_evidence.append("no request authentication credential observed")
                    eligibility_evidence = [*dict.fromkeys(eligibility_evidence)]
                    missing_evidence = [
                        "Account A requesting Account B's object has not been tested",
                        "Account B requesting Account A's object has not been tested",
                        "server-side authorization behavior is not yet confirmed",
                    ]
                draft.update(
                    {
                        "eligibility_evidence": eligibility_evidence,
                        "missing_evidence": missing_evidence,
                        "generation_rule": {
                            "id": "AUTH_OBJECT_ACCESS",
                            "version": (
                                "4"
                                if binding is not None and binding.source == "PATH_PARENT_SCOPE"
                                else "3"
                            ),
                        },
                        "priority_rationale": endpoint.relevance_reasons,
                    }
                )
                drafts.append(draft)
                active_endpoint_ids.add(endpoint.id)
        elif invariant.category == "state_integrity":
            gate = target.analysis.hypothesis_gates.state_transition_minimum_score
            if (
                runtime
                and resource.states
                and endpoint.state_change
                and endpoint.security_relevance >= gate
            ):
                drafts.append(_state_research_task(invariant, endpoint, resource))
                active_endpoint_ids.add(endpoint.id)
        elif (
            invariant.category == "single_execution"
            and runtime
            and endpoint.action.type == "financial_mutation"
        ):
            draft = _replay_hypothesis(invariant, endpoint, resource, target.testing.production)
            draft.update(
                {
                    "eligibility_evidence": ["financial mutation-like action observed"],
                    "missing_evidence": ["idempotency behavior is not observed"],
                    "generation_rule": {"id": "SINGLE_EXECUTION", "version": "2"},
                    "priority_rationale": endpoint.relevance_reasons,
                }
            )
            drafts.append(draft)
            active_endpoint_ids.add(endpoint.id)
    for resource_name, entries in sorted(authentication_research.items()):
        grouped_endpoints = sorted(
            {endpoint.id: endpoint for _, endpoint, _ in entries}.values(),
            key=lambda item: item.id,
        )
        grouped_invariants = sorted(
            {invariant.id: invariant for invariant, _, _ in entries}.values(),
            key=lambda item: item.id,
        )
        drafts.append(
            _authentication_research_task(
                resource_name,
                grouped_endpoints,
                grouped_invariants,
            )
        )
        active_endpoint_ids.update(item.id for item in grouped_endpoints)
    drafts.extend(_value_hypotheses(target, endpoints, invariants, resources, observation_by_id))
    drafts.extend(_version_hypotheses(endpoints, invariants, resources, observation_by_id))
    drafts.extend(_channel_hypotheses(endpoints, invariants, resources, observation_by_id))
    drafts.extend(_business_logic_research_tasks(target, endpoints))
    drafts.extend(_function_authorization_hypotheses(target, observation_by_id, endpoints))
    drafts.extend(_jwt_algorithm_hypotheses(target, observation_by_id, endpoints))
    active_endpoint_ids.update(
        endpoint_id
        for draft in drafts
        for endpoint_id in draft.get("source", {}).get("endpoints", [])
    )
    for endpoint in endpoints.endpoints:
        always_research = any(
            marker in endpoint.path.lower()
            for marker in (
                "user_verification",
                "/user/verification",
                "code/consume",
                "change-wallet",
            )
        ) or (
            endpoint.action.type == "unknown"
            and EndpointPrimaryClassification.FINANCIAL in endpoint.classification.tags
        )
        interesting = bool(
            set(endpoint.classification.tags)
            & {
                EndpointPrimaryClassification.AUTHENTICATION,
                EndpointPrimaryClassification.FINANCIAL,
            }
        ) or any(
            marker in endpoint.path.lower()
            for marker in ("my-posts", "user_verification", "code/consume")
        )
        if (
            endpoint.disposition == "ACTIVE"
            and endpoint.method not in {"HEAD", "OPTIONS"}
            and interesting
            and (always_research or endpoint.id not in active_endpoint_ids)
        ):
            drafts.append(
                _research_task(
                    endpoint,
                    "The endpoint is security-relevant but lacks sufficient ownership, action, "
                    "or lifecycle evidence for a vulnerability hypothesis.",
                )
            )
    for draft in drafts:
        draft.setdefault("kind", "SECURITY_HYPOTHESIS")
        draft.setdefault("disposition", "ACTIVE")
        draft.setdefault(
            "readiness",
            "RESEARCH_ONLY" if draft["kind"] == "RESEARCH_TASK" else "REVIEW_REQUIRED",
        )
        endpoint_ids = draft.get("source", {}).get("endpoints", [])
        related = [endpoint_by_id[item] for item in endpoint_ids if item in endpoint_by_id]
        reasons = sorted({reason for item in related for reason in item.relevance_reasons})
        draft.setdefault("eligibility_evidence", reasons)
        draft.setdefault("missing_evidence", ["Researcher validation evidence is not collected."])
        draft.setdefault(
            "generation_rule",
            {"id": str(draft.get("category", "UNKNOWN")).upper(), "version": "2"},
        )
        draft.setdefault("priority_rationale", reasons)
    return sorted(
        drafts,
        key=lambda item: (
            0 if item.get("generation_rule", {}).get("id") == "AUTH_ENFORCEMENT_RESEARCH" else 1
        ),
    )


def generate_hypotheses(workspace: WorkspacePaths) -> HypothesisResult:
    """Generate a specific backlog without changing lifecycle status or notes."""

    target, observations, endpoints, resources, invariants = _load_inputs(workspace)
    fingerprint = hypothesis_source_fingerprint(
        target,
        observations,
        endpoints,
        resources,
        invariants,
    )
    drafts = _drafts(target, observations, endpoints, resources, invariants)
    merge = merge_generated_records(
        workspace.hypotheses,
        "hypotheses",
        "HYP",
        "phase3-hypothesis-generator",
        fingerprint,
        drafts,
        preserved_fields=("status", "notes"),
    )
    draft_keys = {str(item["key"]) for item in drafts}
    records = merge.document.get("hypotheses", [])
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict) or record.get("key") in draft_keys:
                continue
            generation = record.get("generation")
            if not isinstance(generation, dict):
                continue
            if generation.get("generator") != "phase3-hypothesis-generator":
                continue
            payload = {
                key: value
                for key, value in record.items()
                if key not in {"generation", "status", "notes"}
            }
            if generation.get("generated_checksum") != stable_fingerprint(payload):
                continue
            record["kind"] = "SECURITY_HYPOTHESIS"
            record["disposition"] = "SUPPRESSED_INSUFFICIENT_EVIDENCE"
            record["priority"] = "P3"
            record["missing_evidence"] = [
                "The candidate no longer passes the current classification and evidence gates."
            ]
            record["generation_rule"] = {
                "id": "LEGACY_CANDIDATE_REEVALUATION",
                "version": "2",
            }
            record["priority_rationale"] = [
                "Suppressed candidates do not receive an active security priority."
            ]
            normalized = HypothesisRecord.model_validate(record).model_dump(
                mode="json", exclude_none=True
            )
            normalized_generation = normalized["generation"]
            normalized_payload = {
                key: value
                for key, value in normalized.items()
                if key not in {"generation", "status", "notes"}
            }
            normalized_generation["generated_checksum"] = stable_fingerprint(normalized_payload)
            record.clear()
            record.update(normalized)
    try:
        store = HypothesisStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(
            f"Cannot validate hypothesis backlog {workspace.hypotheses}: {error}"
        ) from error
    store = finalize_hypothesis_store(target, observations, endpoints, resources, store)
    write_yaml(workspace.hypotheses, store.model_dump(mode="json", exclude_none=True))
    record_stage_provenance(
        workspace,
        key="hypothesize",
        stage="hypothesize",
        producer="phase3-hypothesis-generator",
        input_fingerprint=fingerprint,
    )
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
            if hypothesis.category == "business_logic":
                epistemic_statuses: dict[HypothesisStatus, BusinessEpistemicStatus] = {
                    "NOT_TESTED": "TEST_CANDIDATE",
                    "TEST_PLANNED": "TEST_PLANNED",
                    "REFUTED": "REJECTED_BY_BACKEND",
                    "NEEDS_EVIDENCE": "NEEDS_EVIDENCE",
                    "CONFIRMED": "CONFIRMED",
                }
                hypothesis.epistemic_status = epistemic_statuses[status]
            write_yaml(workspace.hypotheses, store.model_dump(mode="json", exclude_none=True))
            if (
                hypothesis.category == "business_logic"
                and workspace.business_logic_hypotheses.is_file()
            ):
                logic_store = load_yaml(workspace.business_logic_hypotheses)
                if isinstance(logic_store, dict) and isinstance(
                    logic_store.get("hypotheses"), list
                ):
                    for item in logic_store["hypotheses"]:
                        if (
                            isinstance(item, dict)
                            and str(item.get("id", "")).upper() == hypothesis.id.upper()
                        ):
                            item["epistemic_status"] = hypothesis.epistemic_status
                            break
                    write_yaml(workspace.business_logic_hypotheses, logic_store)
            return hypothesis
    raise FinsecError(f"Hypothesis not found: {hypothesis_id}")
