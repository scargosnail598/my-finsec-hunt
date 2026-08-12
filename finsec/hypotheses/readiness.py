"""One authoritative hypothesis-readiness evaluator used by generation and planning."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from finsec.config.models import TargetDocument
from finsec.config.scope import hosts_are_covered
from finsec.hypotheses.contracts import (
    BlockerStage,
    CapabilityAssessment,
    CapabilityKind,
    ClaimStrengthAssessment,
    DecisionEvidence,
    DomainIntentAssessment,
    DomainOperation,
    HypothesisReadinessAssessment,
    HypothesisReadinessValue,
    MutationTargetAssessment,
    ReadinessIssue,
    VisibilityIntent,
)
from finsec.modeling.domain import ResourceStore
from finsec.modeling.models import Endpoint, ObservationStore
from finsec.modeling.semantics import (
    IdentifierSemanticClass,
    OwnershipState,
    execution_ownership_supported,
)

RUNTIME_SOURCES = {"HAR", "BURP_XML", "CAIDO_JSON"}


class HypothesisSourceLike(Protocol):
    @property
    def endpoints(self) -> Sequence[str]: ...

    @property
    def observations(self) -> Sequence[str]: ...


class HypothesisLike(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def kind(self) -> str: ...

    @property
    def category(self) -> str: ...

    @property
    def source(self) -> HypothesisSourceLike: ...

    @property
    def observations(self) -> Sequence[str]: ...

    @property
    def mutation_dimensions(self) -> Sequence[str]: ...

    @property
    def evidence_to_collect(self) -> Sequence[str]: ...

    @property
    def generation_rule(self) -> Mapping[str, str]: ...

    @property
    def logic_details(self) -> Mapping[str, object] | None: ...


@dataclass(frozen=True)
class ReadinessContext:
    """Typed facts supplied to the canonical evaluator."""

    hypothesis_id: str
    kind: str
    capabilities: tuple[CapabilityAssessment, ...]
    warnings: tuple[ReadinessIssue, ...] = ()


def _evidence(reference: str, source: str, detail: str) -> DecisionEvidence:
    return DecisionEvidence(reference=reference, source=source, detail=detail)  # type: ignore[arg-type]


def _capability(
    capability: CapabilityKind,
    *,
    satisfied: bool,
    stage: BlockerStage,
    summary: str,
    required: bool = True,
    evidence: list[DecisionEvidence] | None = None,
    missing: list[str] | None = None,
    next_action: str | None = None,
) -> CapabilityAssessment:
    return CapabilityAssessment(
        capability=capability,
        required=required,
        satisfied=satisfied,
        stage=stage,
        summary=summary,
        evidence=sorted(evidence or [], key=lambda item: (item.reference, item.detail)),
        missing=sorted(set(missing or [])),
        next_action=next_action,
    )


def evaluate_readiness(context: ReadinessContext) -> HypothesisReadinessAssessment:
    """Evaluate identical capability facts identically for producers and the planner."""

    capabilities = sorted(context.capabilities, key=lambda item: item.capability.value)
    blockers = [
        ReadinessIssue(
            code=f"MISSING_{item.capability.value}",
            stage=item.stage,
            capability=item.capability,
            summary="; ".join(item.missing) if item.missing else item.summary,
            evidence=item.evidence,
            next_action=item.next_action,
        )
        for item in capabilities
        if item.required and not item.satisfied
    ]
    concrete = next(
        (item for item in capabilities if item.capability == CapabilityKind.CONCRETE_TEST),
        None,
    )
    if context.kind != "SECURITY_HYPOTHESIS" or concrete is None or not concrete.satisfied:
        readiness: HypothesisReadinessValue = "RESEARCH_ONLY"
        reasons = [
            "The record is a discovery or coverage question without one fully concrete bounded "
            "test."
        ]
    elif blockers:
        readiness = "REVIEW_REQUIRED"
        reasons = [
            "The security question is specific, but evidence or plan-construction prerequisites "
            "remain unresolved."
        ]
    else:
        readiness = "TEST_READY"
        reasons = [
            "Current evidence supports a concrete bounded plan; human approval and execution "
            "policy remain separate gates."
        ]
    missing = sorted(
        {
            missing
            for capability in capabilities
            if capability.required and not capability.satisfied
            for missing in capability.missing
        }
    )
    references = sorted(
        {evidence.reference for capability in capabilities for evidence in capability.evidence}
    )
    return HypothesisReadinessAssessment(
        readiness=readiness,
        actionable_plan=readiness == "TEST_READY",
        reasons=reasons,
        missing_prerequisites=missing,
        blockers=sorted(blockers, key=lambda item: (item.stage.value, item.code, item.summary)),
        warnings=sorted(
            context.warnings, key=lambda item: (item.stage.value, item.code, item.summary)
        ),
        capabilities=capabilities,
        evidence_references=references,
    )


def readiness_blocking_issues(
    assessment: HypothesisReadinessAssessment,
) -> list[ReadinessIssue]:
    """Return only evidence and constructability blockers, never approval/policy gates."""

    return [
        item
        for item in assessment.blockers
        if item.stage in {BlockerStage.HYPOTHESIS_EVIDENCE, BlockerStage.PLAN_CONSTRUCTABILITY}
    ]


def _logic_capability(
    record: HypothesisLike, capability: CapabilityKind
) -> CapabilityAssessment | None:
    details = record.logic_details
    if not isinstance(details, Mapping):
        return None
    raw = details.get("readiness_assessment")
    if not isinstance(raw, Mapping):
        return None
    try:
        assessment = HypothesisReadinessAssessment.model_validate(raw)
    except ValueError:
        return None
    return next((item for item in assessment.capabilities if item.capability == capability), None)


def _source_endpoints(record: HypothesisLike, endpoints: list[Endpoint]) -> list[Endpoint]:
    selected = set(record.source.endpoints)
    return sorted((item for item in endpoints if item.id in selected), key=lambda item: item.id)


def _runtime_observation_ids(record: HypothesisLike, observations: ObservationStore) -> set[str]:
    selected = set(record.source.observations) | set(record.observations)
    return {
        item.id
        for item in observations.observations
        if item.id in selected and item.source in RUNTIME_SOURCES
    }


def _required_actors(record: HypothesisLike) -> int:
    if record.logic_details is not None:
        value = record.logic_details.get("controlled_actors_required")
        if isinstance(value, int):
            return value
    rule = record.generation_rule.get("id", "")
    if record.category == "authorization" and rule != "FUNCTION_AUTHORIZATION":
        return 2
    return 1


def _mutation_target(record: HypothesisLike) -> MutationTargetAssessment:
    value = getattr(record, "mutation_target", None)
    return value if isinstance(value, MutationTargetAssessment) else MutationTargetAssessment()


def _state_changing(intent: DomainIntentAssessment) -> bool:
    return intent.operation in {
        DomainOperation.CREATE,
        DomainOperation.CREATE_CHILD,
        DomainOperation.UPDATE,
        DomainOperation.DELETE,
        DomainOperation.TRANSITION,
        DomainOperation.ACTION,
    }


def _oracle_endpoints(
    source: list[Endpoint], all_endpoints: list[Endpoint], intent: DomainIntentAssessment
) -> list[Endpoint]:
    resources = {intent.subject_resource.lower()}
    if intent.parent_resource is not None:
        resources.add(intent.parent_resource.lower())
    return sorted(
        (
            endpoint
            for endpoint in all_endpoints
            if endpoint.method in {"GET", "HEAD"}
            and not endpoint.state_change
            and endpoint.resource.type.lower() in resources
        ),
        key=lambda item: item.id,
    ) or [
        endpoint
        for endpoint in source
        if endpoint.method in {"GET", "HEAD"} and not endpoint.state_change
    ]


def _request_budget(record: HypothesisLike, intent: DomainIntentAssessment) -> int:
    if record.logic_details is not None:
        value = record.logic_details.get("estimated_request_budget")
        if isinstance(value, int):
            return value
    rule = record.generation_rule.get("id", "")
    if rule.startswith("JWT_ALGORITHM_VALIDATION"):
        return 2
    if _state_changing(intent):
        return 4
    return 2


def build_record_readiness_context(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: list[Endpoint],
    resources: ResourceStore,
    record: HypothesisLike,
    intent: DomainIntentAssessment,
    claim_strength: ClaimStrengthAssessment,
) -> ReadinessContext:
    """Derive shared prerequisite facts from one persisted HYP or BLH record."""

    del resources  # The endpoint/resource relationship is already represented in domain intent.
    source = _source_endpoints(record, endpoints)
    runtime_ids = _runtime_observation_ids(record, observations)
    source_ids = {observation for endpoint in source for observation in endpoint.sources}
    runtime_source_ids = runtime_ids & source_ids
    rule = record.generation_rule.get("id", "")
    mutation_target = _mutation_target(record)
    actor_count = sum(account.ownership == "researcher" for account in target.accounts)
    actors_required = _required_actors(record)
    actor_evidence = [
        _evidence(account.id, "TARGET_POLICY", "Researcher-controlled actor is configured.")
        for account in target.accounts
        if account.ownership == "researcher"
    ]

    concrete = record.kind == "SECURITY_HYPOTHESIS" and bool(
        record.mutation_dimensions or rule.startswith("JWT_ALGORITHM_VALIDATION")
    )
    concrete_capability = _capability(
        CapabilityKind.CONCRETE_TEST,
        satisfied=concrete,
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary="One concrete mutation and security oracle must be defined.",
        evidence=[
            _evidence(record.id, "GENERATOR", "The generator emitted a concrete test mutation.")
        ]
        if concrete
        else [],
        missing=["Define one bounded mutation with a meaningful secure and vulnerable oracle."],
        next_action="Refine the discovery question into one concrete bounded test.",
    )
    semantic_target_required = record.category == "authorization" and rule.startswith(
        "AUTH_OBJECT_ACCESS"
    )
    semantic_target_satisfied = (
        mutation_target.parameter is not None
        and mutation_target.semantics.semantic_class == IdentifierSemanticClass.OWNED_OBJECT
        and mutation_target.semantics.ownership_state
        not in {OwnershipState.SHARED, OwnershipState.CONTRADICTED}
    )
    semantic_target_capability = _capability(
        CapabilityKind.SEMANTIC_TARGET,
        required=semantic_target_required,
        satisfied=semantic_target_satisfied,
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary="The mutation target must represent an ownership-relevant object.",
        evidence=[
            _evidence(
                mutation_target.parameter or record.id,
                "ENDPOINT",
                (
                    f"Identifier class is "
                    f"{mutation_target.semantics.semantic_class.value}; resource role is "
                    f"{mutation_target.semantics.resource_role.value}."
                ),
            )
        ]
        if mutation_target.parameter is not None
        else [],
        missing=[
            (
                f"Identifier is classified as "
                f"{mutation_target.semantics.semantic_class.value}, therefore an owned-object "
                "cross-account mutation is not constructable."
                if mutation_target.parameter is not None
                else "Identify the exact ownership-relevant mutation parameter."
            )
        ],
        next_action=(
            "Collect object lifecycle or explicit owner evidence; do not reinterpret shared "
            "scope as ownership."
        ),
    )
    actor_capability = _capability(
        CapabilityKind.ACTOR,
        satisfied=actor_count >= actors_required,
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary=f"At least {actors_required} researcher-controlled actor(s) are required.",
        evidence=actor_evidence,
        missing=[
            f"Configure at least {actors_required} researcher-controlled account(s) or actor(s)."
        ],
        next_action="Configure the required controlled actors without adding real-user accounts.",
    )

    binding_family = rule.startswith("BUSINESS_LOGIC_ACTOR_SWITCH") or rule.startswith(
        "BUSINESS_LOGIC_RESOURCE_SWITCH"
    )
    ownership_required = record.category == "authorization" or binding_family
    ownership_satisfied = (
        execution_ownership_supported(mutation_target.semantics)
        and intent.visibility
        in {
            VisibilityIntent.OWNER_SCOPED,
            VisibilityIntent.ACTOR_BOUND,
        }
        and intent.binding.value != "UNKNOWN"
    )
    if binding_family:
        ownership_satisfied = (
            intent.visibility
            in {
                VisibilityIntent.OWNER_SCOPED,
                VisibilityIntent.ROLE_SCOPED,
                VisibilityIntent.ACTOR_BOUND,
            }
            and intent.binding.value != "UNKNOWN"
        )
    if rule == "FUNCTION_AUTHORIZATION":
        ownership_satisfied = intent.visibility == VisibilityIntent.ROLE_SCOPED
    ownership_capability = _capability(
        CapabilityKind.OWNERSHIP,
        required=ownership_required,
        satisfied=ownership_satisfied,
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary="The claimed owner, tenant, role, session, or actor binding must be evidenced.",
        evidence=intent.positive_evidence,
        missing=[
            "Collect explicit owner, tenant, role, session, producer-consumer, or initiating-actor "
            "binding evidence for the protected subject."
        ],
        next_action=(
            "Capture two controlled subject/boundary baselines or add an explicit reviewed policy "
            "annotation."
        ),
    )

    matching_access = [
        access
        for endpoint in source
        for access in endpoint.object_access
        if mutation_target.parameter is None
        or access.identifier.lower() == mutation_target.parameter.lower()
    ]
    distinct_baselines = any(
        access.actor_object_binding_observed
        and access.source in {"CONTROLLED_LIFECYCLE", "RESPONSE_BODY"}
        and access.distinct_actors >= 2
        and access.distinct_objects >= 2
        and len(access.baselines) >= 2
        for access in matching_access
    )
    baseline_actors = {
        baseline.actor
        for access in matching_access
        if access.source in {"CONTROLLED_LIFECYCLE", "RESPONSE_BODY"}
        for baseline in access.baselines
    }
    controlled_actor_ids = [
        account.id for account in target.accounts if account.ownership == "researcher"
    ]
    missing_baseline_actors = sorted(set(controlled_actor_ids) - baseline_actors)
    controlled_baseline_evidence = [
        _evidence(
            baseline.baseline_id or observation_id,
            "WORKFLOW" if access.source == "CONTROLLED_LIFECYCLE" else "ENDPOINT",
            (
                f"Controlled {baseline.operation or 'resource'} baseline for {baseline.actor} "
                "is backed by explicit lifecycle or owner-binding evidence."
            ),
        )
        for access in matching_access
        if access.actor_object_binding_observed
        and access.source in {"CONTROLLED_LIFECYCLE", "RESPONSE_BODY"}
        for baseline in access.baselines
        for observation_id in baseline.observations[:1]
    ]
    all_runtime_ids = {
        item.id for item in observations.observations if item.source in RUNTIME_SOURCES
    }
    safe_oracles = [
        endpoint
        for endpoint in _oracle_endpoints(source, endpoints, intent)
        if set(endpoint.sources).intersection(all_runtime_ids)
    ]
    state_changing = _state_changing(intent)
    capture_strategy = " ".join(record.evidence_to_collect).lower()
    before_strategy = any(
        marker in capture_strategy
        for marker in ("before", "pre-state", "pre state", "initial state", "baseline state")
    )
    after_strategy = any(
        marker in capture_strategy
        for marker in ("after", "post-state", "post state", "state delta", "resulting state")
    )
    logic_baseline = _logic_capability(record, CapabilityKind.BASELINE)
    baseline_required = (
        record.category in {"authentication", "authorization"} or state_changing or binding_family
    )
    if rule == "FUNCTION_AUTHORIZATION":
        baseline_satisfied = (
            bool(runtime_source_ids)
            and actor_count >= 1
            and (not state_changing or before_strategy)
        )
    elif record.category == "authorization" or binding_family:
        baseline_satisfied = distinct_baselines and (not state_changing or before_strategy)
    elif state_changing:
        baseline_satisfied = bool(safe_oracles and runtime_ids and before_strategy)
        if logic_baseline is not None:
            baseline_satisfied = baseline_satisfied and logic_baseline.satisfied
    else:
        baseline_satisfied = bool(runtime_source_ids)
    baseline_capability = _capability(
        CapabilityKind.BASELINE,
        required=baseline_required,
        satisfied=baseline_satisfied,
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary="Controlled baselines must establish the comparison or pre-state.",
        evidence=[
            _evidence(endpoint.id, "ENDPOINT", "A safe baseline/oracle endpoint is available.")
            for endpoint in safe_oracles
        ]
        + controlled_baseline_evidence,
        missing=(
            (
                [
                    f"Missing controlled object baseline for {actor}."
                    for actor in missing_baseline_actors
                ]
                or ["Capture two distinct controlled actor/subject baselines."]
            )
            if record.category == "authorization" or binding_family
            else ["Capture a controlled pre-state through an authoritative safe read."]
        ),
        next_action=("Capture the missing controlled baselines before planning the mutation."),
    )

    source_hosts = {host for endpoint in source for host in endpoint.hosts}
    scope_satisfied = bool(target.scope.hosts) and (
        not source_hosts or hosts_are_covered(source_hosts, target.scope.hosts)
    )
    request_template_satisfied = (
        len(source) == len(set(record.source.endpoints))
        and bool(source and runtime_source_ids)
        and scope_satisfied
    )
    if rule.startswith("BUSINESS_LOGIC_SHADOW_ENDPOINT"):
        request_template_satisfied = False
    request_missing: list[str] = []
    if not source or len(source) != len(set(record.source.endpoints)):
        request_missing.append("One or more source endpoints cannot be resolved from inventory.")
    if not runtime_source_ids:
        request_missing.append(
            "Capture a runtime request matching the exact method, route, and mutation input."
        )
    if not target.scope.hosts:
        request_missing.append("No in-scope hosts are configured.")
    elif not scope_satisfied:
        request_missing.append("Source endpoint hosts are not fully covered by target scope.")
    if rule.startswith("BUSINESS_LOGIC_SHADOW_ENDPOINT"):
        request_missing.append("The candidate method has not been observed at runtime.")
    request_capability = _capability(
        CapabilityKind.REQUEST_TEMPLATE,
        satisfied=request_template_satisfied,
        stage=BlockerStage.PLAN_CONSTRUCTABILITY,
        summary="A redacted observed request template must support the exact bounded mutation.",
        evidence=[
            _evidence(endpoint.id, "ENDPOINT", "Endpoint has runtime request provenance.")
            for endpoint in source
            if set(endpoint.sources).intersection(runtime_source_ids)
        ],
        missing=request_missing,
        next_action="Collect one authorized runtime baseline request for the exact operation.",
    )

    if intent.operation == DomainOperation.VERIFY_CREDENTIAL:
        oracle_satisfied = bool(source and runtime_source_ids)
        oracle_summary = "A verifier decision can classify the bounded credential claim."
    elif state_changing:
        oracle_satisfied = bool(safe_oracles and runtime_ids and after_strategy)
        oracle_summary = (
            "A concrete post-state oracle plus before/immediate/delayed capture strategy is "
            "required."
        )
    else:
        oracle_satisfied = bool(
            source
            and runtime_source_ids
            and any(
                parameter.source == "response"
                for endpoint in source
                for parameter in endpoint.parameters
            )
        )
        oracle_summary = "A meaningful response or protected-resource oracle is required."
    oracle_capability = _capability(
        CapabilityKind.ORACLE,
        satisfied=oracle_satisfied,
        stage=BlockerStage.PLAN_CONSTRUCTABILITY,
        summary=oracle_summary,
        evidence=[
            _evidence(endpoint.id, "ENDPOINT", "Endpoint supports the planned oracle strategy.")
            for endpoint in safe_oracles or source
        ],
        missing=[
            "Define and capture an authoritative post-state or protected-response oracle, "
            "including "
            "before/immediate/delayed state when the operation changes state."
        ],
        next_action="Capture the independent safe oracle required to classify the result.",
    )

    budget_required = _request_budget(record, intent)
    budget_capability = _capability(
        CapabilityKind.BUDGET,
        satisfied=target.testing.maximum_requests_per_plan >= budget_required,
        stage=BlockerStage.PLAN_CONSTRUCTABILITY,
        summary=(
            f"The bounded plan requires {budget_required} request(s); target policy permits "
            f"{target.testing.maximum_requests_per_plan}."
        ),
        evidence=[
            _evidence(
                "target.testing.maximum_requests_per_plan",
                "TARGET_POLICY",
                f"Configured request budget is {target.testing.maximum_requests_per_plan}.",
            )
        ],
        missing=[
            "Target request budget is too low: "
            f"the bounded plan requires {budget_required} request(s), but policy permits "
            f"{target.testing.maximum_requests_per_plan}."
        ],
        next_action="Review the request budget without enabling active execution.",
    )

    segmentation = _logic_capability(record, CapabilityKind.SEGMENTATION)
    segmentation_capability = segmentation or _capability(
        CapabilityKind.SEGMENTATION,
        required=record.category == "business_logic",
        satisfied=record.category != "business_logic",
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary="Workflow segmentation must be strong enough to isolate the tested sequence.",
        missing=["Collect typed causal evidence that resolves workflow segmentation ambiguity."],
        next_action="Capture the producer-consumer evidence needed to isolate the workflow.",
    )

    cleanup_required = state_changing
    cleanup_satisfied = not cleanup_required or target.testing.synthetic or target.testing.local_lab
    logic_cleanup = _logic_capability(record, CapabilityKind.CLEANUP)
    if logic_cleanup is not None and cleanup_required:
        cleanup_satisfied = cleanup_satisfied and logic_cleanup.satisfied
    cleanup_capability = _capability(
        CapabilityKind.CLEANUP,
        required=cleanup_required,
        satisfied=cleanup_satisfied,
        stage=BlockerStage.PLAN_CONSTRUCTABILITY,
        summary="State-changing tests require rollback, cleanup, or disposable-resource controls.",
        evidence=(
            [
                _evidence(
                    "target.testing",
                    "TARGET_POLICY",
                    "The target is configured as a synthetic or local-lab environment.",
                )
            ]
            if cleanup_satisfied and cleanup_required
            else []
        ),
        missing=["Define a rollback, cleanup, or disposable-resource strategy."],
        next_action="Document the cleanup or disposable-resource strategy before planning.",
    )

    warnings = [
        ReadinessIssue(
            code="HUMAN_APPROVAL_REQUIRED",
            stage=BlockerStage.HUMAN_APPROVAL,
            summary="Human approval remains mandatory after the plan is reviewed.",
        )
    ]
    if not target.testing.active_execution_enabled:
        warnings.append(
            ReadinessIssue(
                code="ACTIVE_EXECUTION_DISABLED",
                stage=BlockerStage.EXECUTION_POLICY,
                summary="Active execution is disabled; this does not change hypothesis readiness.",
            )
        )
    if state_changing and target.testing.read_only_only:
        warnings.append(
            ReadinessIssue(
                code="READ_ONLY_RUNNER_UNSUPPORTED",
                stage=BlockerStage.EXECUTION_POLICY,
                summary=(
                    "The bounded runner remains read-only; any approved collection is manual-only."
                ),
            )
        )
    logic_safety = (
        str(record.logic_details.get("safety_classification", ""))
        if record.logic_details is not None
        else ""
    )
    if logic_safety == "CONCURRENT" or "CONCURRENCY" in record.mutation_dimensions:
        warnings.append(
            ReadinessIssue(
                code="CONCURRENCY_EXECUTION_UNSUPPORTED",
                stage=BlockerStage.EXECUTION_POLICY,
                summary="Concurrency testing remains manual-only and outside the bounded runner.",
            )
        )
    if claim_strength.target_level.value.startswith("5_"):
        warnings.append(
            ReadinessIssue(
                code="AUTHORITATIVE_EFFECT_EVIDENCE_REQUIRED",
                stage=BlockerStage.HUMAN_APPROVAL,
                summary="A status code alone cannot establish the targeted backend-effect claim.",
            )
        )
    return ReadinessContext(
        hypothesis_id=record.id,
        kind=record.kind,
        capabilities=(
            concrete_capability,
            semantic_target_capability,
            actor_capability,
            ownership_capability,
            baseline_capability,
            request_capability,
            oracle_capability,
            budget_capability,
            segmentation_capability,
            cleanup_capability,
        ),
        warnings=tuple(warnings),
    )


def assess_record_readiness(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: list[Endpoint],
    resources: ResourceStore,
    record: HypothesisLike,
    intent: DomainIntentAssessment,
    claim_strength: ClaimStrengthAssessment,
) -> HypothesisReadinessAssessment:
    """Build and evaluate the canonical record context in one deterministic call."""

    return evaluate_readiness(
        build_record_readiness_context(
            target,
            observations,
            endpoints,
            resources,
            record,
            intent,
            claim_strength,
        )
    )
