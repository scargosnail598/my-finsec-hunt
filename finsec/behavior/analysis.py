"""Business invariant inference and controlled workflow-mutation hypothesis generation."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from finsec.behavior.domain import (
    ActionStore,
    BusinessInvariant,
    BusinessInvariantStore,
    EpistemicStatus,
    HypothesisFamily,
    HypothesisReadiness,
    InferenceConfidence,
    LogicHypothesis,
    LogicHypothesisStore,
    LogicScore,
    MutationRejection,
    PropagationStore,
    RelationshipType,
    SafetyClassification,
    ScoreContribution,
    TransitionRecord,
    TransitionStore,
    WorkflowFamily,
    WorkflowFamilyStore,
    WorkflowInstance,
    WorkflowInstanceStore,
)
from finsec.behavior.reconstruction import (
    TERMINAL_STATES,
    build_behavior_model,
    is_merge_capable_relationship,
)
from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStore
from finsec.modeling.merge import merge_generated_records, stable_fingerprint
from finsec.modeling.models import EndpointStore, ObservationStore
from finsec.utils.yaml_store import load_yaml, write_yaml

ONE_TIME_VERBS = {
    "ACCEPT",
    "APPROVE",
    "CLAIM",
    "COMPLETE",
    "CONFIRM",
    "CONSUME",
    "REDEEM",
    "REFUND",
    "REVERSE",
    "RETURN",
    "WITHDRAW",
}
TERMINAL_VERBS = {
    "CANCEL",
    "CLOSE",
    "COMPLETE",
    "CONSUME",
    "DELETE",
    "EXPIRE",
    "REFUND",
    "REJECT",
    "SHIP",
}
FINANCIAL_TERMS = {
    "amount",
    "balance",
    "capture",
    "coupon",
    "credit",
    "invoice",
    "pay",
    "payment",
    "refund",
    "return",
    "reward",
    "settle",
    "settlement",
    "transfer",
    "wallet",
    "withdraw",
}
SHADOW_MUTABLE_RESOURCES = {"invoice", "order", "payment", "subscription", "transfer"}


@dataclass(frozen=True)
class LogicAnalysisResult:
    """Summary of deterministic offline business-logic analysis."""

    business_invariants: int
    hypotheses: int
    research_tasks: int
    ready_for_planning: int
    rejected_mutations: int
    conflicts: tuple[str, ...]


@dataclass(frozen=True)
class _Inputs:
    target: TargetDocument
    observations: ObservationStore
    endpoints: EndpointStore
    actions: ActionStore
    instances: WorkflowInstanceStore
    families: WorkflowFamilyStore
    transitions: TransitionStore
    propagation: PropagationStore
    existing_hypotheses: HypothesisStore


def _load_inputs(workspace: WorkspacePaths) -> _Inputs:
    try:
        return _Inputs(
            target=TargetDocument.model_validate(load_yaml(workspace.target)),
            observations=ObservationStore.model_validate(load_yaml(workspace.observations)),
            endpoints=EndpointStore.model_validate(load_yaml(workspace.endpoints)),
            actions=ActionStore.model_validate(load_yaml(workspace.behavior_actions)),
            instances=WorkflowInstanceStore.model_validate(load_yaml(workspace.workflow_instances)),
            families=WorkflowFamilyStore.model_validate(load_yaml(workspace.workflow_families)),
            transitions=TransitionStore.model_validate(load_yaml(workspace.behavior_transitions)),
            propagation=PropagationStore.model_validate(load_yaml(workspace.propagation_links)),
            existing_hypotheses=HypothesisStore.model_validate(load_yaml(workspace.hypotheses)),
        )
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load business-logic analysis inputs: {error}") from error


def _verb(action: str) -> str:
    return action.split("_", 1)[0]


def _human_action(action: str) -> str:
    return action.replace("_", " ").lower()


def _family_instances(inputs: _Inputs) -> dict[str, list[WorkflowInstance]]:
    grouped: dict[str, list[WorkflowInstance]] = defaultdict(list)
    for item in inputs.instances.workflow_instances:
        grouped[item.family_id].append(item)
    return grouped


def _family_transitions(inputs: _Inputs) -> dict[str, list[TransitionRecord]]:
    grouped: dict[str, list[TransitionRecord]] = defaultdict(list)
    for item in inputs.transitions.transitions:
        grouped[item.workflow_family_id].append(item)
    return grouped


def _observations_for_actions(
    instances: Iterable[WorkflowInstance], actions: set[str] | None = None
) -> list[str]:
    return sorted(
        {
            step.observation_id
            for instance in instances
            for step in instance.steps
            if actions is None or step.action_name in actions
        }
    )


def _confidence_for_family(family: WorkflowFamily) -> InferenceConfidence:
    if family.inference_confidence == InferenceConfidence.HIGH_EVIDENCE:
        return InferenceConfidence.HIGH_EVIDENCE
    if len(family.workflow_instance_ids) >= 2:
        return InferenceConfidence.MODERATE_EVIDENCE
    return InferenceConfidence.WEAK_EVIDENCE


def _invariant(
    family: WorkflowFamily,
    invariant_type: str,
    statement: str,
    observations: list[str],
    source: list[str],
    *,
    state_changing: bool = True,
    contradictions: list[str] | None = None,
    validation: list[str] | None = None,
    mutable_value_fields: list[str] | None = None,
    authoritative_value_fields: list[str] | None = None,
    resource_types: list[str] | None = None,
    source_endpoint_ids: list[str] | None = None,
    candidate_methods: list[str] | None = None,
    candidate_paths: list[str] | None = None,
    candidate_fields: list[str] | None = None,
    prerequisite_action: str | None = None,
    dependent_action: str | None = None,
    prerequisite_position: int | None = None,
    dependent_position: int | None = None,
    support_count: int = 0,
    support_ratio: float = 0,
    causal_evidence: list[str] | None = None,
    counterexamples: list[str] | None = None,
) -> BusinessInvariant:
    confidence = _confidence_for_family(family)
    contradiction_list = sorted(contradictions or [])
    if contradiction_list:
        confidence = {
            InferenceConfidence.HIGH_EVIDENCE: InferenceConfidence.MODERATE_EVIDENCE,
            InferenceConfidence.MODERATE_EVIDENCE: InferenceConfidence.WEAK_EVIDENCE,
            InferenceConfidence.WEAK_EVIDENCE: InferenceConfidence.SPECULATIVE,
            InferenceConfidence.SPECULATIVE: InferenceConfidence.SPECULATIVE,
        }[confidence]
    explanation = [
        f"The rule is derived from {len(family.workflow_instance_ids)} workflow instance(s).",
        "Observed frequency is evidence of a pattern, not proof that the backend requires it.",
    ]
    if len(family.workflow_instance_ids) == 1:
        explanation.append("One workflow instance cannot establish a mandatory business rule.")
    if contradiction_list:
        explanation.append(
            f"Confidence is reduced by {len(contradiction_list)} contradicting observation(s)."
        )
    invariant_id = (
        "BINV-"
        + stable_fingerprint({"family": family.id, "type": invariant_type, "statement": statement})[
            :16
        ].upper()
    )
    return BusinessInvariant(
        id=invariant_id,
        statement=statement,
        invariant_type=invariant_type,  # type: ignore[arg-type]
        workflow_family_id=family.id,
        resource_types=sorted(set(resource_types or family.resource_types)),
        supporting_observations=observations,
        contradicting_observations=contradiction_list,
        source_of_inference=source,
        mutable_value_fields=sorted(set(mutable_value_fields or [])),
        authoritative_value_fields=sorted(set(authoritative_value_fields or [])),
        source_endpoint_ids=sorted(set(source_endpoint_ids or [])),
        candidate_methods=sorted(set(candidate_methods or [])),
        candidate_paths=sorted(set(candidate_paths or [])),
        candidate_fields=sorted(set(candidate_fields or [])),
        prerequisite_action=prerequisite_action,
        dependent_action=dependent_action,
        prerequisite_position=prerequisite_position,
        dependent_position=dependent_position,
        support_count=support_count,
        support_ratio=support_ratio,
        causal_evidence=sorted(set(causal_evidence or [])),
        counterexamples=sorted(set(counterexamples or [])),
        confidence=confidence,
        confidence_explanation=explanation,
        validation_requirements=validation
        or [
            "Use only researcher-controlled actors and resources.",
            "Capture the mutation request and immediate response.",
            "Capture authoritative state before and after the mutation.",
        ],
        state_changing_validation=state_changing,
    )


def _state_changing_actions(inputs: _Inputs, family: WorkflowFamily) -> list[str]:
    observed = {action for path in family.observed_paths for action in path}
    changing = {
        item.name
        for item in inputs.actions.actions
        if item.state_changing and item.name in observed
    }
    ordered = [action for action in family.common_path if action in changing]
    return [*ordered, *sorted(changing - set(ordered))]


def _preferred_mutation_action(
    inputs: _Inputs, family: WorkflowFamily, *, prefer_rollback: bool = False
) -> str | None:
    actions = _state_changing_actions(inputs, family)
    if prefer_rollback:
        rollback = next(
            (
                action
                for action in actions
                if _verb(action) in {"CANCEL", "REFUND", "RETURN", "REVERSE"}
            ),
            None,
        )
        if rollback is not None:
            return rollback
    return actions[-1] if actions else None


def _value_mutation_action(inputs: _Inputs, family: WorkflowFamily) -> str | None:
    instances = _family_instances(inputs).get(family.id, [])
    eligible = {
        step.action_name
        for instance in instances
        for step in instance.steps
        if step.state_changing and any(value.client_controlled for value in step.business_values)
    }
    ordered = [action for action in family.common_path if action in eligible]
    remaining = sorted(eligible - set(ordered))
    candidates = [*ordered, *remaining]
    rollback = next(
        (
            action
            for action in candidates
            if _verb(action) in {"CANCEL", "REFUND", "RETURN", "REVERSE"}
        ),
        None,
    )
    return rollback or (candidates[-1] if candidates else None)


def infer_business_invariants(inputs: _Inputs) -> list[BusinessInvariant]:
    """Infer conservative business rules while retaining contradictions and uncertainty."""

    instances_by_family = _family_instances(inputs)
    invariants: list[BusinessInvariant] = []
    confidence_rank = {
        InferenceConfidence.SPECULATIVE: 0,
        InferenceConfidence.WEAK_EVIDENCE: 1,
        InferenceConfidence.MODERATE_EVIDENCE: 2,
        InferenceConfidence.HIGH_EVIDENCE: 3,
    }
    preferred_shadow_families: dict[str, WorkflowFamily] = {}
    for candidate_family in inputs.families.workflow_families:
        for resource_type in {
            item.lower() for item in candidate_family.resource_types
        }.intersection(SHADOW_MUTABLE_RESOURCES):
            current = preferred_shadow_families.get(resource_type)
            candidate_score = (
                confidence_rank[candidate_family.inference_confidence],
                len(candidate_family.workflow_instance_ids),
                candidate_family.id,
            )
            current_score = (
                (
                    confidence_rank[current.inference_confidence],
                    len(current.workflow_instance_ids),
                    current.id,
                )
                if current is not None
                else (-1, -1, "")
            )
            if candidate_score > current_score:
                preferred_shadow_families[resource_type] = candidate_family
    shadow_endpoint_ids_seen: set[str] = set()
    for family in inputs.families.workflow_families:
        instances = instances_by_family.get(family.id, [])
        paths = [tuple(step.action_name for step in item.steps) for item in instances]
        observed_actions = sorted({action for path in paths for action in path})
        state_changing_actions = set(_state_changing_actions(inputs, family))
        for prerequisite in family.causal_prerequisites:
            if prerequisite.dependent_action not in state_changing_actions:
                continue
            invariants.append(
                _invariant(
                    family,
                    "ORDERING",
                    f"{prerequisite.dependent_action} appears to require "
                    f"{prerequisite.prerequisite_action} to occur first in {family.name}.",
                    prerequisite.supporting_observations,
                    [
                        prerequisite.reason,
                        f"Support: {prerequisite.support_count}/"
                        f"{prerequisite.comparable_instances} comparable workflow instances.",
                    ],
                    contradictions=prerequisite.counterexamples,
                    prerequisite_action=prerequisite.prerequisite_action,
                    dependent_action=prerequisite.dependent_action,
                    prerequisite_position=prerequisite.prerequisite_position,
                    dependent_position=prerequisite.dependent_position,
                    support_count=prerequisite.support_count,
                    support_ratio=prerequisite.support_ratio,
                    causal_evidence=prerequisite.causal_link_ids,
                    counterexamples=prerequisite.counterexamples,
                )
            )

        for action in observed_actions:
            if _verb(action) in ONE_TIME_VERBS and action in state_changing_actions:
                invariants.append(
                    _invariant(
                        family,
                        "SINGLE_EXECUTION",
                        f"{action} should produce at most one successful business effect per "
                        "logical workflow.",
                        _observations_for_actions(instances, {action}),
                        [f"{action} has one-time or irreversible action semantics."],
                    )
                )
            explicit_terminal = any(
                step.action_name == action
                and any(
                    state.derivation == "EXPLICIT_FIELD" and state.state_after in TERMINAL_STATES
                    for state in step.state_observations
                )
                for instance in instances
                for step in instance.steps
            )
            if _verb(action) in TERMINAL_VERBS and explicit_terminal:
                invariants.append(
                    _invariant(
                        family,
                        "TERMINAL_STATE",
                        f"Operations should not revive or advance {family.name} after {action} "
                        "reaches a terminal state.",
                        _observations_for_actions(instances, {action}),
                        [f"{action} has terminal lifecycle semantics."],
                    )
                )

        family_observations = set(_observations_for_actions(instances))
        comparison_links = [
            item
            for item in inputs.propagation.propagation_links
            if item.relationship_type == RelationshipType.CROSS_ACTOR_COMPARISON
            and family_observations.intersection(item.evidence)
        ]
        client_resource_fields = sorted(
            {
                field
                for instance in instances
                for step in instance.steps
                for field in step.client_controlled_resource_fields
            }
        )
        if comparison_links and client_resource_fields and state_changing_actions:
            invariants.append(
                _invariant(
                    family,
                    "ACTOR_BINDING",
                    f"Each state-changing step in {family.name} should remain bound to an "
                    "authorized workflow actor.",
                    _observations_for_actions(instances),
                    [
                        f"Observed actors: {', '.join(family.actors)}.",
                        f"Cross-actor comparison links: {len(comparison_links)}.",
                    ],
                )
            )
            invariants.append(
                _invariant(
                    family,
                    "RESOURCE_BINDING",
                    f"Identifiers used by {family.name} should remain bound to the same "
                    "controlled resource lifecycle.",
                    _observations_for_actions(instances),
                    [
                        f"Observed typed client-controlled identifier fields: "
                        f"{', '.join(client_resource_fields)}."
                    ],
                )
            )

        token_links = [
            item
            for item in inputs.propagation.propagation_links
            if item.value_kind == "WORKFLOW_TOKEN"
            and is_merge_capable_relationship(item)
            and item.source_observation_id in family_observations
        ]
        if token_links:
            invariants.append(
                _invariant(
                    family,
                    "TOKEN_SCOPE",
                    f"Workflow references propagated through {family.name} should be "
                    "single-purpose and resource-scoped.",
                    sorted({value for item in token_links for value in item.evidence}),
                    [
                        f"Observed {len(token_links)} response-to-request workflow "
                        "reference link(s)."
                    ],
                )
            )

        actions = set(observed_actions)
        rollback_actions = {
            item for item in actions if _verb(item) in {"CANCEL", "REFUND", "RETURN", "REVERSE"}
        }
        if rollback_actions:
            for rollback_action in sorted(rollback_actions):
                rollback_resource_types = sorted(
                    {
                        state.resource_type
                        for instance in instances
                        for step in instance.steps
                        if step.action_name == rollback_action
                        for state in step.state_observations
                    }
                )
                if len(rollback_resource_types) < 2:
                    continue
                invariants.append(
                    _invariant(
                        family,
                        "ROLLBACK_CONSISTENCY",
                        f"{rollback_action} in {family.name} should leave all linked resource "
                        "states mutually consistent.",
                        _observations_for_actions(instances, {rollback_action}),
                        [
                            f"Rollback action: {rollback_action}.",
                            f"Linked resource states: {', '.join(rollback_resource_types)}.",
                        ],
                        resource_types=rollback_resource_types,
                    )
                )

        family_steps = [step for instance in instances for step in instance.steps]
        mutable_value_fields = sorted(
            {
                value.field
                for step in family_steps
                for value in step.business_values
                if value.direction == "REQUEST"
            }
        )
        authoritative_value_fields = sorted(
            {
                value.field
                for step in family_steps
                for value in step.business_values
                if value.direction == "RESPONSE"
            }
        )
        balance_steps = [
            step
            for instance in inputs.instances.workflow_instances
            for step in instance.steps
            if step.actor in family.actors
            and any(
                value.direction == "RESPONSE"
                and any(term in value.field.lower() for term in ("balance", "credit"))
                for value in step.business_values
            )
        ]
        if any(_verb(action) in {"REFUND", "RETURN", "REVERSE"} for action in observed_actions):
            authoritative_value_fields = sorted(
                set(authoritative_value_fields)
                | {
                    value.field
                    for step in balance_steps
                    for value in step.business_values
                    if value.direction == "RESPONSE"
                }
            )
        value_fields = sorted(set(mutable_value_fields) | set(authoritative_value_fields))
        if mutable_value_fields and state_changing_actions:
            balance_observations = [step.observation_id for step in balance_steps]
            value_resource_types = list(family.resource_types)
            if any(
                "credit" in field.lower() or "balance" in field.lower() for field in value_fields
            ):
                value_resource_types.append("account")
            invariants.append(
                _invariant(
                    family,
                    "VALUE_CONSERVATION",
                    f"Amounts, quantities, and linked financial effects in {family.name} "
                    "should remain internally consistent.",
                    sorted(set(_observations_for_actions(instances)) | set(balance_observations)),
                    [
                        "Observed value fields: "
                        f"{', '.join(value_fields) or 'financial action semantics'}."
                    ],
                    mutable_value_fields=mutable_value_fields,
                    authoritative_value_fields=authoritative_value_fields,
                    resource_types=value_resource_types,
                )
            )

        family_resource_names = {item.lower() for item in family.resource_types}
        if family_resource_names.intersection(SHADOW_MUTABLE_RESOURCES):
            for endpoint in inputs.endpoints.endpoints:
                if endpoint.method != "GET" or "{" not in endpoint.path:
                    continue
                if endpoint.resource.type.lower() not in family_resource_names:
                    continue
                if (
                    preferred_shadow_families.get(endpoint.resource.type.lower()) != family
                    or endpoint.id in shadow_endpoint_ids_seen
                    or len(endpoint.sources) < 2
                ):
                    continue
                candidate_fields = sorted(
                    {
                        parameter.name
                        for parameter in endpoint.parameters
                        if parameter.source == "response"
                        and parameter.semantic_type in {"monetary_value", "state"}
                    }
                )
                if not candidate_fields:
                    continue
                collection_path = endpoint.path.rsplit("/", 1)[0]
                has_collection_mutation = any(
                    item.method == "POST"
                    and item.path == collection_path
                    and item.resource.type.lower() == endpoint.resource.type.lower()
                    for item in inputs.endpoints.endpoints
                )
                has_item_update = any(
                    item.method in {"PATCH", "PUT"} and item.path == endpoint.path
                    for item in inputs.endpoints.endpoints
                )
                if not has_collection_mutation or has_item_update:
                    continue
                shadow_endpoint_ids_seen.add(endpoint.id)
                invariants.append(
                    _invariant(
                        family,
                        "SERVER_CONTROLLED_FIELDS",
                        f"Server-controlled {endpoint.resource.type} lifecycle and value fields "
                        "should not become writable through an undocumented REST method.",
                        endpoint.sources,
                        [
                            f"Observed readable item route: GET {endpoint.path}.",
                            f"No observed PUT or PATCH operation exists for {endpoint.path}.",
                            "Candidate fields are response-derived and not observed request "
                            "inputs.",
                        ],
                        resource_types=[endpoint.resource.type],
                        source_endpoint_ids=[endpoint.id],
                        candidate_methods=["PATCH", "PUT"],
                        candidate_paths=[endpoint.path],
                        candidate_fields=candidate_fields,
                        authoritative_value_fields=[
                            parameter.json_path or parameter.name
                            for parameter in endpoint.parameters
                            if parameter.name in candidate_fields
                            and parameter.semantic_type == "monetary_value"
                        ],
                    )
                )

        approval_actions = {item for item in actions if _verb(item) in {"APPROVE", "REVIEW"}}
        initiating_actions = {
            item for item in actions if _verb(item) in {"CREATE", "INITIATE", "REQUEST", "SUBMIT"}
        }
        if approval_actions and initiating_actions:
            invariants.append(
                _invariant(
                    family,
                    "ROLE_SEPARATION",
                    f"Initiation and approval in {family.name} should enforce the intended "
                    "role separation.",
                    _observations_for_actions(instances, approval_actions | initiating_actions),
                    [
                        f"Initiating actions: {', '.join(sorted(initiating_actions))}.",
                        f"Approval actions: {', '.join(sorted(approval_actions))}.",
                    ],
                )
            )

    return sorted({item.id: item for item in invariants}.values(), key=lambda item: item.id)


def _controlled_accounts(target: TargetDocument) -> list[str]:
    return sorted(item.id for item in target.accounts if item.ownership == "researcher")


def _endpoint_ids(instances: list[WorkflowInstance], actions: set[str]) -> list[str]:
    return sorted(
        {
            endpoint_id
            for instance in instances
            for step in instance.steps
            if step.action_name in actions
            for endpoint_id in step.endpoint_ids
        }
    )


def _safety(family: HypothesisFamily, action: str) -> SafetyClassification:
    lowered = action.lower()
    if family == "CONCURRENT_EXECUTION":
        return SafetyClassification.CONCURRENT
    if _verb(action) in {
        "CAPTURE",
        "PAY",
        "REFUND",
        "RETURN",
        "SETTLE",
        "TRANSFER",
        "WITHDRAW",
    } or any(
        term in lowered
        for term in ("payment", "refund", "return_order", "transfer", "withdraw", "wallet")
    ):
        return SafetyClassification.FINANCIAL_STATE_CHANGE
    if any(term in lowered for term in ("delete", "close", "terminate")):
        return SafetyClassification.DESTRUCTIVE
    if any(term in lowered for term in ("email", "sms", "provision", "ship")):
        return SafetyClassification.EXTERNAL_SIDE_EFFECT
    if _verb(action) == "READ":
        return SafetyClassification.READ_ONLY
    if any(term in lowered for term in ("cancel", "suspend", "disable")):
        return SafetyClassification.REVERSIBLE_STATE_CHANGE
    return SafetyClassification.LOW_RISK_STATE_CHANGE


def _score(
    invariant: BusinessInvariant,
    family: WorkflowFamily,
    safety: SafetyClassification,
    blockers: list[str],
    action: str,
) -> LogicScore:
    breakdown: list[ScoreContribution] = []
    support = len(family.workflow_instance_ids)
    likelihood = 1
    if support >= 3:
        likelihood += 2
        breakdown.append(ScoreContribution(reason="Three or more supporting workflows", points=2))
    elif support >= 2:
        likelihood += 1
        breakdown.append(ScoreContribution(reason="Two supporting workflows", points=1))
    if invariant.confidence == InferenceConfidence.HIGH_EVIDENCE:
        likelihood += 1
        breakdown.append(ScoreContribution(reason="High-evidence invariant", points=1))
    if invariant.contradicting_observations:
        likelihood -= 1
        breakdown.append(ScoreContribution(reason="Contradicting observation exists", points=-1))
    likelihood = min(max(likelihood, 1), 5)

    impact = 2
    lowered = action.lower()
    if any(term in lowered for term in FINANCIAL_TERMS) or any(
        term in field.lower()
        for field in invariant.authoritative_value_fields
        for term in FINANCIAL_TERMS
    ):
        impact += 2
        breakdown.append(ScoreContribution(reason="Financial operation", points=2))
    if any(term in lowered for term in ("approve", "admin", "role", "entitlement")):
        impact += 1
        breakdown.append(ScoreContribution(reason="Privilege or entitlement impact", points=1))
    impact = min(impact, 5)

    readiness = 5
    for blocker in blockers:
        deduction = (
            2 if "controlled" in blocker.lower() or "authentication" in blocker.lower() else 1
        )
        readiness -= deduction
        breakdown.append(ScoreContribution(reason=blocker, points=-deduction))
    readiness = min(max(readiness, 1), 5)

    safety_cost = {
        SafetyClassification.READ_ONLY: 1,
        SafetyClassification.LOW_RISK_STATE_CHANGE: 2,
        SafetyClassification.REVERSIBLE_STATE_CHANGE: 3,
        SafetyClassification.FINANCIAL_STATE_CHANGE: 5,
        SafetyClassification.DESTRUCTIVE: 5,
        SafetyClassification.CONCURRENT: 5,
        SafetyClassification.EXTERNAL_SIDE_EFFECT: 5,
        SafetyClassification.UNSAFE_OR_UNBOUNDED: 5,
    }[safety]
    confidence = {
        InferenceConfidence.HIGH_EVIDENCE: 5,
        InferenceConfidence.MODERATE_EVIDENCE: 4,
        InferenceConfidence.WEAK_EVIDENCE: 2,
        InferenceConfidence.SPECULATIVE: 1,
    }[invariant.confidence]
    return LogicScore(
        likelihood=likelihood,
        impact=impact,
        test_readiness=readiness,
        safety_cost=safety_cost,
        confidence=confidence,
        breakdown=breakdown,
    )


def _title(family: HypothesisFamily, action: str, context: str) -> str:
    readable = _human_action(action).capitalize()
    return {
        "STEP_SKIPPING": f"{readable} may succeed without {context}",
        "OUT_OF_ORDER_EXECUTION": f"{readable} may be accepted before {context}",
        "REPLAY": f"{readable} may remain replayable after its first successful effect",
        "DUPLICATE_ACTION": (
            f"Immediate duplicate {readable.lower()} may create two business effects"
        ),
        "CONCURRENT_EXECUTION": (
            f"Concurrent {readable.lower()} may bypass single-execution protection"
        ),
        "TERMINAL_STATE_BYPASS": f"{readable} may remain available after a terminal workflow state",
        "ACTOR_SWITCH": f"{readable} may not remain bound to the initiating actor",
        "RESOURCE_SWITCH": f"{readable} may accept a resource from another controlled workflow",
        "CROSS_WORKFLOW_TOKEN_REUSE": f"{readable} reference may be reusable across workflows",
        "PARTIAL_ROLLBACK": f"{readable} may leave linked resource state partially active",
        "QUANTITY_VALUE_INVARIANT": (
            f"Refund credit for {readable.lower()} may exceed the immutable order value"
            if _verb(action) in {"REFUND", "RETURN"}
            else f"{readable} may accept an amount or quantity inconsistent with the baseline"
        ),
        "ROLE_APPROVAL_BYPASS": f"{readable} may be performed by the original requester",
        "SHADOW_ENDPOINT": (
            f"Undocumented {readable.lower()} method may expose server-controlled fields"
        ),
    }[family]


def _blockers(
    inputs: _Inputs,
    family: WorkflowFamily,
    invariant: BusinessInvariant,
    required_actors: int,
    safety: SafetyClassification,
    request_budget: int,
) -> list[str]:
    blockers: list[str] = []
    if len(family.workflow_instance_ids) < 2:
        blockers.append("Insufficient workflow observations to treat the pattern as mandatory.")
    if family.inference_confidence in {
        InferenceConfidence.WEAK_EVIDENCE,
        InferenceConfidence.SPECULATIVE,
    }:
        blockers.append("Workflow segmentation remains ambiguous.")
    controlled = _controlled_accounts(inputs.target)
    if len(controlled) < required_actors:
        blockers.append(f"At least {required_actors} controlled actor(s) are required.")
    configured_controlled = [
        item for item in inputs.target.accounts if item.id in controlled[:required_actors]
    ]
    missing_authentication = any(
        item.authenticated
        and (
            item.authentication is None
            or (
                item.authentication.auth_type != "none"
                and item.authentication.status
                in {
                    "MISSING",
                    "INVALID",
                    "EXPIRED",
                    "REFRESH_REQUIRED",
                    "REFRESH_FAILED",
                    "AUTH_CONTEXT_CHANGED",
                }
            )
        )
        for item in configured_controlled
    )
    if missing_authentication:
        blockers.append("Missing actor authentication for one or more controlled workflow actors.")
    if not family.resource_types:
        blockers.append("Controlled resource ownership is not established.")
    if invariant.invariant_type in {"ACTOR_BINDING", "RESOURCE_BINDING", "TOKEN_SCOPE"} and not any(
        evidence.actor_object_binding_observed
        for endpoint in inputs.endpoints.endpoints
        for evidence in endpoint.object_access
    ):
        blockers.append("Controlled resource ownership baseline is missing.")
    family_transitions = [
        item for item in inputs.transitions.transitions if item.workflow_family_id == family.id
    ]
    if invariant.state_changing_validation and not any(
        item.source_state != "UNRESOLVED" and item.destination_state != "UNRESOLVED"
        for item in family_transitions
    ):
        blockers.append("An authoritative baseline state and before-state query are missing.")
    if safety == SafetyClassification.CONCURRENT:
        blockers.append("Concurrency testing is not permitted by the offline engine.")
    if safety in {
        SafetyClassification.FINANCIAL_STATE_CHANGE,
        SafetyClassification.DESTRUCTIVE,
        SafetyClassification.EXTERNAL_SIDE_EFFECT,
    }:
        blockers.append(
            f"{safety.value.replace('_', ' ').title()} requires explicit target policy permission."
        )
    if inputs.target.testing.maximum_requests_per_plan < request_budget:
        blockers.append(
            "Target request budget is too low: "
            f"{request_budget} requests are estimated but only "
            f"{inputs.target.testing.maximum_requests_per_plan} are permitted."
        )
    return sorted(set(blockers))


def _hypothesis(
    inputs: _Inputs,
    family: WorkflowFamily,
    invariant: BusinessInvariant,
    hypothesis_family: HypothesisFamily,
    action: str,
    context: str,
    canonical: str,
    mutated: str,
    actions: set[str],
    *,
    required_actors: int = 1,
    transition_id: str | None = None,
    extra_suppression: list[str] | None = None,
    extra_blockers: list[str] | None = None,
    endpoint_ids_override: list[str] | None = None,
    safety_override: SafetyClassification | None = None,
) -> LogicHypothesis:
    instances = [
        item for item in inputs.instances.workflow_instances if item.family_id == family.id
    ]
    safety = safety_override or _safety(hypothesis_family, action)
    budget = 4 if invariant.state_changing_validation else 2
    if hypothesis_family in {"REPLAY", "DUPLICATE_ACTION", "CONCURRENT_EXECUTION"}:
        budget = 5
    blockers = _blockers(inputs, family, invariant, required_actors, safety, budget)
    blockers.extend(extra_blockers or [])
    blockers = sorted(set(blockers))
    endpoint_ids = sorted(set(endpoint_ids_override or _endpoint_ids(instances, actions)))
    suppression = list(extra_suppression or [])
    if hypothesis_family == "RESOURCE_SWITCH":
        existing = load_existing_endpoint_hypotheses(inputs, endpoint_ids)
        if existing:
            suppression.append(
                "A stronger endpoint-level object-authorization hypothesis already covers "
                "this mutation."
            )
    unsafe = safety in {
        SafetyClassification.CONCURRENT,
        SafetyClassification.DESTRUCTIVE,
        SafetyClassification.EXTERNAL_SIDE_EFFECT,
        SafetyClassification.FINANCIAL_STATE_CHANGE,
        SafetyClassification.UNSAFE_OR_UNBOUNDED,
    }
    weak = invariant.confidence in {
        InferenceConfidence.WEAK_EVIDENCE,
        InferenceConfidence.SPECULATIVE,
    }
    kind = "RESEARCH_TASK" if unsafe or weak or suppression else "SECURITY_HYPOTHESIS"
    readiness = (
        HypothesisReadiness.RESEARCH_ONLY
        if kind == "RESEARCH_TASK"
        else HypothesisReadiness.REVIEW_REQUIRED
        if blockers
        else HypothesisReadiness.TEST_READY
    )
    status = (
        EpistemicStatus.RESEARCH_TASK if kind == "RESEARCH_TASK" else EpistemicStatus.TEST_CANDIDATE
    )
    score = _score(invariant, family, safety, blockers, action)
    fingerprint = stable_fingerprint(
        {
            "family": family.id,
            "hypothesis_family": hypothesis_family,
            "action": action,
            "context": context,
            "invariant": invariant.id,
            "mutation": mutated,
        }
    )
    state_requirements = (
        [
            "Record authoritative state for every affected resource before the mutation.",
            "Record the immediate mutation response.",
            "Record immediate and delayed authoritative state after the mutation.",
            "Compare linked financial, entitlement, inventory, and terminal workflow state "
            "where applicable.",
        ]
        if invariant.state_changing_validation
        else ["Retain the complete read-only response with provenance."]
    )
    if invariant.authoritative_value_fields:
        state_requirements.append(
            "Record authoritative values before and after the mutation for: "
            + ", ".join(invariant.authoritative_value_fields)
            + "."
        )
    controlled = _controlled_accounts(inputs.target)
    authentication = [
        f"Use the reviewed credential profile for {actor}."
        for actor in controlled[:required_actors]
    ] or ["Configure a researcher-controlled actor credential profile."]
    evidence = sorted(
        set(invariant.supporting_observations)
        | {
            step.observation_id
            for instance in instances
            for step in instance.steps
            if step.action_name in actions
        }
    )
    return LogicHypothesis(
        id=f"BLH-{fingerprint[:16].upper()}",
        fingerprint=fingerprint,
        title=_title(hypothesis_family, action, context),
        family=hypothesis_family,
        workflow_family_id=family.id,
        affected_action=action,
        affected_transition_id=transition_id,
        invariant_id=invariant.id,
        invariant_statement=invariant.statement,
        canonical_behavior=canonical,
        mutated_behavior=mutated,
        supporting_evidence=evidence,
        contradicting_evidence=invariant.contradicting_observations,
        controlled_actors_required=required_actors,
        controlled_resources_required=invariant.resource_types,
        authentication_requirements=authentication,
        state_evidence_requirements=state_requirements,
        mutable_value_fields=invariant.mutable_value_fields,
        authoritative_value_fields=invariant.authoritative_value_fields,
        candidate_methods=invariant.candidate_methods,
        candidate_paths=invariant.candidate_paths,
        candidate_fields=invariant.candidate_fields,
        expected_safe_baseline=(
            f"The canonical sequence is accepted for controlled {family.name} data."
        ),
        expected_vulnerable_outcome=(
            f"The backend accepts {mutated} and authoritative state shows an unintended effect."
        ),
        expected_secure_outcome=(
            f"The backend rejects {mutated} or produces no unauthorized state change."
        ),
        impact_rationale=(
            "Acceptance could violate lifecycle, financial, ownership, entitlement, or role state "
            "represented by the challenged invariant."
        ),
        score=score,
        confidence_explanation=invariant.confidence_explanation,
        uncertainty=[
            "Offline sequence evidence cannot prove that the backend requires the observed order.",
            "Capture incompleteness or an undocumented optional branch may explain the pattern.",
        ],
        safety_classification=safety,
        estimated_request_budget=budget,
        readiness_blockers=blockers,
        suggested_validation_strategy=[
            "Establish a successful controlled baseline.",
            f"Apply only this mutation: {mutated}.",
            "Stop after the minimum approved request budget.",
            "Classify the result from authoritative backend state, not status code alone.",
        ],
        suppression_reasons=suppression,
        endpoint_ids=endpoint_ids,
        observation_ids=evidence,
        kind=kind,  # type: ignore[arg-type]
        readiness=readiness,
        epistemic_status=status,
    )


def load_existing_endpoint_hypotheses(inputs: _Inputs, endpoint_ids: list[str]) -> list[str]:
    """Return overlapping endpoint hypotheses without coupling to their generated IDs."""

    selected = set(endpoint_ids)
    return sorted(
        item.id
        for item in inputs.existing_hypotheses.hypotheses
        if item.category == "authorization"
        and item.disposition == "ACTIVE"
        and selected.intersection(item.source.endpoints)
    )


def generate_logic_hypotheses(
    inputs: _Inputs, invariants: list[BusinessInvariant]
) -> list[LogicHypothesis]:
    """Apply minimal, family-specific workflow mutations to inferred business rules."""

    family_by_id = {item.id: item for item in inputs.families.workflow_families}
    transitions_by_family = _family_transitions(inputs)
    hypotheses: list[LogicHypothesis] = []
    for invariant in invariants:
        family = family_by_id[invariant.workflow_family_id]
        common = family.common_path
        observed = sorted({action for path in family.observed_paths for action in path})
        if invariant.invariant_type == "ORDERING":
            predecessor = invariant.prerequisite_action
            action = invariant.dependent_action
            if predecessor is None or action is None:
                continue
            transition = next(
                (
                    item
                    for item in transitions_by_family.get(family.id, [])
                    if item.action_name == action
                ),
                None,
            )
            hypotheses.extend(
                [
                    _hypothesis(
                        inputs,
                        family,
                        invariant,
                        "OUT_OF_ORDER_EXECUTION",
                        action,
                        _human_action(predecessor),
                        f"{predecessor} -> {action}",
                        f"{action} -> {predecessor}",
                        {predecessor, action},
                        transition_id=transition.id if transition else None,
                    ),
                    _hypothesis(
                        inputs,
                        family,
                        invariant,
                        "STEP_SKIPPING",
                        action,
                        _human_action(predecessor),
                        f"{predecessor} -> {action}",
                        f"omit {predecessor} and invoke {action}",
                        {predecessor, action},
                        transition_id=transition.id if transition else None,
                    ),
                ]
            )
        elif invariant.invariant_type == "SINGLE_EXECUTION":
            action = next((item for item in observed if item in invariant.statement), common[-1])
            hypotheses.extend(
                [
                    _hypothesis(
                        inputs,
                        family,
                        invariant,
                        "REPLAY",
                        action,
                        "the first successful effect",
                        f"{action} executes once",
                        f"{action} -> replay identical logical action",
                        {action},
                    ),
                    _hypothesis(
                        inputs,
                        family,
                        invariant,
                        "DUPLICATE_ACTION",
                        action,
                        "the first response",
                        f"{action} executes once",
                        f"{action} -> immediate duplicate {action}",
                        {action},
                    ),
                    _hypothesis(
                        inputs,
                        family,
                        invariant,
                        "CONCURRENT_EXECUTION",
                        action,
                        "single-execution serialization",
                        f"{action} executes serially once",
                        f"two bounded {action} requests execute concurrently",
                        {action},
                    ),
                ]
            )
        elif invariant.invariant_type == "TERMINAL_STATE":
            terminal = next((item for item in observed if item in invariant.statement), common[-1])
            action = next(
                (
                    item
                    for item in reversed(common)
                    if item != terminal and _verb(item) not in TERMINAL_VERBS
                ),
                common[0],
            )
            hypotheses.append(
                _hypothesis(
                    inputs,
                    family,
                    invariant,
                    "TERMINAL_STATE_BYPASS",
                    action,
                    _human_action(terminal),
                    f"{action} occurs before terminal action {terminal}",
                    f"{terminal} -> {action}",
                    {terminal, action},
                )
            )
        elif invariant.invariant_type == "ACTOR_BINDING":
            mutation_action = _preferred_mutation_action(inputs, family)
            if mutation_action is None:
                continue
            hypotheses.append(
                _hypothesis(
                    inputs,
                    family,
                    invariant,
                    "ACTOR_SWITCH",
                    mutation_action,
                    "the initiating actor",
                    f"one authorized actor performs {mutation_action}",
                    f"switch to a second controlled actor only for {mutation_action}",
                    {mutation_action},
                    required_actors=2,
                )
            )
        elif invariant.invariant_type == "RESOURCE_BINDING":
            mutation_action = _preferred_mutation_action(inputs, family)
            if mutation_action is None:
                continue
            hypotheses.append(
                _hypothesis(
                    inputs,
                    family,
                    invariant,
                    "RESOURCE_SWITCH",
                    mutation_action,
                    "the original controlled resource",
                    f"{mutation_action} uses identifiers from one controlled workflow",
                    "replace one identifier with a second controlled workflow resource for "
                    f"{mutation_action}",
                    {mutation_action},
                    required_actors=2,
                )
            )
        elif invariant.invariant_type == "TOKEN_SCOPE":
            action = common[-1]
            hypotheses.append(
                _hypothesis(
                    inputs,
                    family,
                    invariant,
                    "CROSS_WORKFLOW_TOKEN_REUSE",
                    action,
                    "the original workflow scope",
                    "a propagated workflow reference is consumed by its originating resource",
                    f"reuse the observed reference with a second controlled resource at {action}",
                    {action},
                    required_actors=2,
                )
            )
        elif invariant.invariant_type == "ROLLBACK_CONSISTENCY":
            action = next(
                (
                    item
                    for item in observed
                    if item in invariant.statement
                    and _verb(item) in {"CANCEL", "REFUND", "RETURN", "REVERSE"}
                ),
                common[-1],
            )
            hypotheses.append(
                _hypothesis(
                    inputs,
                    family,
                    invariant,
                    "PARTIAL_ROLLBACK",
                    action,
                    "linked resource compensation",
                    f"{action} reverses every linked resource effect",
                    f"perform {action} and compare each linked resource for incomplete "
                    "compensation",
                    {action},
                )
            )
        elif invariant.invariant_type == "VALUE_CONSERVATION":
            if not invariant.mutable_value_fields:
                continue
            mutation_action = _value_mutation_action(inputs, family)
            if mutation_action is None:
                continue
            refund_like = _verb(mutation_action) in {"REFUND", "RETURN"}
            hypotheses.append(
                _hypothesis(
                    inputs,
                    family,
                    invariant,
                    "QUANTITY_VALUE_INVARIANT",
                    mutation_action,
                    "the observed amount and quantity relationship",
                    (
                        f"{mutation_action} credits no more than the immutable purchase value"
                        if refund_like
                        else f"{mutation_action} uses the observed internally consistent values"
                    ),
                    (
                        "change one order value through an observed or separately researched "
                        f"update before {mutation_action}, then compare the credited balance"
                        if refund_like
                        else f"change one observed value field for {mutation_action} while "
                        "preserving all other fields"
                    ),
                    {mutation_action},
                )
            )
        elif invariant.invariant_type == "SERVER_CONTROLLED_FIELDS":
            resource = invariant.resource_types[0] if invariant.resource_types else "RESOURCE"
            action = f"UPDATE_{resource.upper()}"
            methods = "/".join(invariant.candidate_methods)
            paths = ", ".join(invariant.candidate_paths)
            fields = ", ".join(invariant.candidate_fields)
            hypotheses.append(
                _hypothesis(
                    inputs,
                    family,
                    invariant,
                    "SHADOW_ENDPOINT",
                    action,
                    "the documented resource interface",
                    "only observed methods can change server-controlled fields",
                    f"research whether {methods} {paths} accepts one of: {fields}",
                    set(),
                    endpoint_ids_override=invariant.source_endpoint_ids,
                    safety_override=SafetyClassification.FINANCIAL_STATE_CHANGE,
                    extra_blockers=[
                        "The candidate method has not been observed at runtime.",
                        "Collect passive route evidence or obtain explicit approval before "
                        "validation.",
                    ],
                    extra_suppression=[
                        "An unobserved REST method remains a research lead, not a test candidate."
                    ],
                )
            )
        elif invariant.invariant_type == "ROLE_SEPARATION":
            action = next(
                (item for item in observed if _verb(item) in {"APPROVE", "REVIEW"}), common[-1]
            )
            hypotheses.append(
                _hypothesis(
                    inputs,
                    family,
                    invariant,
                    "ROLE_APPROVAL_BYPASS",
                    action,
                    "an independent approver",
                    "separate configured roles initiate and approve the workflow",
                    f"the initiating controlled actor also performs {action}",
                    {action},
                    required_actors=2,
                )
            )
    deduplicated: dict[str, LogicHypothesis] = {}
    for item in hypotheses:
        current = deduplicated.get(item.fingerprint)
        if current is None or item.score.confidence > current.score.confidence:
            deduplicated[item.fingerprint] = item
    return sorted(deduplicated.values(), key=lambda item: item.id)


def generate_mutation_rejections(
    inputs: _Inputs,
    invariants: list[BusinessInvariant],
    hypotheses: list[LogicHypothesis],
) -> list[MutationRejection]:
    """Persist semantic gate failures without promoting them to research hypotheses."""

    accepted = {(item.workflow_family_id, item.family, item.affected_action) for item in hypotheses}
    instances_by_family = _family_instances(inputs)
    invariant_by_type = {
        (item.workflow_family_id, item.invariant_type): item for item in invariants
    }
    rejections: dict[tuple[str, str, str], MutationRejection] = {}

    def add(
        family: WorkflowFamily,
        mutation: HypothesisFamily,
        action: str,
        reasons: list[str],
        evidence: list[str],
        invariant: BusinessInvariant | None = None,
    ) -> None:
        if (family.id, mutation, action) in accepted:
            return
        key = (family.id, mutation, action)
        rejection_id = (
            "MREJ-"
            + stable_fingerprint({"family": family.id, "mutation": mutation, "action": action})[
                :16
            ].upper()
        )
        rejections[key] = MutationRejection(
            id=rejection_id,
            workflow_family_id=family.id,
            mutation_family=mutation,
            affected_action=action,
            invariant_id=invariant.id if invariant is not None else None,
            reasons=sorted(set(reasons)),
            evidence=sorted(set(evidence)),
        )

    for family in inputs.families.workflow_families:
        instances = instances_by_family.get(family.id, [])
        observations = _observations_for_actions(instances)
        changing_actions = _state_changing_actions(inputs, family)
        prerequisites = {
            (
                item.prerequisite_action,
                item.dependent_action,
                item.prerequisite_position,
                item.dependent_position,
            )
            for item in family.causal_prerequisites
        }
        if instances:
            for left, right in zip(instances[0].steps, instances[0].steps[1:], strict=False):
                key = (left.action_name, right.action_name, left.position, right.position)
                if right.state_changing and key not in prerequisites:
                    reason = [
                        "Adjacent route order has no typed producer-consumer or required-state "
                        "evidence; adjacency alone is not a prerequisite."
                    ]
                    add(family, "STEP_SKIPPING", right.action_name, reason, observations)
                    add(family, "OUT_OF_ORDER_EXECUTION", right.action_name, reason, observations)

        mutation_action = _preferred_mutation_action(inputs, family)
        if mutation_action is not None:
            action_steps = [
                step
                for instance in instances
                for step in instance.steps
                if step.action_name == mutation_action
            ]
            mutable_values = [
                value
                for step in action_steps
                for value in step.business_values
                if value.client_controlled
            ]
            value_invariant = invariant_by_type.get((family.id, "VALUE_CONSERVATION"))
            if not mutable_values:
                add(
                    family,
                    "QUANTITY_VALUE_INVARIANT",
                    mutation_action,
                    [
                        "No client-controlled request field has a recognized amount, price, "
                        "quantity, balance, credit, refund, limit, fee, or cumulative-value role."
                    ],
                    [step.observation_id for step in action_steps],
                    value_invariant,
                )

            comparison_links = [
                link
                for link in inputs.propagation.propagation_links
                if link.relationship_type == RelationshipType.CROSS_ACTOR_COMPARISON
                and set(link.evidence).intersection(observations)
            ]
            client_fields = sorted(
                {field for step in action_steps for field in step.client_controlled_resource_fields}
            )
            if not comparison_links or not client_fields:
                reasons = []
                if not client_fields:
                    reasons.append("The action has no typed client-controlled resource identifier.")
                if not comparison_links:
                    reasons.append(
                        "No separate controlled-actor/object baseline is available for comparison."
                    )
                add(family, "ACTOR_SWITCH", mutation_action, reasons, observations)
                add(family, "RESOURCE_SWITCH", mutation_action, reasons, observations)

        for action in changing_actions:
            action_observations = _observations_for_actions(instances, {action})
            if _verb(action) not in ONE_TIME_VERBS:
                reason = [
                    "The action lacks one-time, irreversible, or duplicate-business-effect "
                    "semantics required for replay and concurrency mutations."
                ]
                add(family, "REPLAY", action, reason, action_observations)
                add(family, "DUPLICATE_ACTION", action, reason, action_observations)
                add(family, "CONCURRENT_EXECUTION", action, reason, action_observations)
            if _verb(action) in TERMINAL_VERBS:
                explicit_terminal = any(
                    step.action_name == action
                    and any(
                        state.derivation == "EXPLICIT_FIELD"
                        and state.state_after in TERMINAL_STATES
                        for state in step.state_observations
                    )
                    for instance in instances
                    for step in instance.steps
                )
                if not explicit_terminal:
                    add(
                        family,
                        "TERMINAL_STATE_BYPASS",
                        action,
                        ["No explicit terminal response state was observed for this action."],
                        action_observations,
                    )
            if _verb(action) in {"CANCEL", "REFUND", "RETURN", "REVERSE"}:
                rollback_resources = {
                    state.resource_type
                    for instance in instances
                    for step in instance.steps
                    if step.action_name == action
                    for state in step.state_observations
                }
                if len(rollback_resources) < 2:
                    add(
                        family,
                        "PARTIAL_ROLLBACK",
                        action,
                        [
                            "Partial rollback requires at least two linked resource or state "
                            "effects that can be compared."
                        ],
                        action_observations,
                    )

    return sorted(rejections.values(), key=lambda item: item.id)


def _priority(score: LogicScore) -> str:
    total = score.impact + score.likelihood + score.confidence + score.test_readiness
    return "P1" if total >= 16 else "P2" if total >= 11 else "P3"


def _backlog_draft(item: LogicHypothesis) -> dict[str, Any]:
    score = item.score
    total = score.impact + score.likelihood + score.confidence + score.test_readiness
    mutation_dimensions: list[str] = ["WORKFLOW"]
    if item.family == "ACTOR_SWITCH":
        mutation_dimensions.append("ACTOR")
    if item.family in {"RESOURCE_SWITCH", "CROSS_WORKFLOW_TOKEN_REUSE"}:
        mutation_dimensions.append("OBJECT")
    if item.family == "QUANTITY_VALUE_INVARIANT":
        mutation_dimensions.append("VALUE")
    if item.family == "CONCURRENT_EXECUTION":
        mutation_dimensions.extend(["TIME", "CONCURRENCY"])
    return {
        "id": item.id,
        "key": f"business-logic:{item.fingerprint}",
        "title": item.title,
        "kind": item.kind,
        "disposition": "ACTIVE" if item.kind == "SECURITY_HYPOTHESIS" else "NEEDS_RESEARCH",
        "readiness": item.readiness,
        "category": "business_logic",
        "component": item.workflow_family_id,
        "source": {
            "endpoints": item.endpoint_ids,
            "invariants": [item.invariant_id],
            "observations": item.observation_ids,
        },
        "invariant": [item.invariant_id],
        "observations": item.observation_ids,
        "mutation_dimensions": mutation_dimensions,
        "required_state": item.state_evidence_requirements,
        "attacker_capability": [item.mutated_behavior],
        "evidence_status": "INFERRED",
        "hypothesis": item.mutated_behavior,
        "reasoning": (
            f"Canonical behavior: {item.canonical_behavior}. Challenged invariant: "
            f"{item.invariant_statement}"
        ),
        "preconditions": [
            *item.authentication_requirements,
            *item.controlled_resources_required,
        ],
        "expected_secure_behavior": item.expected_secure_outcome,
        "possible_vulnerable_behavior": item.expected_vulnerable_outcome,
        "potential_impact": {
            "confidentiality": "low"
            if item.family in {"ACTOR_SWITCH", "RESOURCE_SWITCH"}
            else "none",
            "integrity": "high" if score.impact >= 4 else "medium",
            "availability": "none",
            "financial": "high"
            if item.safety_classification == SafetyClassification.FINANCIAL_STATE_CHANGE
            else "unknown",
        },
        "evidence_to_collect": item.state_evidence_requirements,
        "eligibility_evidence": item.supporting_evidence,
        "missing_evidence": item.readiness_blockers,
        "generation_rule": {"id": f"BUSINESS_LOGIC_{item.family}", "version": "2"},
        "priority_rationale": [
            contribution.reason for contribution in item.score.breakdown if contribution.points > 0
        ],
        "scores": {
            "impact": score.impact,
            "likelihood": score.likelihood,
            "confidence": score.confidence,
            "testability": score.test_readiness,
            "total": total,
        },
        "priority": _priority(score),
        "status": "NOT_TESTED",
        "safety_notes": [
            f"Safety classification: {item.safety_classification}.",
            "Offline analysis does not confirm backend acceptance.",
            "Human approval and the existing request budget remain mandatory.",
            *item.suppression_reasons,
        ],
        "epistemic_status": item.epistemic_status,
        "logic_details": item.model_dump(mode="json", exclude={"epistemic_status"}),
    }


def _sync_backlog(workspace: WorkspacePaths, hypotheses: list[LogicHypothesis]) -> tuple[str, ...]:
    drafts = [_backlog_draft(item) for item in hypotheses]
    source_fingerprint = stable_fingerprint([item.model_dump(mode="json") for item in hypotheses])
    merge = merge_generated_records(
        workspace.hypotheses,
        "hypotheses",
        "BLH",
        "business-logic-analysis",
        source_fingerprint,
        drafts,
        preserved_fields=("status", "epistemic_status", "notes"),
    )
    merge.document["version"] = 2
    active_keys = {str(item["key"]) for item in drafts}
    records = merge.document.get("hypotheses", [])
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict) or record.get("key") in active_keys:
                continue
            generation = record.get("generation")
            if (
                not isinstance(generation, dict)
                or generation.get("generator") != "business-logic-analysis"
            ):
                continue
            record["kind"] = "RESEARCH_TASK"
            record["disposition"] = "SUPPRESSED_INSUFFICIENT_EVIDENCE"
            record["readiness"] = "RESEARCH_ONLY"
            record["epistemic_status"] = "RESEARCH_TASK"
            record["missing_evidence"] = [
                "The workflow pattern no longer exists in the current passive evidence."
            ]
            normalized = HypothesisRecord.model_validate(record).model_dump(
                mode="json", exclude_none=True
            )
            normalized_generation = normalized["generation"]
            normalized_payload = {
                key: value
                for key, value in normalized.items()
                if key not in {"generation", "status", "epistemic_status", "notes"}
            }
            normalized_generation["generated_checksum"] = stable_fingerprint(normalized_payload)
            record.clear()
            record.update(normalized)
    try:
        store = HypothesisStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(f"Cannot synchronize business-logic hypotheses: {error}") from error
    write_yaml(workspace.hypotheses, store.model_dump(mode="json", exclude_none=True))
    return merge.conflicts


def analyze_business_logic(
    workspace: WorkspacePaths, *, rebuild: bool = True
) -> LogicAnalysisResult:
    """Run deterministic workflow, invariant, and offline hypothesis analysis."""

    if rebuild:
        build_behavior_model(workspace)
    inputs = _load_inputs(workspace)
    invariants = infer_business_invariants(inputs)
    hypotheses = generate_logic_hypotheses(inputs, invariants)
    rejections = generate_mutation_rejections(inputs, invariants, hypotheses)
    previous_statuses: dict[str, EpistemicStatus] = {}
    if workspace.business_logic_hypotheses.is_file():
        try:
            previous = LogicHypothesisStore.model_validate(
                load_yaml(workspace.business_logic_hypotheses)
            )
        except (OSError, ValidationError):
            previous = LogicHypothesisStore()
        previous_statuses = {item.id: item.epistemic_status for item in previous.hypotheses}
    hypotheses = [
        item.model_copy(update={"epistemic_status": previous_statuses[item.id]})
        if previous_statuses.get(item.id)
        in {
            EpistemicStatus.TEST_PLANNED,
            EpistemicStatus.NEEDS_EVIDENCE,
            EpistemicStatus.REJECTED_BY_BACKEND,
            EpistemicStatus.CONFIRMED,
        }
        else item
        for item in hypotheses
    ]
    write_yaml(
        workspace.business_invariants,
        BusinessInvariantStore(business_invariants=invariants).model_dump(mode="json"),
    )
    write_yaml(
        workspace.business_logic_hypotheses,
        LogicHypothesisStore(hypotheses=hypotheses, rejections=rejections).model_dump(mode="json"),
    )
    conflicts = _sync_backlog(workspace, hypotheses)
    return LogicAnalysisResult(
        business_invariants=len(invariants),
        hypotheses=sum(item.kind == "SECURITY_HYPOTHESIS" for item in hypotheses),
        research_tasks=sum(item.kind == "RESEARCH_TASK" for item in hypotheses),
        ready_for_planning=sum(
            item.readiness == HypothesisReadiness.TEST_READY for item in hypotheses
        ),
        rejected_mutations=len(rejections),
        conflicts=conflicts,
    )


def load_business_invariants(workspace: WorkspacePaths) -> BusinessInvariantStore:
    try:
        return BusinessInvariantStore.model_validate(load_yaml(workspace.business_invariants))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load business invariants: {error}") from error


def load_logic_hypotheses(workspace: WorkspacePaths) -> LogicHypothesisStore:
    try:
        return LogicHypothesisStore.model_validate(load_yaml(workspace.business_logic_hypotheses))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load business-logic hypotheses: {error}") from error


def find_logic_hypothesis(workspace: WorkspacePaths, hypothesis_id: str) -> LogicHypothesis:
    wanted = hypothesis_id.upper()
    for item in load_logic_hypotheses(workspace).hypotheses:
        if item.id.upper() == wanted:
            return item
    raise FinsecError(f"Business-logic hypothesis not found: {hypothesis_id}")
