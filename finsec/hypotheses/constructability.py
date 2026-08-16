"""Pure canonical execution-constructability assessment."""

from __future__ import annotations

from dataclasses import dataclass

from finsec.hypotheses.contracts import (
    BlockerStage,
    CapabilityKind,
    ComparisonBaseline,
    ConstructabilityBaseline,
    ConstructabilityBlockerCode,
    DecisionEvidence,
    ExecutionConstructabilityAssessment,
    ExecutionMode,
    ReadinessIssue,
)
from finsec.modeling.liveness import ControlledObjectLiveness, execution_binding_eligible


@dataclass(frozen=True)
class IdentityConstructabilityFact:
    """One actor identity fact without credential material or response content."""

    actor_id: str
    credential_accepted: bool
    scope_validated: bool
    identity_confirmed: bool
    evidence_reference: str


@dataclass(frozen=True)
class ConstructabilityContext:
    """Already-derived immutable facts supplied to the pure decision function."""

    hypothesis_id: str
    category: str
    generation_rule_id: str
    methods: tuple[str, ...]
    state_changing: bool
    runtime_template_satisfied: bool
    runtime_evidence: tuple[DecisionEvidence, ...] = ()
    semantic_target_required: bool = False
    semantic_target_satisfied: bool = True
    semantic_evidence: tuple[DecisionEvidence, ...] = ()
    controlled_baseline_required: bool = False
    controlled_baseline_satisfied: bool = True
    selected_baselines: tuple[ComparisonBaseline, ...] = ()
    cleanup_required: bool = False
    cleanup_satisfied: bool = True
    cleanup_evidence: tuple[DecisionEvidence, ...] = ()
    cleanup_missing: tuple[str, ...] = ()
    cleanup_next_action: str | None = None
    maximum_requests_per_plan: int = 0
    identity_facts: tuple[IdentityConstructabilityFact, ...] = ()


def _execution_mode(context: ConstructabilityContext) -> ExecutionMode:
    rule = context.generation_rule_id
    if rule in {"JWT_ALGORITHM_VALIDATION", "FUNCTION_AUTHORIZATION"}:
        return ExecutionMode.MANUAL_ONLY
    if context.category == "authorization" and rule.startswith("AUTH_OBJECT_ACCESS"):
        return ExecutionMode.OBJECT_SUBSTITUTION
    if context.category == "authentication":
        return ExecutionMode.AUTHENTICATION_COMPARISON
    if context.category == "version_parity":
        return ExecutionMode.VERSION_COMPARISON
    if context.category == "channel_parity":
        return ExecutionMode.CHANNEL_COMPARISON
    return ExecutionMode.MANUAL_ONLY


def _issue(
    code: ConstructabilityBlockerCode,
    capability: CapabilityKind | None,
    summary: str,
    *,
    evidence: tuple[DecisionEvidence, ...] = (),
    next_action: str,
) -> ReadinessIssue:
    return ReadinessIssue(
        code=code.value,
        stage=BlockerStage.PLAN_CONSTRUCTABILITY,
        capability=capability,
        summary=summary,
        evidence=sorted(evidence, key=lambda item: (item.reference, item.detail)),
        next_action=next_action,
    )


def _selected_baselines(
    context: ConstructabilityContext,
) -> list[ConstructabilityBaseline]:
    return [
        ConstructabilityBaseline(
            canonical_reference=item.canonical_reference,
            actor_id=item.actor_id,
            object_reference=item.object_reference,
            liveness=item.liveness,
            execution_eligible=execution_binding_eligible(item.liveness),
            evidence_references=sorted(
                {
                    *item.baseline_ids,
                    *item.endpoint_ids,
                    *item.supporting_relationship_ids,
                    *item.observation_ids,
                    *item.liveness_evidence_references,
                }
            ),
        )
        for item in context.selected_baselines
    ]


def _manual_only_issue(
    context: ConstructabilityContext,
    mode: ExecutionMode,
) -> ReadinessIssue:
    state_changing_object = mode == ExecutionMode.OBJECT_SUBSTITUTION and context.state_changing
    unsupported_object_method = mode == ExecutionMode.OBJECT_SUBSTITUTION and any(
        method not in {"GET", "HEAD"} for method in context.methods
    )
    if state_changing_object or unsupported_object_method:
        return _issue(
            ConstructabilityBlockerCode.UNSUPPORTED_EXECUTION_TEMPLATE,
            CapabilityKind.REQUEST_TEMPLATE,
            (
                "The endpoint is state-changing and has no supported automated execution "
                "template. Automated object substitution currently supports only read-only "
                "GET and HEAD requests."
            ),
            next_action=(
                "Keep the hypothesis in manual review. Use fresh disposable researcher-owned "
                "resources and obtain approval for a cleanup or recreation procedure before "
                "any manual test."
            ),
        )
    return _issue(
        ConstructabilityBlockerCode.UNSUPPORTED_EXECUTION_TEMPLATE,
        CapabilityKind.REQUEST_TEMPLATE,
        "The hypothesis has no supported automated execution template in the bounded runner.",
        next_action=(
            "Retain the security question for manual review without constructing or sending "
            "a request."
        ),
    )


def assess_execution_constructability(
    context: ConstructabilityContext,
) -> ExecutionConstructabilityAssessment:
    """Return one deterministic local decision without file or network access."""

    mode = _execution_mode(context)
    blockers: list[ReadinessIssue] = []
    baselines = _selected_baselines(context)
    method_supported = bool(context.methods) and all(
        method in {"GET", "HEAD"} for method in context.methods
    )
    automated_mode = mode not in {ExecutionMode.MANUAL_ONLY, ExecutionMode.UNSUPPORTED}
    if not automated_mode or not method_supported or context.state_changing:
        blockers.append(_manual_only_issue(context, mode))

    if not context.runtime_template_satisfied:
        blockers.append(
            _issue(
                ConstructabilityBlockerCode.MISSING_RUNTIME_TEMPLATE,
                CapabilityKind.REQUEST_TEMPLATE,
                "No exact redacted runtime request can be reconstructed for the bounded test.",
                evidence=context.runtime_evidence,
                next_action=(
                    "Capture one authorized runtime request matching the exact method, route, "
                    "actor, and mutation input."
                ),
            )
        )
    if context.semantic_target_required and not context.semantic_target_satisfied:
        blockers.append(
            _issue(
                ConstructabilityBlockerCode.MISSING_SEMANTIC_TARGET,
                CapabilityKind.SEMANTIC_TARGET,
                "The exact ownership-relevant mutation target is not constructable.",
                evidence=context.semantic_evidence,
                next_action=(
                    "Collect object lifecycle or explicit owner evidence for the exact scalar "
                    "target; do not guess a replacement field."
                ),
            )
        )
    if context.controlled_baseline_required and not context.controlled_baseline_satisfied:
        blockers.append(
            _issue(
                ConstructabilityBlockerCode.MISSING_CONTROLLED_BASELINE,
                CapabilityKind.BASELINE,
                "No controlled ownership baseline exists for the required comparison context.",
                next_action=(
                    "Capture the missing actor/object ownership evidence for this workflow family."
                ),
            )
        )

    if context.controlled_baseline_satisfied and baselines:
        stale_states = {
            ControlledObjectLiveness.DELETED,
            ControlledObjectLiveness.HISTORICAL_ONLY,
        }
        if any(item.liveness in stale_states for item in baselines):
            blockers.append(
                _issue(
                    ConstructabilityBlockerCode.STALE_EXECUTION_BASELINE,
                    CapabilityKind.BASELINE,
                    (
                        "Historical ownership evidence exists, but one or more selected objects "
                        "are deleted or historical-only and cannot be reused for execution."
                    ),
                    next_action=(
                        "Observe fresh disposable researcher-owned objects as LIVE, or keep the "
                        "hypothesis manual-only."
                    ),
                )
            )
        if any(item.liveness == ControlledObjectLiveness.UNKNOWN for item in baselines):
            blockers.append(
                _issue(
                    ConstructabilityBlockerCode.MISSING_LIVE_CONTROLLED_OBJECT,
                    CapabilityKind.BASELINE,
                    (
                        "Controlled ownership evidence exists, but authoritative current "
                        "liveness is unknown for one or more execution bindings."
                    ),
                    next_action=(
                        "Use a safe authoritative read or supported setup recipe to establish "
                        "a fresh live controlled object."
                    ),
                )
            )

    if context.cleanup_required and not context.cleanup_satisfied:
        blockers.append(
            _issue(
                ConstructabilityBlockerCode.MISSING_CLEANUP,
                CapabilityKind.CLEANUP,
                (
                    "; ".join(context.cleanup_missing)
                    if context.cleanup_missing
                    else (
                        "State-changing testing requires reviewed cleanup or disposable "
                        "resources."
                    )
                ),
                evidence=context.cleanup_evidence,
                next_action=context.cleanup_next_action
                or "Define a reviewed cleanup, rollback, or disposable-resource procedure.",
            )
        )

    identity_required = bool(context.identity_facts)
    identity_confirmed = identity_required and all(
        item.credential_accepted and item.scope_validated and item.identity_confirmed
        for item in context.identity_facts
    )
    if identity_required and not identity_confirmed:
        accepted = [item for item in context.identity_facts if item.credential_accepted]
        accepted_but_unconfirmed = [
            item
            for item in accepted
            if item.scope_validated and not item.identity_confirmed
        ]
        blockers.append(
            _issue(
                ConstructabilityBlockerCode.MISSING_IDENTITY_CONFIRMATION,
                CapabilityKind.ACTOR,
                (
                    "Actor credential is accepted, but identity is not confirmed."
                    if accepted_but_unconfirmed
                    else (
                        "Actor identity is not confirmed; credential acceptance or scope "
                        "validation is also incomplete."
                    )
                ),
                evidence=tuple(
                    DecisionEvidence(
                        reference=item.evidence_reference,
                        source="ACTOR_AUTHENTICATION",
                        detail=(
                            f"Credential accepted={item.credential_accepted}; scope "
                            f"validated={item.scope_validated}; identity "
                            f"confirmed={item.identity_confirmed} for {item.actor_id}."
                        ),
                    )
                    for item in context.identity_facts
                ),
                next_action=(
                    "Configure and satisfy an actor-specific structured identity assertion on "
                    "a safe in-scope read-only endpoint."
                ),
            )
        )

    core_template_exists = (
        automated_mode
        and method_supported
        and not context.state_changing
        and context.runtime_template_satisfied
        and (not context.semantic_target_required or context.semantic_target_satisfied)
        and (
            not context.controlled_baseline_required
            or (
                context.controlled_baseline_satisfied
                and bool(baselines)
                and all(item.execution_eligible for item in baselines)
            )
        )
    )
    request_count = 2 if core_template_exists else None
    if request_count is not None and request_count > context.maximum_requests_per_plan:
        blockers.append(
            _issue(
                ConstructabilityBlockerCode.MISSING_BUDGET,
                CapabilityKind.BUDGET,
                (
                    f"The concrete template requires {request_count} request(s), but target "
                    f"policy permits {context.maximum_requests_per_plan}."
                ),
                next_action=(
                    "Review target.testing.maximum_requests_per_plan without enabling active "
                    "execution or changing policy automatically."
                ),
            )
        )

    blockers = list({(item.code, item.summary): item for item in blockers}.values())
    blocker_order = {
        code.value: index for index, code in enumerate(ConstructabilityBlockerCode)
    }
    blockers.sort(key=lambda item: (blocker_order.get(item.code, len(blocker_order)), item.summary))
    primary = blockers[0] if blockers else None
    evidence_references = sorted(
        {
            evidence.reference
            for item in blockers
            for evidence in item.evidence
        }
        | {
            reference
            for baseline in baselines
            for reference in baseline.evidence_references
        }
    )
    return ExecutionConstructabilityAssessment(
        supported=not blockers and request_count is not None,
        execution_mode=mode,
        blocker_code=(
            ConstructabilityBlockerCode(primary.code) if primary is not None else None
        ),
        blocker_stage=primary.stage if primary is not None else None,
        summary=(
            primary.summary
            if primary is not None
            else "A concrete read-only bounded execution template is constructable."
        ),
        evidence_references=evidence_references,
        missing_requirements=sorted({item.summary for item in blockers}),
        next_action=(
            primary.next_action
            if primary is not None
            else "Review the exact structured requests before requesting human approval."
        ),
        blockers=blockers,
        baselines=baselines,
        request_count=request_count,
        identity_confirmation_required=identity_required,
        identity_confirmed=identity_confirmed,
    )
