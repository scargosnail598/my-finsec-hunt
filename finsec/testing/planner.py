"""Safety-gated test planning; this module never executes requests."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from finsec.auth.service import actor_preflight
from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.hypotheses.contracts import HypothesisReadinessAssessment
from finsec.hypotheses.domain import HypothesisRecord
from finsec.hypotheses.generator import find_hypothesis, update_hypothesis_status
from finsec.hypotheses.readiness import assess_record_readiness, readiness_blocking_issues
from finsec.hypotheses.semantics import assess_claim_strength, assess_domain_intent
from finsec.modeling.domain import ResourceStore
from finsec.modeling.invariants import FINANCIAL_RESOURCES
from finsec.modeling.merge import merge_generated_records, stable_fingerprint
from finsec.modeling.models import Endpoint, EndpointStore, ObservationStore
from finsec.testing.domain import TestPlanRecord, TestPlanStore
from finsec.testing.templates import build_execution_templates
from finsec.utils.yaml_store import load_yaml, write_yaml


@dataclass(frozen=True)
class PlanResult:
    """Generated plan plus preservation information."""

    plan: TestPlanRecord
    path: Path
    conflict: bool


@dataclass(frozen=True)
class PlanAlignment:
    """Read-only agreement check between persisted readiness and planner constructability."""

    readiness: HypothesisReadinessAssessment
    plan_status: str
    agrees: bool
    violation: str | None


def plan_source_fingerprint(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: EndpointStore,
    resources: ResourceStore,
    hypothesis: HypothesisRecord,
) -> str:
    """Fingerprint deterministic plan inputs while excluding hypothesis lifecycle annotations."""

    target_payload = target.model_dump(mode="json")
    for account in target_payload.get("accounts", []):
        authentication = account.get("authentication")
        if not isinstance(authentication, dict):
            continue
        authentication.pop("expiration", None)
        authentication.pop("status", None)
        authentication.pop("credential_accepted_at", None)
        authentication.pop("scope_validated_at", None)
        identity = authentication.get("identity")
        if isinstance(identity, dict):
            identity.pop("confirmed_at", None)
        source = authentication.get("source")
        if isinstance(source, dict):
            authentication["source"] = {"type": source.get("type")}
    hypothesis_payload = hypothesis.model_dump(mode="json", exclude_none=True)
    for field in ("status", "epistemic_status", "notes", "generation"):
        hypothesis_payload.pop(field, None)
    logic_details = hypothesis_payload.get("logic_details")
    if isinstance(logic_details, dict):
        logic_details.pop("epistemic_status", None)
    return stable_fingerprint(
        {
            "target": target_payload,
            "observations": observations.model_dump(mode="json", exclude_none=True),
            "endpoints": endpoints.model_dump(mode="json", exclude_none=True),
            "resources": resources.model_dump(mode="json", exclude_none=True),
            "hypothesis": hypothesis_payload,
        }
    )


def _load_inputs(
    workspace: WorkspacePaths, hypothesis_id: str
) -> tuple[TargetDocument, ObservationStore, EndpointStore, ResourceStore, HypothesisRecord]:
    try:
        target = TargetDocument.model_validate(load_yaml(workspace.target))
        observations = ObservationStore.model_validate(load_yaml(workspace.observations))
        endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))
        resources = ResourceStore.model_validate(load_yaml(workspace.resources))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load test-plan inputs: {error}") from error
    return target, observations, endpoints, resources, find_hypothesis(workspace, hypothesis_id)


def _endpoints(hypothesis: HypothesisRecord, endpoints: EndpointStore) -> list[Endpoint]:
    """Resolve every source endpoint so differential plans get complete scope checks."""

    by_id = {item.id: item for item in endpoints.endpoints}
    return [by_id[item] for item in hypothesis.source.endpoints if item in by_id]


def _steps(
    hypothesis: HypothesisRecord, endpoint: Endpoint | None, owner: str | None, actor: str | None
) -> tuple[list[str], list[str], list[str]]:
    operation = (
        f"{endpoint.method} {endpoint.path}" if endpoint is not None else "the observed operation"
    )
    jwt_algorithm_validation = hypothesis.generation_rule.get("id") == "JWT_ALGORITHM_VALIDATION"
    function_authorization = hypothesis.generation_rule.get("id") == "FUNCTION_AUTHORIZATION"
    if hypothesis.category == "business_logic":
        details = hypothesis.logic_details or {}
        canonical = str(details.get("canonical_behavior", "the observed canonical workflow"))
        mutated = str(details.get("mutated_behavior", hypothesis.hypothesis))
        state_requirements = details.get("state_evidence_requirements", [])
        requirements = (
            [str(item) for item in state_requirements]
            if isinstance(state_requirements, list)
            else []
        )
        setup = [
            "Prepare only researcher-controlled actors and resources.",
            f"Reproduce the safe canonical baseline: {canonical}.",
            *requirements,
        ]
        actions = [
            f"After explicit approval, apply only this workflow mutation: {mutated}.",
            "Stop at the approved request budget and do not add retries or concurrency.",
            "Collect immediate and delayed authoritative state for every affected resource.",
        ]
        assertions = [
            hypothesis.expected_secure_behavior,
            "A response status alone is not proof; authoritative state must remain secure.",
        ]
    elif jwt_algorithm_validation:
        setup = [
            f"Authenticate as {actor or 'the researcher-controlled account'}.",
            f"Capture one successful signed-JWT baseline for {operation} with token material "
            "redacted from storage.",
        ]
        actions = [
            "After explicit approval, change only the JWT algorithm to the configured rejected "
            "value and remove the signature.",
            "Preserve the researcher-controlled subject and do not add privileged claims.",
            "Submit exactly one unsigned-token request and perform one safe identity check.",
        ]
        assertions = [
            "The unsigned JWT is rejected and no authenticated identity or session is accepted.",
        ]
    elif function_authorization:
        setup = [
            f"Record the configured role for {actor or 'the researcher-controlled account'}.",
            "Record the authoritative function-to-role policy and initial resource state.",
        ]
        actions = [
            f"Review the existing successful {operation} observation without replaying it.",
            "Verify whether the role was outside the configured allowed-role set.",
            "Verify the resulting resource state using an independent safe read.",
        ]
        assertions = [
            "A non-allowed role must not create or change privileged resource state.",
        ]
    elif hypothesis.category == "authorization":
        setup = [
            f"{owner or 'Researcher Account A'} creates or selects the test object.",
            "Record object ownership and initial state.",
        ]
        if endpoint is not None and endpoint.authentication.required:
            setup.append(f"Authenticate separately as {actor or 'Researcher Account B'}.")
        else:
            setup.append(
                f"Use the passive baseline labeled {actor or 'Researcher Account B'}; "
                "no request credential was observed."
            )
        actions = [
            f"Copy the successful {operation} request for Account B's own object when available.",
            "Replace only the object identifier with Account A's researcher-owned identifier.",
            "Submit exactly one modified request.",
        ]
        assertions = [
            "The modified request is rejected without exposing Account A data.",
        ]
        if endpoint is not None and endpoint.state_change:
            actions.append("Retrieve the object again as Account A to verify state and ownership.")
            assertions.append("Account A's object state remains unchanged.")
    elif hypothesis.category == "authentication":
        setup = [
            f"Authenticate as {actor or 'the researcher-controlled account'}.",
            f"Capture one successful {operation} baseline with credentials redacted in storage.",
        ]
        actions = [
            "Copy the baseline and remove only the observed authentication credential.",
            "Submit exactly one unauthenticated control request.",
        ]
        assertions = [
            "The control request is rejected without protected data or state change.",
        ]
    elif hypothesis.category == "version_parity":
        setup = ["Prepare equivalent researcher-owned data accepted by both in-scope API versions."]
        actions = [
            "Send one redacted, semantically equivalent request to each observed version.",
            "Compare only authentication, authorization, validation, and resulting state.",
        ]
        assertions = ["Both versions enforce an equivalent security boundary."]
    elif hypothesis.category == "channel_parity":
        setup = [
            "Prepare equivalent researcher-owned data accepted through both in-scope channels."
        ]
        actions = [
            "Send one redacted, semantically equivalent request through each observed channel.",
            "Compare only authentication, authorization, validation, and resulting state.",
        ]
        assertions = ["Both channels enforce an equivalent security boundary."]
    elif hypothesis.category == "replay":
        setup = [
            "Prepare the smallest permitted, reversible, researcher-owned operation.",
            "Record authoritative accounting state before the operation.",
        ]
        actions = [
            f"Submit one valid {operation} request.",
            "Replay the identical logical request once; do not add concurrency or further retries.",
            "Retrieve authoritative accounting state.",
        ]
        assertions = ["At most one successful financial effect is recorded."]
    elif hypothesis.category == "value_validation":
        setup = ["Select a documented, non-dangerous boundary value on a researcher-owned object."]
        actions = [
            "Change exactly one value field in a copy of the baseline request.",
            "Submit exactly one request.",
        ]
        assertions = ["The server rejects invalid value combinations without state change."]
    else:
        setup = [
            "Document the intended lifecycle from direct evidence.",
            "Prepare a researcher-owned object in a reversible state.",
        ]
        actions = [
            f"Submit {operation} once from the researcher-confirmed disallowed state.",
            "Retrieve the object using an independent read operation.",
        ]
        assertions = ["The server rejects the forbidden transition and preserves state."]
    return setup, actions, assertions


def _readiness_assessment(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: EndpointStore,
    resources: ResourceStore,
    hypothesis: HypothesisRecord,
) -> HypothesisReadinessAssessment:
    selected = _endpoints(hypothesis, endpoints)
    intent = assess_domain_intent(
        target,
        selected,
        category=hypothesis.category,
        generation_rule_id=hypothesis.generation_rule.get("id", ""),
        logic_details=hypothesis.logic_details,
        mutation_target=hypothesis.mutation_target,
    )
    claim = assess_claim_strength(
        generation_rule_id=hypothesis.generation_rule.get("id", ""),
        category=hypothesis.category,
        intent=intent,
        eligibility_evidence=hypothesis.eligibility_evidence,
    )
    return assess_record_readiness(
        target,
        observations,
        endpoints.endpoints,
        resources,
        hypothesis,
        intent,
        claim,
    )


def _draft(
    workspace: WorkspacePaths,
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: EndpointStore,
    resources: ResourceStore,
    hypothesis: HypothesisRecord,
) -> dict[str, Any]:
    source_endpoints = _endpoints(hypothesis, endpoints)
    endpoint = source_endpoints[0] if source_endpoints else None
    researcher_accounts = sorted(
        account.id for account in target.accounts if account.ownership == "researcher"
    )
    owner = researcher_accounts[0] if researcher_accounts else None
    actor = researcher_accounts[1] if len(researcher_accounts) > 1 else owner
    assessment = _readiness_assessment(target, observations, endpoints, resources, hypothesis)
    execution_templates = build_execution_templates(
        workspace,
        target,
        hypothesis,
        source_endpoints,
        observations,
        assessment.constructability,
    )
    owner = execution_templates.object_owner or owner
    actor = execution_templates.actor or actor
    plan_authentication: list[dict[str, Any]] = []
    resource_name = (
        endpoint.resource.type if endpoint is not None else hypothesis.component.split(" / ", 1)[0]
    )
    logic_details = hypothesis.logic_details or {}
    logic_safety = str(logic_details.get("safety_classification", ""))
    financial = logic_safety == "FINANCIAL_STATE_CHANGE" or (
        resource_name.lower() in FINANCIAL_RESOURCES
        and any(item.state_change for item in source_endpoints)
    )
    destructive = logic_safety == "DESTRUCTIVE" or any(
        item.method == "DELETE"
        or any(action in item.path.lower() for action in ("/cancel", "/refund", "/reverse"))
        for item in source_endpoints
    )
    concurrency = logic_safety == "CONCURRENT"
    request_budget = assessment.constructability.request_count or 0
    function_authorization = hypothesis.generation_rule.get("id") == "FUNCTION_AUTHORIZATION"
    requires_two_accounts = hypothesis.category == "authorization" and not function_authorization
    planning_issues = readiness_blocking_issues(assessment)
    blockers = [item.summary for item in planning_issues]
    execution_blockers = list(execution_templates.execution.blockers)
    if destructive and (
        not target.testing.destructive_testing or not target.restrictions.destructive_actions
    ):
        execution_blockers.append(
            "The operation may be destructive and target execution policy does not permit it."
        )
    if financial and target.testing.production:
        execution_blockers.append(
            "Financial-effect testing against production requires explicit policy approval."
        )

    request_actor_ids = {item.actor for item in execution_templates.requests}
    if not request_actor_ids:
        request_actor_ids = {item.actor_id for item in assessment.constructability.baselines}
    request_actors = sorted(request_actor_ids)
    for actor_id in request_actors:
        configured = next((item for item in target.accounts if item.id == actor_id), None)
        authentication = configured.authentication if configured is not None else None
        if authentication is None:
            continue
        if authentication.auth_type == "none":
            continue
        preflight = actor_preflight(
            workspace,
            actor_id,
            request_count=len(execution_templates.requests),
            request_hosts={
                item.host for item in execution_templates.requests if item.actor == actor_id
            },
        )
        if preflight.result == "BLOCKED_BY_AUTH":
            detail = "; ".join(preflight.reasons) or f"authentication status is {preflight.status}"
            execution_blockers.append(f"{actor_id} authentication is unusable: {detail}")
        if authentication.profile_ref is not None:
            plan_authentication.append(
                {
                    "actor": actor_id,
                    "credential_profile_ref": authentication.profile_ref,
                    "required_status": "READY",
                    "context_fingerprint": authentication.context_fingerprint,
                }
            )

    execution_blockers = list(dict.fromkeys(execution_blockers))
    if execution_blockers:
        execution_templates.execution.supported = False
        execution_templates.execution.blockers = execution_blockers

    affects_external = (
        requires_two_accounts and len(researcher_accounts) < 2
    ) or not researcher_accounts
    decision = "BLOCKED" if blockers else "REQUIRES_HUMAN_APPROVAL"
    plan_status = "READY_FOR_REVIEW" if not blockers else "BLOCKED"
    readiness_consistent = hypothesis.readiness == assessment.readiness and not (
        hypothesis.readiness == "TEST_READY" and plan_status == "BLOCKED"
    )
    violation = None
    if not readiness_consistent:
        violation = (
            f"Persisted readiness is {hypothesis.readiness}, canonical readiness is "
            f"{assessment.readiness}, and planner status is {plan_status}."
        )
    setup, actions, assertions = _steps(hypothesis, endpoint, owner, actor)
    draft: dict[str, Any] = {
        "key": f"plan:{hypothesis.id}",
        "hypothesis_id": hypothesis.id,
        "purpose": f"Safely evaluate {hypothesis.title} without expanding beyond minimum proof.",
        "risk": {
            "destructive": destructive,
            "financial": financial,
            "affects_external_user": affects_external,
            "concurrency": concurrency,
            "request_budget": request_budget,
            "decision": decision,
            "reasons": blockers
            or ["Static policy checks pass; explicit human approval is still mandatory."],
        },
        "accounts": {"object_owner": owner, "actor": actor},
        "preconditions": hypothesis.preconditions,
        "setup": setup,
        "actions": actions,
        "secure_assertions": assertions,
        "interesting_behavior": [
            hypothesis.possible_vulnerable_behavior,
            "Unexpected status codes alone are not proof; verify data or authoritative state.",
        ],
        "evidence_to_capture": hypothesis.evidence_to_collect,
        "stop_conditions": [
            "Any unrelated user data becomes visible.",
            "Any financial movement exceeds the explicitly approved test value.",
            "The operation affects an external user or irreversible state.",
            "Rate limiting, instability, or an unexpected side effect appears.",
            "The minimum evidence needed to classify behavior has been collected.",
        ],
        "cleanup": [
            "Restore or cancel only researcher-owned reversible test state when permitted.",
            "Store only redacted evidence and keep credentials outside the workspace.",
        ],
        "requests": [
            item.model_dump(mode="json", exclude_none=True) for item in execution_templates.requests
        ],
        "authentication": plan_authentication,
        "execution": execution_templates.execution.model_dump(mode="json"),
        "mutation_target": hypothesis.mutation_target.model_dump(mode="json", exclude_none=True),
        "readiness_assessment": assessment.model_dump(mode="json", exclude_none=True),
        "planning_blockers": [
            item.model_dump(mode="json", exclude_none=True) for item in planning_issues
        ],
        "readiness_consistent": readiness_consistent,
        "human_approval_required": True,
        "execution_default": "DO_NOT_EXECUTE",
        "approval_status": "NOT_REQUESTED",
        "status": plan_status,
    }
    if violation is not None:
        draft["readiness_invariant_violation"] = violation
    return draft


def inspect_plan_alignment(workspace: WorkspacePaths, hypothesis_id: str) -> PlanAlignment:
    """Assess planner/readiness agreement without writing a plan or lifecycle state."""

    target, observations, endpoints, resources, hypothesis = _load_inputs(workspace, hypothesis_id)
    return inspect_plan_alignment_from_inputs(
        target,
        observations,
        endpoints,
        resources,
        hypothesis,
    )


def inspect_plan_alignment_from_inputs(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: EndpointStore,
    resources: ResourceStore,
    hypothesis: HypothesisRecord,
) -> PlanAlignment:
    """Assess planner/readiness agreement from already-loaded immutable inputs."""

    assessment = _readiness_assessment(target, observations, endpoints, resources, hypothesis)
    plan_status = "BLOCKED" if readiness_blocking_issues(assessment) else "READY_FOR_REVIEW"
    readiness_consistent = hypothesis.readiness == assessment.readiness and not (
        hypothesis.readiness == "TEST_READY" and plan_status == "BLOCKED"
    )
    violation = None
    if not readiness_consistent:
        violation = (
            f"Persisted readiness is {hypothesis.readiness}, canonical readiness is "
            f"{assessment.readiness}, and planner status is {plan_status}."
        )
    return PlanAlignment(
        readiness=assessment,
        plan_status=plan_status,
        agrees=readiness_consistent,
        violation=violation,
    )


def generate_plan(workspace: WorkspacePaths, hypothesis_id: str) -> PlanResult:
    """Generate a policy-checked plan and never execute it."""

    target, observations, endpoints, resources, hypothesis = _load_inputs(workspace, hypothesis_id)
    if hypothesis.kind != "SECURITY_HYPOTHESIS" or hypothesis.disposition != "ACTIVE":
        raise FinsecError(
            f"{hypothesis.id} is a research or suppressed candidate, not an active security "
            "hypothesis. Collect the missing evidence and regenerate first."
        )
    draft = _draft(workspace, target, observations, endpoints, resources, hypothesis)
    fingerprint = plan_source_fingerprint(target, observations, endpoints, resources, hypothesis)
    merge = merge_generated_records(
        workspace.test_plans,
        "plans",
        "TEST",
        "phase3-test-planner",
        fingerprint,
        [draft],
        preserved_fields=("approval_status", "approval", "notes"),
    )
    try:
        store = TestPlanStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(f"Cannot validate test plans: {error}") from error
    write_yaml(workspace.test_plans, store.model_dump(mode="json", exclude_none=True))
    plan = next(item for item in store.plans if item.hypothesis_id == hypothesis.id)
    update_hypothesis_status(workspace, hypothesis.id, "TEST_PLANNED")
    return PlanResult(plan, workspace.test_plans, f"plan:{hypothesis.id}" in merge.conflicts)
