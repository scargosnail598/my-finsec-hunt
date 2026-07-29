"""Safety-gated Phase 3 test planning; this module never executes requests."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from finsec.auth.service import actor_preflight
from finsec.config.models import TargetDocument
from finsec.config.scope import hosts_are_covered
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.hypotheses.domain import HypothesisRecord
from finsec.hypotheses.generator import find_hypothesis, update_hypothesis_status
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
    if hypothesis.category == "authorization":
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
    execution_templates = build_execution_templates(
        workspace,
        target,
        hypothesis,
        source_endpoints,
        observations,
    )
    owner = execution_templates.object_owner or owner
    actor = execution_templates.actor or actor
    plan_authentication: list[dict[str, Any]] = []
    resource_name = (
        endpoint.resource.type if endpoint is not None else hypothesis.component.split(" / ", 1)[0]
    )
    financial = resource_name.lower() in FINANCIAL_RESOURCES and any(
        item.state_change for item in source_endpoints
    )
    destructive = any(
        item.method == "DELETE"
        or any(action in item.path.lower() for action in ("/cancel", "/refund", "/reverse"))
        for item in source_endpoints
    )
    concurrency = False
    request_budget = execution_templates.execution.request_budget or 2
    requires_two_accounts = hypothesis.category == "authorization"
    blockers: list[str] = []
    endpoint_hosts = {host for item in source_endpoints for host in item.hosts}
    if not hypothesis.source.endpoints:
        blockers.append("The hypothesis has no source endpoint for scope validation.")
    elif len(source_endpoints) != len(set(hypothesis.source.endpoints)):
        blockers.append("One or more hypothesis source endpoints cannot be resolved.")
    if not target.scope.hosts:
        blockers.append("No in-scope hosts are recorded in target.yaml.")
    elif endpoint_hosts and not hosts_are_covered(endpoint_hosts, target.scope.hosts):
        blockers.append("The source endpoint host is not fully covered by target.yaml scope.")
    if requires_two_accounts and len(researcher_accounts) < 2:
        blockers.append("Two researcher-controlled accounts are required for this boundary test.")
    elif not requires_two_accounts and not researcher_accounts:
        blockers.append("A researcher-controlled account is not configured in target.yaml.")
    if hypothesis.category == "state_integrity":
        resource = next((item for item in resources.resources if item.name == resource_name), None)
        if resource is None or not resource.states:
            blockers.append(
                "No researcher-confirmed lifecycle states are recorded for this resource."
            )
    if destructive and (
        not target.testing.destructive_testing or not target.restrictions.destructive_actions
    ):
        blockers.append("The operation may be destructive and target policy does not permit it.")
    if financial and target.testing.production:
        blockers.append(
            "Financial-effect testing against production requires explicit policy approval."
        )

    request_actors = sorted({item.actor for item in execution_templates.requests})
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
            blockers.append(f"{actor_id} authentication is unusable: {detail}")
        if authentication.profile_ref is not None:
            plan_authentication.append(
                {
                    "actor": actor_id,
                    "credential_profile_ref": authentication.profile_ref,
                    "required_status": "READY",
                    "context_fingerprint": authentication.context_fingerprint,
                }
            )

    if blockers and execution_templates.execution.supported:
        execution_templates.execution.supported = False
        execution_templates.execution.blockers.extend(
            item for item in blockers if item not in execution_templates.execution.blockers
        )

    affects_external = (
        requires_two_accounts and len(researcher_accounts) < 2
    ) or not researcher_accounts
    decision = "BLOCKED" if blockers else "REQUIRES_HUMAN_APPROVAL"
    setup, actions, assertions = _steps(hypothesis, endpoint, owner, actor)
    return {
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
        "human_approval_required": True,
        "execution_default": "DO_NOT_EXECUTE",
        "approval_status": "NOT_REQUESTED",
        "status": "BLOCKED" if blockers else "READY_FOR_REVIEW",
    }


def generate_plan(workspace: WorkspacePaths, hypothesis_id: str) -> PlanResult:
    """Generate a policy-checked plan and never execute it."""

    target, observations, endpoints, resources, hypothesis = _load_inputs(workspace, hypothesis_id)
    if hypothesis.kind != "SECURITY_HYPOTHESIS" or hypothesis.disposition != "ACTIVE":
        raise FinsecError(
            f"{hypothesis.id} is a research or suppressed candidate, not an active security "
            "hypothesis. Collect the missing evidence and regenerate first."
        )
    draft = _draft(workspace, target, observations, endpoints, resources, hypothesis)
    fingerprint = stable_fingerprint(
        {
            "target": target.model_dump(mode="json"),
            "observations": observations.model_dump(mode="json", exclude_none=True),
            "endpoints": endpoints.model_dump(mode="json", exclude_none=True),
            "resources": resources.model_dump(mode="json", exclude_none=True),
            "hypothesis": hypothesis.model_dump(mode="json", exclude_none=True),
        }
    )
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
