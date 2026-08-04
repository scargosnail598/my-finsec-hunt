"""Deterministic skeptical validation; ambiguity never becomes CONFIRMED."""

import hashlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from finsec.config.models import TargetDocument
from finsec.config.scope import hosts_are_covered
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.evidence.domain import (
    EvidenceAssessment,
    EvidenceKind,
    EvidenceMetadata,
    FindingNarrative,
)
from finsec.evidence.manager import load_evidence
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStatus
from finsec.hypotheses.generator import find_hypothesis, update_hypothesis_status
from finsec.modeling.merge import merge_generated_records
from finsec.modeling.models import Endpoint, EndpointStore
from finsec.readiness.provenance import validation_source_fingerprint
from finsec.testing.domain import TestPlanRecord, TestPlanStore
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.validation.domain import (
    ValidationCheck,
    ValidationDisposition,
    ValidationRecord,
    ValidationStore,
)

REPORT_FIELDS = (
    "report_title",
    "summary",
    "root_cause",
    "affected_boundary",
    "actual_behavior",
    "technical_impact",
    "business_impact",
    "realistic_attack_scenario",
    "severity_rationale",
    "remediation",
)


@dataclass(frozen=True)
class ValidationResult:
    """Validation outcome plus merge-conflict information."""

    validation: ValidationRecord
    path: Path
    conflict: bool


def _load_inputs(
    workspace: WorkspacePaths, hypothesis_id: str
) -> tuple[TargetDocument, EndpointStore, HypothesisRecord, EvidenceMetadata]:
    try:
        target = TargetDocument.model_validate(load_yaml(workspace.target))
        endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load validation inputs: {error}") from error
    hypothesis = find_hypothesis(workspace, hypothesis_id)
    evidence = load_evidence(workspace, hypothesis.id)
    return target, endpoints, hypothesis, evidence


def _plan(workspace: WorkspacePaths, hypothesis_id: str) -> TestPlanRecord | None:
    if not workspace.test_plans.is_file():
        return None
    try:
        store = TestPlanStore.model_validate(load_yaml(workspace.test_plans))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load test plans: {error}") from error
    return next((item for item in store.plans if item.hypothesis_id == hypothesis_id), None)


def _source_endpoints(hypothesis: HypothesisRecord, endpoints: EndpointStore) -> list[Endpoint]:
    by_id = {item.id: item for item in endpoints.endpoints}
    return [by_id[item] for item in hypothesis.source.endpoints if item in by_id]


def _assessment_check(
    check_id: str,
    question: str,
    value: bool | None,
    expected: bool,
) -> ValidationCheck:
    if value is None:
        return ValidationCheck(
            id=check_id,
            question=question,
            result="MISSING",
            detail="Researcher assessment is not recorded.",
        )
    if value is expected:
        return ValidationCheck(
            id=check_id,
            question=question,
            result="PASS",
            detail=f"Researcher recorded {value}.",
        )
    return ValidationCheck(
        id=check_id,
        question=question,
        result="FAIL",
        detail=f"Researcher recorded {value}; expected {expected} for confirmation.",
    )


def _artifact_integrity(root: Path, evidence: EvidenceMetadata) -> tuple[bool, list[str]]:
    problems: list[str] = []
    for artifact in evidence.artifacts:
        path = (root / artifact.path).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError:
            problems.append(f"{artifact.id} escapes the evidence directory.")
            continue
        if not path.is_file():
            problems.append(f"{artifact.id} file is missing.")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != artifact.sha256:
            problems.append(f"{artifact.id} checksum does not match metadata.")
    return not problems, problems


def _artifact_checks(
    workspace: WorkspacePaths,
    hypothesis: HypothesisRecord,
    evidence: EvidenceMetadata,
    endpoints: list[Endpoint],
) -> tuple[list[ValidationCheck], list[str]]:
    checks: list[ValidationCheck] = []
    missing: list[str] = []
    integrity, problems = _artifact_integrity(workspace.evidence_for(hypothesis.id), evidence)
    checks.append(
        ValidationCheck(
            id="EVIDENCE-INTEGRITY",
            question="Do indexed evidence files exist with matching checksums?",
            result="PASS" if integrity else "FAIL",
            detail="All artifact checksums match." if integrity else " ".join(problems),
        )
    )
    counts = Counter(item.kind for item in evidence.artifacts)
    minimum = 2 if hypothesis.category in {"version_parity", "channel_parity"} else 1
    exchange_kinds: tuple[EvidenceKind, ...] = ("request", "response")
    for kind in exchange_kinds:
        if counts[kind] >= minimum:
            checks.append(
                ValidationCheck(
                    id=f"EVIDENCE-{kind.upper()}",
                    question=f"Are at least {minimum} redacted {kind} artifact(s) present?",
                    result="PASS",
                    detail=f"Found {counts[kind]} artifact(s).",
                )
            )
        else:
            requirement = f"Add at least {minimum} redacted {kind} artifact(s)."
            missing.append(requirement)
            checks.append(
                ValidationCheck(
                    id=f"EVIDENCE-{kind.upper()}",
                    question=f"Are at least {minimum} redacted {kind} artifact(s) present?",
                    result="MISSING",
                    detail=requirement,
                )
            )
    logic_details = hypothesis.logic_details or {}
    logic_state_requirements = logic_details.get("state_evidence_requirements", [])
    requires_state = any(item.state_change for item in endpoints) or (
        hypothesis.category == "business_logic"
        and isinstance(logic_state_requirements, list)
        and bool(logic_state_requirements)
    )
    if requires_state:
        state_kinds: tuple[EvidenceKind, ...] = ("before", "after")
        if hypothesis.category == "business_logic":
            state_kinds = (*state_kinds, "delayed_after")
        for kind in state_kinds:
            if counts[kind] >= 1:
                checks.append(
                    ValidationCheck(
                        id=f"EVIDENCE-{kind.upper()}",
                        question=f"Is authoritative {kind}-state evidence present?",
                        result="PASS",
                        detail=f"Found {counts[kind]} artifact(s).",
                    )
                )
            else:
                requirement = f"Add authoritative {kind}.json evidence."
                missing.append(requirement)
                checks.append(
                    ValidationCheck(
                        id=f"EVIDENCE-{kind.upper()}",
                        question=f"Is authoritative {kind}-state evidence present?",
                        result="MISSING",
                        detail=requirement,
                    )
                )
        controlled_resources = logic_details.get("controlled_resources_required", [])
        if (
            hypothesis.category == "business_logic"
            and isinstance(controlled_resources, list)
            and len(controlled_resources) > 1
        ):
            if counts["related_state"] >= 1:
                checks.append(
                    ValidationCheck(
                        id="EVIDENCE-RELATED-STATE",
                        question="Is authoritative related-resource state evidence present?",
                        result="PASS",
                        detail=f"Found {counts['related_state']} artifact(s).",
                    )
                )
            else:
                requirement = "Add authoritative related-resource state evidence."
                missing.append(requirement)
                checks.append(
                    ValidationCheck(
                        id="EVIDENCE-RELATED-STATE",
                        question="Is authoritative related-resource state evidence present?",
                        result="MISSING",
                        detail=requirement,
                    )
                )
    return checks, missing


def _scope_check(
    target: TargetDocument,
    hypothesis: HypothesisRecord,
    endpoints: list[Endpoint],
) -> ValidationCheck:
    if not hypothesis.source.endpoints or len(endpoints) != len(set(hypothesis.source.endpoints)):
        return ValidationCheck(
            id="SCOPE-ENDPOINTS",
            question="Can every source endpoint be resolved and checked against scope?",
            result="FAIL",
            detail="One or more source endpoints cannot be resolved.",
        )
    hosts = {host for endpoint in endpoints for host in endpoint.hosts}
    if not target.scope.hosts or not hosts_are_covered(hosts, target.scope.hosts):
        return ValidationCheck(
            id="SCOPE-ENDPOINTS",
            question="Are all source endpoint hosts explicitly in scope?",
            result="FAIL",
            detail="Source endpoint hosts are not fully covered by target.yaml scope.",
        )
    return ValidationCheck(
        id="SCOPE-ENDPOINTS",
        question="Are all source endpoint hosts explicitly in scope?",
        result="PASS",
        detail="All source endpoint hosts are recorded in target.yaml scope.",
    )


def _assessment_checks(assessment: EvidenceAssessment) -> list[ValidationCheck]:
    specifications = (
        (
            "SCOPE-COMPLIANCE",
            "Was the evidence collected within program scope?",
            "scope_compliant",
            True,
        ),
        (
            "RULES-COMPLIANCE",
            "Did collection comply with program restrictions?",
            "rules_compliant",
            True,
        ),
        (
            "CONTROLLED-ACCOUNTS",
            "Were all affected identities researcher-controlled?",
            "researcher_controlled_accounts",
            True,
        ),
        (
            "BOUNDARY",
            "Is ownership, tenant, role, or state boundary evidence present?",
            "ownership_or_boundary_verified",
            True,
        ),
        (
            "SECURE-CONTROL",
            "Was expected secure behavior absent in the controlled reproduction?",
            "expected_secure_behavior_observed",
            False,
        ),
        (
            "ATTACKER-GAIN",
            "Did the actor gain an unauthorized capability?",
            "unauthorized_capability_demonstrated",
            True,
        ),
        (
            "ACTUAL-BEHAVIOR",
            "Was the actual server behavior directly verified?",
            "actual_behavior_verified",
            True,
        ),
        (
            "AUTHORITATIVE-RESULT",
            "Was data or state verified through an authoritative source?",
            "authoritative_result_verified",
            True,
        ),
        (
            "NEGATIVE-CONTROL",
            "Was an appropriate negative or owner control performed?",
            "negative_control_performed",
            True,
        ),
        (
            "CLEAN-SESSION",
            "Was the result reproduced in a clean session?",
            "reproduced_clean_session",
            True,
        ),
        (
            "ALTERNATIVES",
            "Were caching, UI, test-data, and timing explanations ruled out?",
            "alternative_explanations_ruled_out",
            True,
        ),
        (
            "IMPACT",
            "Was meaningful security impact demonstrated?",
            "meaningful_impact_demonstrated",
            True,
        ),
        (
            "PREREQUISITES",
            "Are the stated attacker prerequisites realistic?",
            "realistic_prerequisites",
            True,
        ),
        (
            "INTENDED-BEHAVIOR",
            "Is the behavior undocumented and not intended?",
            "documented_or_intended_behavior",
            False,
        ),
        (
            "SERVER-BOUNDARY",
            "Is the result more than a client-side-only issue?",
            "client_side_only",
            False,
        ),
        (
            "DUPLICATE",
            "Has known-duplicate risk been checked and ruled out?",
            "known_duplicate",
            False,
        ),
        (
            "REDACTION",
            "Were stored artifacts reviewed for secret and personal-data redaction?",
            "redaction_reviewed",
            True,
        ),
    )
    return [
        _assessment_check(check_id, question, getattr(assessment, field), expected)
        for check_id, question, field, expected in specifications
    ]


def _narrative_missing(narrative: FindingNarrative) -> list[str]:
    missing = [field for field in REPORT_FIELDS if not getattr(narrative, field)]
    if not narrative.reproduction_steps:
        missing.append("reproduction_steps")
    return missing


def _disposition(
    checks: list[ValidationCheck], assessment: EvidenceAssessment, plan: TestPlanRecord | None
) -> tuple[ValidationDisposition, str]:
    by_id = {item.id: item for item in checks}
    if (
        by_id["SCOPE-ENDPOINTS"].result == "FAIL"
        or assessment.scope_compliant is False
        or assessment.rules_compliant is False
    ):
        return "OUT_OF_SCOPE", "Scope or program-rule compliance is not established."
    if assessment.documented_or_intended_behavior is True or assessment.client_side_only is True:
        return (
            "EXPECTED_BEHAVIOR",
            "Recorded evidence does not establish an unintended server-side security "
            "boundary violation.",
        )
    if (
        assessment.expected_secure_behavior_observed is True
        or assessment.unauthorized_capability_demonstrated is False
        or assessment.actual_behavior_verified is False
        or assessment.ownership_or_boundary_verified is False
        or assessment.meaningful_impact_demonstrated is False
    ):
        return "REFUTED", "A decisive control or researcher assessment contradicts the hypothesis."
    if plan is None or plan.status != "READY_FOR_REVIEW" or plan.approval_status != "APPROVED":
        return "NEEDS_MORE_EVIDENCE", "A review-ready, explicitly approved test plan is required."
    if any(item.result in {"FAIL", "MISSING"} for item in checks):
        return (
            "NEEDS_MORE_EVIDENCE",
            "Required evidence or skeptical validation controls are incomplete.",
        )
    return "CONFIRMED", "Evidence supports a reproducible, meaningful security-boundary violation."


def _status(disposition: ValidationDisposition) -> HypothesisStatus:
    if disposition == "CONFIRMED":
        return "CONFIRMED"
    if disposition in {"REFUTED", "EXPECTED_BEHAVIOR"}:
        return "REFUTED"
    return "NEEDS_EVIDENCE"


def validate_hypothesis(workspace: WorkspacePaths, hypothesis_id: str) -> ValidationResult:
    """Attempt to disprove a hypothesis and persist the resulting disposition."""

    target, endpoint_store, hypothesis, evidence = _load_inputs(workspace, hypothesis_id)
    plan = _plan(workspace, hypothesis.id)
    endpoints = _source_endpoints(hypothesis, endpoint_store)
    checks = [_scope_check(target, hypothesis, endpoints), *_assessment_checks(evidence.assessment)]
    if plan is None:
        checks.append(
            ValidationCheck(
                id="PLAN-APPROVAL",
                question="Was a review-ready plan explicitly approved before testing?",
                result="MISSING",
                detail="No test plan is recorded for this hypothesis.",
            )
        )
    else:
        approved = plan.status == "READY_FOR_REVIEW" and plan.approval_status == "APPROVED"
        checks.append(
            ValidationCheck(
                id="PLAN-APPROVAL",
                question="Was a review-ready plan explicitly approved before testing?",
                result="PASS" if approved else "FAIL",
                detail=(
                    "Plan is READY_FOR_REVIEW and APPROVED."
                    if approved
                    else f"Plan status is {plan.status}; approval is {plan.approval_status}."
                ),
            )
        )
    artifact_checks, artifact_missing = _artifact_checks(workspace, hypothesis, evidence, endpoints)
    checks.extend(artifact_checks)
    disposition, summary = _disposition(checks, evidence.assessment, plan)
    missing = [item.detail for item in checks if item.result == "MISSING"]
    missing.extend(item for item in artifact_missing if item not in missing)
    narrative_missing = _narrative_missing(evidence.narrative)
    report_ready = disposition == "CONFIRMED" and not narrative_missing
    if disposition == "CONFIRMED" and narrative_missing:
        missing.append("Complete report narrative fields: " + ", ".join(narrative_missing) + ".")
    draft: dict[str, Any] = {
        "key": f"validation:{hypothesis.id}",
        "hypothesis_id": hypothesis.id,
        "title": hypothesis.title,
        "disposition": disposition,
        "summary": summary,
        "checks": [item.model_dump(mode="json") for item in checks],
        "evidence_artifacts": [item.id for item in evidence.artifacts],
        "missing_requirements": missing,
        "report_ready": report_ready,
    }
    fingerprint = validation_source_fingerprint(
        target,
        endpoint_store,
        hypothesis,
        plan,
        evidence,
    )
    merge = merge_generated_records(
        workspace.validations,
        "validations",
        "FND",
        "phase4-validator",
        fingerprint,
        [draft],
        preserved_fields=("notes",),
    )
    try:
        store = ValidationStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(f"Cannot validate finding store: {error}") from error
    write_yaml(workspace.validations, store.model_dump(mode="json", exclude_none=True))
    record = next(item for item in store.validations if item.hypothesis_id == hypothesis.id)
    update_hypothesis_status(workspace, hypothesis.id, _status(record.disposition))
    return ValidationResult(
        record,
        workspace.validations,
        f"validation:{hypothesis.id}" in merge.conflicts,
    )
