"""Generate versioned reports only from currently validated evidence."""

import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, StrictUndefined
from pydantic import ValidationError

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.evidence.domain import EvidenceMetadata
from finsec.evidence.manager import load_evidence
from finsec.hypotheses.domain import HypothesisRecord
from finsec.hypotheses.generator import find_hypothesis
from finsec.modeling.domain import InvariantStore
from finsec.utils.redaction import redact_text
from finsec.utils.yaml_store import load_yaml
from finsec.validation.validator import validate_hypothesis


@dataclass(frozen=True)
class ReportResult:
    """Generated or reused report path."""

    path: Path
    created: bool


def _load_invariants(workspace: WorkspacePaths) -> InvariantStore:
    try:
        return InvariantStore.model_validate(load_yaml(workspace.invariants))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load invariants for reporting: {error}") from error


def _bullet_list(items: list[str]) -> str:
    return "\n".join(f"- {redact_text(item).replace('|', '\\|')}" for item in items)


def _numbered_list(items: list[str]) -> str:
    return "\n".join(
        f"{index}. {redact_text(item).replace('|', '\\|')}" for index, item in enumerate(items, 1)
    )


def _evidence_list(evidence: EvidenceMetadata) -> str:
    return "\n".join(
        f"- `{item.id}` `{item.kind}`: `{item.path}` (SHA-256 `{item.sha256}`)"
        for item in evidence.artifacts
    )


def _invariant_text(hypothesis: HypothesisRecord, store: InvariantStore) -> str:
    by_id = {item.id: item for item in store.invariants}
    statements = [
        redact_text(by_id[item].statement) if item in by_id else f"Invariant `{item}`"
        for item in hypothesis.invariant
    ]
    return _bullet_list(statements) if statements else "No invariant is linked."


def _render(
    workspace: WorkspacePaths,
    hypothesis: HypothesisRecord,
    evidence: EvidenceMetadata,
) -> str:
    narrative = evidence.narrative
    required = {
        "report_title": narrative.report_title,
        "summary": narrative.summary,
        "root_cause": narrative.root_cause,
        "affected_boundary": narrative.affected_boundary,
        "actual_behavior": narrative.actual_behavior,
        "technical_impact": narrative.technical_impact,
        "business_impact": narrative.business_impact,
        "realistic_attack_scenario": narrative.realistic_attack_scenario,
        "severity_rationale": narrative.severity_rationale,
        "remediation": narrative.remediation,
    }
    missing = [name for name, value in required.items() if not value]
    if not narrative.reproduction_steps:
        missing.append("reproduction_steps")
    if missing:
        raise FinsecError(
            "Report narrative is incomplete; fill metadata.yaml fields: " + ", ".join(missing)
        )
    template_resource = files("finsec.reporting.templates").joinpath("report.md.j2")
    environment = Environment(
        undefined=StrictUndefined, autoescape=False, keep_trailing_newline=True
    )
    template = environment.from_string(template_resource.read_text(encoding="utf-8"))
    invariants = _load_invariants(workspace)
    return (
        template.render(
            title=redact_text(narrative.report_title or ""),
            summary=redact_text(narrative.summary or ""),
            affected_component=(
                f"{redact_text(hypothesis.component)}\n\nAffected boundary: "
                f"{redact_text(narrative.affected_boundary or '')}"
            ),
            preconditions=_bullet_list(hypothesis.preconditions),
            root_cause=redact_text(narrative.root_cause or ""),
            steps_to_reproduce=_numbered_list(narrative.reproduction_steps),
            expected_behavior=redact_text(hypothesis.expected_secure_behavior),
            actual_behavior=redact_text(narrative.actual_behavior or ""),
            invariant=_invariant_text(hypothesis, invariants),
            technical_impact=redact_text(narrative.technical_impact or ""),
            business_impact=redact_text(narrative.business_impact or ""),
            realistic_attack_scenario=redact_text(narrative.realistic_attack_scenario or ""),
            evidence=_evidence_list(evidence),
            severity_rationale=redact_text(narrative.severity_rationale or ""),
            scope_compliance=(
                "The deterministic validator recorded `CONFIRMED`. Evidence metadata states that "
                "scope, program rules, researcher-controlled accounts, human approval, and "
                "redaction requirements were satisfied."
            ),
            remediation=redact_text(narrative.remediation or ""),
        ).rstrip()
        + "\n"
    )


def _report_path(workspace: WorkspacePaths, hypothesis_id: str, content: str) -> ReportResult:
    workspace.reports.mkdir(parents=True, exist_ok=True)
    pattern = re.compile(rf"^{re.escape(hypothesis_id)}-report-v(\d+)\.md$")
    existing: list[tuple[int, Path]] = []
    for path in workspace.reports.glob(f"{hypothesis_id}-report-v*.md"):
        match = pattern.fullmatch(path.name)
        if match is not None:
            existing.append((int(match.group(1)), path))
    for _, path in sorted(existing):
        if path.read_text(encoding="utf-8") == content:
            return ReportResult(path, False)
    version = max((number for number, _ in existing), default=0) + 1
    path = workspace.reports / f"{hypothesis_id}-report-v{version}.md"
    path.write_text(content, encoding="utf-8", newline="\n")
    return ReportResult(path, True)


def generate_report(workspace: WorkspacePaths, hypothesis_id: str) -> ReportResult:
    """Revalidate current evidence and write a new report version when appropriate."""

    validation = validate_hypothesis(workspace, hypothesis_id)
    if validation.conflict:
        raise FinsecError(
            "The researcher-edited validation record was preserved; resolve it before reporting."
        )
    if validation.validation.disposition != "CONFIRMED":
        raise FinsecError(
            f"Report generation requires CONFIRMED evidence; current disposition is "
            f"{validation.validation.disposition}."
        )
    if not validation.validation.report_ready:
        raise FinsecError("Validation is confirmed, but report narrative fields are incomplete.")
    hypothesis = find_hypothesis(workspace, hypothesis_id)
    evidence = load_evidence(workspace, hypothesis.id)
    return _report_path(workspace, hypothesis.id, _render(workspace, hypothesis, evidence))
