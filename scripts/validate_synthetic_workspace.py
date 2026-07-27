#!/usr/bin/env python3
"""Configure, snapshot, and validate the isolated SyntheticPay workspace."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStore
from finsec.modeling.domain import InvariantStore, ResourceStore
from finsec.modeling.models import (
    EndpointPrimaryClassification,
    EndpointStore,
    ObservationStore,
)
from finsec.testing.domain import TestPlanStore
from finsec.utils.yaml_store import load_yaml, write_yaml

PRESERVATION_NOTE = "Synthetic validation preservation note."
OVERRIDE_PATH = "/api/v2/search"
SECRETS = (
    "SYNTHETIC_ACCOUNT_A_TOKEN",
    "SYNTHETIC_ACCOUNT_B_TOKEN",
    "SYNTHETIC_COOKIE_A",
    "SYNTHETIC_COOKIE_B",
    "111111",
    "222222",
)


def configure(workspace: WorkspacePaths) -> None:
    """Write only fields accepted by the current strict target schema."""

    document = TargetDocument.model_validate(load_yaml(workspace.target)).model_dump(mode="json")
    document["scope"]["hosts"] = [
        "app.syntheticpay.test",
        "api.syntheticpay.test",
        "static.syntheticpay.test",
    ]
    document["accounts"] = [
        {"id": "ACCOUNT_A", "ownership": "researcher"},
        {"id": "ACCOUNT_B", "ownership": "researcher"},
    ]
    document["testing"] = {
        "production": False,
        "human_approval_required": True,
        "destructive_testing": False,
    }
    document["analysis"] = {
        "include_hosts": [
            "app.syntheticpay.test",
            "api.syntheticpay.test",
            "static.syntheticpay.test",
        ],
        "exclude_hosts": ["telemetry.syntheticpay.test", "thirdparty.invalid"],
        "suppress": {
            "static_assets": True,
            "telemetry": True,
            "analytics": True,
            "third_party": True,
        },
        "excluded_extensions": [
            "jpg",
            "jpeg",
            "png",
            "webp",
            "svg",
            "css",
            "js",
            "map",
            "woff",
            "woff2",
        ],
        "excluded_path_patterns": [
            "/static/",
            "/assets/",
            "/gen_204",
            "/envelope/",
            "/telemetry/",
            "/client-exporter/",
            "/actionlog/",
        ],
        "hypothesis_gates": {
            "bola_minimum_score": 6,
            "state_transition_minimum_score": 7,
            "financial_minimum_score": 5,
        },
        "classification_overrides": {},
    }
    TargetDocument.model_validate(document)
    write_yaml(workspace.target, document)
    (workspace.root / "scope/program.md").write_text(
        "# SyntheticPay Program Rules\n\nOffline synthetic validation only. No network access.\n",
        encoding="utf-8",
    )
    (workspace.root / "scope/scope.md").write_text(
        "# Synthetic Scope\n\nOnly reserved `.test` and `.invalid` fixtures are used.\n",
        encoding="utf-8",
    )
    (workspace.root / "scope/restrictions.md").write_text(
        "# Synthetic Restrictions\n\n"
        "Accounts A and B have equivalent user roles and basic verification.\n",
        encoding="utf-8",
    )


def annotate_lifecycle(workspace: WorkspacePaths) -> None:
    """Use the supported researcher-edit path to record a synthetic lifecycle."""

    document = load_yaml(workspace.resources)
    resources = document.get("resources", []) if isinstance(document, dict) else []
    payment = next(item for item in resources if item.get("name") == "Payment")
    payment["states"] = ["pending", "cancelled", "confirmed", "completed"]
    payment["notes"] = "Synthetic observations support pending -> cancelled/confirmed."
    write_yaml(workspace.resources, document)


def _endpoint_snapshot(store: EndpointStore) -> list[dict[str, Any]]:
    return [
        {
            "id": item.id,
            "method": item.method,
            "path": item.path,
            "classification": item.classification.model_dump(mode="json"),
            "action": item.action.model_dump(mode="json"),
            "state_change": item.state_change,
            "parameters": [value.model_dump(mode="json") for value in item.parameters],
            "disposition": item.disposition,
            "security_relevance": item.security_relevance,
            "sources": item.sources,
        }
        for item in sorted(store.endpoints, key=lambda value: value.id)
    ]


def snapshot(workspace: WorkspacePaths) -> dict[str, Any]:
    endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    resources = ResourceStore.model_validate(load_yaml(workspace.resources))
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    return {
        "endpoints": _endpoint_snapshot(endpoints),
        "resources": [
            {
                "id": item.id,
                "key": item.key,
                "name": item.name,
                "identifiers": item.identifiers,
                "states": item.states,
                "disposition": item.disposition,
            }
            for item in sorted(resources.resources, key=lambda value: value.id)
        ],
        "candidates": [
            {
                "id": item.id,
                "key": item.key,
                "kind": item.kind,
                "disposition": item.disposition,
                "category": item.category,
                "title": item.title,
                "source": item.source.model_dump(mode="json"),
                "scores": item.scores.model_dump(mode="json"),
                "generation_rule": item.generation_rule,
                "eligibility_evidence": item.eligibility_evidence,
                "missing_evidence": item.missing_evidence,
            }
            for item in sorted(hypotheses.hypotheses, key=lambda value: value.id)
        ],
    }


def prepare_preservation(workspace: WorkspacePaths) -> str:
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    payment = _payment_bola(hypotheses.hypotheses)
    document = load_yaml(workspace.hypotheses)
    record = next(item for item in document["hypotheses"] if item["id"] == payment.id)
    record["notes"] = PRESERVATION_NOTE
    write_yaml(workspace.hypotheses, document)

    target = load_yaml(workspace.target)
    target["analysis"]["classification_overrides"][OVERRIDE_PATH] = "FIRST_PARTY_API"
    write_yaml(workspace.target, target)
    return payment.id


def _payment_bola(records: list[HypothesisRecord]) -> HypothesisRecord:
    return next(
        item
        for item in records
        if item.category == "authorization"
        and item.disposition == "ACTIVE"
        and item.generation_rule.get("id") == "AUTH_OBJECT_ACCESS"
        and item.source.endpoints
        and "payment" in item.component.lower()
        and "wallet" not in item.component.lower()
    )


def _count_primary(endpoints: EndpointStore) -> Counter[str]:
    return Counter(item.classification.primary.value for item in endpoints.endpoints)


def validate(root: Path) -> None:
    run1 = WorkspacePaths(root / "run-1/workspaces/syntheticpay")
    results = root / "results"
    observations = ObservationStore.model_validate(load_yaml(run1.observations))
    endpoints = EndpointStore.model_validate(load_yaml(run1.endpoints))
    resources = ResourceStore.model_validate(load_yaml(run1.resources))
    invariants = InvariantStore.model_validate(load_yaml(run1.invariants))
    hypotheses = HypothesisStore.model_validate(load_yaml(run1.hypotheses))
    plans = TestPlanStore.model_validate(load_yaml(run1.test_plans))
    active = [
        item
        for item in hypotheses.hypotheses
        if item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
    ]
    tasks = [item for item in hypotheses.hypotheses if item.kind == "RESEARCH_TASK"]
    by_path = {(item.method, item.path): item for item in endpoints.endpoints}
    scenarios: list[tuple[str, str, str, bool]] = []

    def check(name: str, expected: str, actual: str, condition: bool) -> None:
        scenarios.append((name, expected, actual, condition))

    static = [
        item
        for item in endpoints.endpoints
        if item.classification.primary == EndpointPrimaryClassification.STATIC_ASSET
    ]
    telemetry = [
        item
        for item in endpoints.endpoints
        if item.classification.primary
        in {EndpointPrimaryClassification.TELEMETRY, EndpointPrimaryClassification.ANALYTICS}
    ]
    third_party = [
        item
        for item in endpoints.endpoints
        if item.classification.primary == EndpointPrimaryClassification.THIRD_PARTY
    ]
    check(
        "Static asset suppression",
        "All static families suppressed",
        f"{len(static)} static; {sum(item.disposition != 'ACTIVE' for item in static)} suppressed",
        bool(static) and all(item.disposition == "SUPPRESSED_STATIC_ASSET" for item in static),
    )
    check(
        "Telemetry suppression",
        "Telemetry/analytics suppressed",
        f"{len(telemetry)} telemetry/analytics",
        bool(telemetry) and all(item.disposition != "ACTIVE" for item in telemetry),
    )
    check(
        "Third-party classification",
        "thirdparty.invalid is THIRD_PARTY",
        ", ".join(sorted({host for item in third_party for host in item.hosts})) or "missing",
        any("thirdparty.invalid" in item.hosts for item in third_party),
    )

    paths = {item.path for item in endpoints.endpoints}
    check(
        "Version preservation",
        "v2/v3 remain literal and no version ID placeholder",
        f"v3 asset={('/web/v3/loader_v3.12.3.js' in paths)}",
        "/web/v3/loader_v3.12.3.js" in paths
        and not any("{v2Id}" in path or "{v3Id}" in path for path in paths),
    )
    payment_endpoint = by_path.get(("GET", "/api/v2/payments/{paymentId}"))
    check(
        "Endpoint deduplication",
        "One payment family with all literal instances",
        f"sources={len(payment_endpoint.sources) if payment_endpoint else 0}",
        payment_endpoint is not None and len(payment_endpoint.sources) >= 8,
    )

    read_names = {"search", "list", "menu", "viewport", "lookup", "history"}
    read_posts = [
        item
        for item in endpoints.endpoints
        if item.method == "POST" and item.action.name in read_names
    ]
    check(
        "Read-like POST classification",
        "Read actions are not state changes",
        f"{len(read_posts)} read-like POST families",
        len(read_posts) >= 6 and all(not item.state_change for item in read_posts),
    )

    wallet = by_path.get(("POST", "/api/v2/wallet/payment-history"))
    wallet_id = (
        next((item for item in wallet.parameters if item.name == "walletId"), None)
        if wallet
        else None
    )
    check(
        "JSON body identifier",
        "walletId body parameter with $.walletId object semantics",
        str(wallet_id.model_dump(mode="json") if wallet_id else "missing"),
        wallet is not None
        and EndpointPrimaryClassification.FINANCIAL in wallet.classification.tags
        and wallet_id is not None
        and wallet_id.location == "body"
        and wallet_id.json_path == "$.walletId"
        and wallet_id.semantic_type == "object_identifier"
        and wallet_id.client_controlled,
    )

    payment_bola = [
        item
        for item in active
        if item.category == "authorization"
        and "paymentId" in item.hypothesis
        and "wallet" not in item.component.lower()
    ]
    wallet_bola = [
        item
        for item in active
        if item.category == "authorization" and "walletId" in item.hypothesis
    ]
    check(
        "Path BOLA",
        "One semantic Payment authorization family",
        f"{len(payment_bola)} candidates",
        len(payment_bola) >= 1 and len({item.key for item in payment_bola}) == len(payment_bola),
    )
    check(
        "Body BOLA",
        "Wallet payment-history authorization candidate",
        f"{len(wallet_bola)} candidates",
        len(wallet_bola) == 1,
    )

    auth_code = [item for item in tasks if "code replay and binding" in item.title.lower()]
    auth_text = " ".join(
        [value for item in auth_code for value in [*item.evidence_to_collect, item.reasoning]]
    ).lower()
    check(
        "Authentication replay/binding",
        "Replay, challenge, session, account, and purpose questions",
        auth_text or "missing",
        len(auth_code) == 1
        and all(
            word in auth_text for word in ("replay", "challenge", "session", "account", "purpose")
        ),
    )

    state_tasks = [
        item for item in tasks if item.generation_rule.get("id") == "STATE_TRANSITION_RESEARCH"
    ]
    state_task_text = " ".join(item.title.lower() for item in state_tasks)
    check(
        "State-transition specificity",
        "Specific cancel/confirm research questions, no generic active claim",
        state_task_text or "missing",
        not any(item.category == "state_integrity" for item in active)
        and "confirm operation rejects cancelled payment" in state_task_text
        and "cancel operation rejects confirmed payment" in state_task_text,
    )

    active_authentication = [item for item in active if item.category == "authentication"]
    authentication_tasks = [
        item for item in tasks if item.generation_rule.get("id") == "AUTH_ENFORCEMENT_RESEARCH"
    ]
    check(
        "Authentication enforcement gate",
        "Authenticated baselines become grouped research tasks",
        f"active={len(active_authentication)}, tasks={len(authentication_tasks)}",
        not active_authentication and len(authentication_tasks) >= 2,
    )

    response_monetary = [
        item
        for endpoint in endpoints.endpoints
        for item in endpoint.parameters
        if item.source == "response" and item.semantic_type == "monetary_value"
    ]
    active_values = [item for item in active if item.category == "value_validation"]
    check(
        "Response-only value exclusion",
        "Response monetary fields retain provenance and create no mutation candidate",
        f"response_fields={len(response_monetary)}, active_values={len(active_values)}",
        bool(response_monetary)
        and all(not item.client_controlled for item in response_monetary)
        and not active_values,
    )

    task_titles = " ".join(item.title.lower() for item in tasks)
    check(
        "Research-task generation",
        "change-wallet and verification tasks",
        task_titles,
        "change-wallet persists server-side state" in task_titles
        and "lifecycle and security impact of user verification" in task_titles,
    )

    forbidden_paths = ("/search", "/menu", "/list", "/viewport", "/lookup")
    generic_state = [
        item
        for item in active
        if item.category == "state_integrity"
        and any(marker in item.hypothesis.lower() for marker in forbidden_paths)
    ]
    noisy = [
        item
        for item in active
        if any(
            endpoint_id in {value.id for value in static + telemetry + third_party}
            for endpoint_id in item.source.endpoints
        )
    ]
    check(
        "Noise exclusion",
        "No static, telemetry, third-party, or generic read-state hypotheses",
        f"noisy={len(noisy)}, generic_state={len(generic_state)}",
        not noisy and not generic_state,
    )

    quality = all(
        item.eligibility_evidence
        and item.missing_evidence
        and item.generation_rule
        and item.expected_secure_behavior
        and item.possible_vulnerable_behavior
        and item.priority_rationale
        for item in active
    )
    check(
        "Hypothesis explainability",
        "Every active hypothesis has required quality fields",
        f"active={len(active)}",
        bool(active) and quality,
    )

    before = json.loads((results / "run-1-snapshot.json").read_text(encoding="utf-8"))
    second = json.loads((results / "run-2-snapshot.json").read_text(encoding="utf-8"))
    check(
        "Determinism",
        "Clean runs have identical semantic snapshots",
        "identical" if before == second else "different",
        before == second,
    )

    preserved = next(item for item in hypotheses.hypotheses if item.notes == PRESERVATION_NOTE)
    override_endpoint = by_path.get(("POST", OVERRIDE_PATH))
    check(
        "Regeneration preservation",
        "Note, TEST_PLANNED status, lifecycle annotation, and override survive",
        (
            f"status={preserved.status}; override="
            f"{override_endpoint.classification.reasons if override_endpoint else None}"
        ),
        preserved.status == "TEST_PLANNED"
        and override_endpoint is not None
        and "researcher classification override" in override_endpoint.classification.reasons
        and any(
            item.name == "Payment" and "cancelled" in item.states for item in resources.resources
        ),
    )

    leaked: list[str] = []
    for path in run1.root.rglob("*"):
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        leaked.extend(secret for secret in SECRETS if secret in content)
    check(
        "Redaction",
        "No synthetic tokens, cookies, or OTP values in workspace",
        f"leaks={sorted(set(leaked))}",
        not leaked,
    )

    safety = bool(plans.plans) and all(
        item.human_approval_required
        and item.execution_default == "DO_NOT_EXECUTE"
        and not item.risk.concurrency
        for item in plans.plans
    )
    plan_text = json.dumps(plans.model_dump(mode="json")).lower()
    check(
        "Safety gates",
        "Plans require approval and propose no brute force/destructive automation",
        f"plans={len(plans.plans)}",
        safety and "brute force" not in plan_text and "brute_force" not in plan_text,
    )

    before_checksums = (results / "real-workspaces-before.sha256").read_text(encoding="utf-8")
    after_checksums = (results / "real-workspaces-after.sha256").read_text(encoding="utf-8")
    check(
        "Real workspace isolation",
        "Existing workspace checksums unchanged",
        "unchanged" if before_checksums == after_checksums else "changed",
        before_checksums == after_checksums,
    )

    classification_counts = _count_primary(endpoints)
    tag_counts = Counter(
        tag.value for item in endpoints.endpoints for tag in item.classification.tags
    )
    disposition_counts = Counter(item.disposition for item in endpoints.endpoints)
    hosts = sorted({item.host for item in observations.observations})
    workflows_text = (run1.root / "model/workflows.md").read_text(encoding="utf-8")
    workflow_count = workflows_text.count("\n## Workflow:")
    failures = [name for name, _, _, passed in scenarios if not passed]
    commit = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    report_lines = [
        "# SyntheticPay Validation Report",
        "",
        "## Environment",
        "",
        f"- Python: {platform.python_version()}",
        f"- FinSec Hunt commit: `{commit}`",
        f"- Workspace: `{run1.root}`",
        "- Execution: offline synthetic HAR ingestion only",
        "",
        "### Commands Executed",
        "",
        "- `hunt init`, `hunt ingest`, `hunt classify`, `hunt inventory`",
        "- `hunt model`, `hunt invariants`, `hunt hypotheses`, `hunt status`",
        "- `hunt plan`, `hunt explain`, `hunt noise`",
        "- `hunt hypotheses --research-tasks --include-suppressed`",
        "- `python scripts/validate_synthetic_workspace.py validate ...`",
        "",
        "## Input",
        "",
        "- HAR files: 10",
        f"- Observations: {len(observations.observations)}",
        "- Actors: ACCOUNT_A, ACCOUNT_B, ANONYMOUS",
        f"- Hosts: {', '.join(hosts)}",
        f"- Workflows: {workflow_count}",
        f"- Active resources: {sum(item.disposition == 'ACTIVE' for item in resources.resources)}",
        (
            "- Active invariants: "
            f"{sum(item.disposition == 'ACTIVE' for item in invariants.invariants)}"
        ),
        "",
        "## Classification Results",
        "",
        *[f"- {name}: {count}" for name, count in sorted(classification_counts.items())],
        f"- AUTHENTICATION tag: {tag_counts['AUTHENTICATION']}",
        f"- FINANCIAL tag: {tag_counts['FINANCIAL']}",
        f"- UNKNOWN: {classification_counts['UNKNOWN']}",
        "",
        "## Normalization Results",
        "",
        f"- Raw observations: {len(observations.observations)}",
        f"- Endpoint families: {len(endpoints.endpoints)}",
        (
            "- Observations merged into families: "
            f"{len(observations.observations) - len(endpoints.endpoints)}"
        ),
        (
            "- Suppressed families: "
            f"{sum(item.disposition != 'ACTIVE' for item in endpoints.endpoints)}"
        ),
        "- Version preservation: verified by model assertions",
        "",
        "## Hypothesis Results",
        "",
        f"- Active hypotheses: {len(active)}",
        f"- Research tasks: {len(tasks)}",
        (
            "- Candidate dispositions: "
            f"{dict(Counter(item.disposition for item in hypotheses.hypotheses))}"
        ),
        f"- Endpoint suppression: {dict(disposition_counts)}",
        "- Suppression reasons: static asset, telemetry pattern, excluded third-party host",
        "",
        "## Required Scenarios",
        "",
        "| Scenario | Expected | Actual | Result |",
        "|---|---|---|---|",
        *[
            f"| {name} | {expected} | {actual.replace('|', '/')} | {'PASS' if passed else 'FAIL'} |"
            for name, expected, actual, passed in scenarios
        ],
        "",
        "## Active Hypotheses",
        "",
        *[f"- `{item.id}` {item.title}" for item in active],
        "",
        "## Research Tasks",
        "",
        *[f"- `{item.id}` {item.title}" for item in tasks],
        "",
        "## Failures and Limitations",
        "",
        (
            "- No validation failures. Lifecycle semantics are synthetic researcher annotations, "
            "not proof about any real system."
            if not failures
            else "- Failed scenarios: " + ", ".join(failures)
        ),
    ]
    report = results / "VALIDATION_REPORT.md"
    report.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(report)
    if failures:
        raise SystemExit("Synthetic validation failed: " + ", ".join(failures))
    print(f"Synthetic validation passed: {len(scenarios)} assertions")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("configure", "annotate", "prepare-preservation", "plan-id", "snapshot"):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("path", type=Path)
        if name == "snapshot":
            subparser.add_argument("output", type=Path)
    endpoint_parser = subparsers.add_parser("endpoint-id")
    endpoint_parser.add_argument("path", type=Path)
    endpoint_parser.add_argument("method")
    endpoint_parser.add_argument("endpoint_path")
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("root", type=Path)
    args = parser.parse_args()
    if args.command == "validate":
        validate(args.root)
        return
    workspace = WorkspacePaths(args.path.resolve())
    if args.command == "configure":
        configure(workspace)
    elif args.command == "annotate":
        annotate_lifecycle(workspace)
    elif args.command == "prepare-preservation":
        print(prepare_preservation(workspace))
    elif args.command == "plan-id":
        store = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
        print(_payment_bola(store.hypotheses).id)
    elif args.command == "snapshot":
        args.output.write_text(
            json.dumps(snapshot(workspace), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif args.command == "endpoint-id":
        store = EndpointStore.model_validate(load_yaml(workspace.endpoints))
        endpoint = next(
            item
            for item in store.endpoints
            if item.method == args.method.upper() and item.path == args.endpoint_path
        )
        print(endpoint.id)


if __name__ == "__main__":
    main()
