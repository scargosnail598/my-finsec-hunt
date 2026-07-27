"""Focused regressions for hypothesis input provenance and evidence specificity."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import EndpointStore
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml, write_yaml


def _entry(
    index: int,
    method: str,
    path: str,
    response: dict[str, Any],
    *,
    request: dict[str, Any] | None = None,
    authenticated: bool = True,
) -> dict[str, Any]:
    headers: list[dict[str, str]] = []
    if authenticated:
        headers.append({"name": "Authorization", "value": "Bearer SYNTHETIC_TOKEN"})
    request_document: dict[str, Any] = {
        "method": method,
        "url": f"https://api.example.test{path}",
        "headers": headers,
    }
    if request is not None:
        request_document["postData"] = {
            "mimeType": "application/json",
            "text": json.dumps(request),
        }
    return {
        "startedDateTime": f"2026-02-01T10:{index:02d}:00Z",
        "request": request_document,
        "response": {
            "status": 200,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": json.dumps(response)},
        },
    }


def _workspace(
    tmp_path: Path,
    entries: list[dict[str, Any]],
    *,
    accounts: int = 1,
    payment_states: list[str] | None = None,
) -> WorkspacePaths:
    workspace = create_workspace("precision", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": f"ACCOUNT_{index}", "ownership": "researcher"} for index in range(1, accounts + 1)
    ]
    target["testing"]["production"] = False
    write_yaml(workspace.target, target)

    capture = tmp_path / "precision.har"
    capture.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "precision-tests", "version": "1"},
                    "entries": entries,
                }
            }
        ),
        encoding="utf-8",
    )
    ingest_har(capture, workspace, actor="ACCOUNT_1", channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    if payment_states is not None:
        resources = load_yaml(workspace.resources)
        payment = next(item for item in resources["resources"] if item["name"] == "Payment")
        payment["states"] = payment_states
        write_yaml(workspace.resources, resources)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    return workspace


def _multi_actor_workspace(
    tmp_path: Path,
    actor_entries: list[tuple[str, dict[str, Any]]],
) -> WorkspacePaths:
    workspace = create_workspace("actor-baselines", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": actor, "ownership": "researcher"}
        for actor in sorted({actor for actor, _ in actor_entries})
    ]
    target["testing"]["production"] = False
    write_yaml(workspace.target, target)

    for index, (actor, entry) in enumerate(actor_entries, start=1):
        capture = tmp_path / f"actor-{index}.har"
        capture.write_text(
            json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "actor-baseline-tests", "version": "1"},
                        "entries": [entry],
                    }
                }
            ),
            encoding="utf-8",
        )
        ingest_har(capture, workspace, actor=actor, channel="WEB")

    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    return workspace


def _records(workspace: WorkspacePaths) -> HypothesisStore:
    return HypothesisStore.model_validate(load_yaml(workspace.hypotheses))


def _endpoints(workspace: WorkspacePaths) -> EndpointStore:
    return EndpointStore.model_validate(load_yaml(workspace.endpoints))


def test_response_only_amount_does_not_generate_boundary_hypothesis(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        [
            _entry(
                1,
                "POST",
                "/api/v2/payments/PAY-1/cancel",
                {
                    "paymentId": "PAY-1",
                    "amount": 12500,
                    "currency": "IRR",
                    "status": "cancelled",
                },
            )
        ],
    )
    endpoint = _endpoints(workspace).endpoints[0]
    response_fields = [item for item in endpoint.parameters if item.source == "response"]
    value_hypotheses = [
        item for item in _records(workspace).hypotheses if item.category == "value_validation"
    ]

    assert {item.name for item in response_fields} >= {"amount", "currency"}
    assert all(item.location == "response_body" for item in response_fields)
    assert all(not item.client_controlled for item in response_fields)
    assert value_hypotheses == []


def test_response_collection_fields_do_not_become_request_inputs(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        [
            _entry(
                1,
                "POST",
                "/api/v2/wallet/change-wallet/FAST_PAYMENT",
                {"items": [{"amount": 1000}]},
                request={"mode": "FAST_PAYMENT"},
            )
        ],
    )
    endpoint = _endpoints(workspace).endpoints[0]
    amount = next(item for item in endpoint.parameters if item.name == "amount")

    assert amount.source == "response"
    assert amount.json_path == "$.items[*].amount"
    assert not amount.client_controlled
    assert not any(item.category == "value_validation" for item in _records(workspace).hypotheses)


def test_request_amount_still_generates_value_candidate(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        [
            _entry(
                1,
                "POST",
                "/api/v2/transfers",
                {"transferId": "TRANSFER-1", "status": "pending"},
                request={"amount": 1000, "currency": "IRR"},
            )
        ],
    )
    candidates = [
        item for item in _records(workspace).hypotheses if item.category == "value_validation"
    ]

    assert len(candidates) == 1
    assert "amount" in candidates[0].title
    assert "currency" in candidates[0].title


def test_authorization_header_alone_creates_authentication_research_task(
    tmp_path: Path,
) -> None:
    workspace = _workspace(
        tmp_path,
        [_entry(1, "GET", "/api/v2/payments/PAY-1", {"paymentId": "PAY-1"})],
    )
    records = _records(workspace).hypotheses

    assert not any(
        item.category == "authentication" and item.disposition == "ACTIVE" for item in records
    )
    assert any(
        item.kind == "RESEARCH_TASK" and "authentication is enforced" in item.title.lower()
        for item in records
    )


def test_anonymous_success_enables_authentication_hypothesis(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        [
            _entry(1, "GET", "/api/v2/payments/PAY-1", {"paymentId": "PAY-1"}),
            _entry(
                2,
                "GET",
                "/api/v2/payments/PAY-1",
                {"paymentId": "PAY-1", "ownerId": "USER-1", "amount": 1000},
                authenticated=False,
            ),
        ],
    )
    active = [item for item in _records(workspace).hypotheses if item.disposition == "ACTIVE"]

    assert any(item.category == "authentication" for item in active)
    assert any("anonymous access" in item.title.lower() for item in active)


def test_generic_state_transition_is_replaced_by_specific_research_task(
    tmp_path: Path,
) -> None:
    workspace = _workspace(
        tmp_path,
        [
            _entry(
                1,
                "POST",
                "/api/v2/payments/PAY-1/cancel",
                {"paymentId": "PAY-1", "status": "cancelled"},
            ),
            _entry(
                2,
                "POST",
                "/api/v2/payments/PAY-2/confirm",
                {"paymentId": "PAY-2", "status": "confirmed"},
            ),
        ],
        payment_states=["pending", "cancelled", "confirmed"],
    )
    records = _records(workspace).hypotheses

    assert not any(
        item.disposition == "ACTIVE"
        and "may accept an invalid payment state transition" in item.title.lower()
        for item in records
    )
    assert any(
        item.kind == "RESEARCH_TASK"
        and "confirm operation rejects cancelled payment" in item.title.lower()
        for item in records
    )


def test_valid_path_and_body_bola_hypotheses_remain_active(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        [
            _entry(1, "GET", "/api/v2/payments/PAY-A-1001", {"paymentId": "PAY-A-1001"}),
            _entry(2, "GET", "/api/v2/payments/PAY-B-2001", {"paymentId": "PAY-B-2001"}),
            _entry(
                3,
                "POST",
                "/api/v2/wallet/payment-history",
                {"walletId": "WALLET-A", "items": []},
                request={"walletId": "WALLET-A"},
            ),
            _entry(
                4,
                "POST",
                "/api/v2/wallet/payment-history",
                {"walletId": "WALLET-B", "items": []},
                request={"walletId": "WALLET-B"},
            ),
        ],
        accounts=2,
    )
    active = [item for item in _records(workspace).hypotheses if item.disposition == "ACTIVE"]

    assert any(
        item.category == "authorization" and "paymentId" in item.hypothesis for item in active
    )
    assert any(
        item.category == "authorization" and "walletId" in item.hypothesis for item in active
    )


def test_unauthenticated_account_scoped_basket_baselines_promote_one_bola(
    tmp_path: Path,
) -> None:
    workspace = _multi_actor_workspace(
        tmp_path,
        [
            (
                "ACCOUNT_A",
                _entry(
                    1,
                    "GET",
                    "/rest/basket/6",
                    {
                        "status": "success",
                        "data": {
                            "id": 6,
                            "UserId": 10,
                            "Products": [{"id": 1, "name": "Synthetic Product A"}],
                        },
                    },
                    authenticated=False,
                ),
            ),
            (
                "ACCOUNT_B",
                _entry(
                    2,
                    "GET",
                    "/rest/basket/7",
                    {
                        "status": "success",
                        "data": {
                            "id": 7,
                            "UserId": 11,
                            "Products": [{"id": 2, "name": "Synthetic Product B"}],
                        },
                    },
                    authenticated=False,
                ),
            ),
        ],
    )

    endpoints = _endpoints(workspace).endpoints
    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.path == "/rest/basket/{basketId}"
    assert endpoint.resource.type == "Basket"
    assert endpoint.authentication.required is False
    assert endpoint.security_relevance >= 6
    parameter = next(item for item in endpoint.parameters if item.name == "basketId")
    assert parameter.semantic_type == "object_identifier"
    assert parameter.client_controlled is True

    assert len(endpoint.object_access) == 1
    binding = endpoint.object_access[0]
    assert binding.identifier == "basketId"
    assert binding.owner_field_path == "$.data.UserId"
    assert binding.distinct_actors == 2
    assert binding.distinct_objects == 2
    assert binding.distinct_owner_values == 2
    assert binding.actor_object_binding_observed is True
    assert {item.actor for item in binding.baselines} == {"ACCOUNT_A", "ACCOUNT_B"}
    assert {item.requested_value for item in binding.baselines} == {"6", "7"}
    assert {item.response_object_path for item in binding.baselines} == {"$.data.id"}
    assert len({item.owner_value_fingerprint for item in binding.baselines}) == 2

    active = [
        item
        for item in _records(workspace).hypotheses
        if item.category == "authorization" and item.disposition == "ACTIVE"
    ]
    assert len(active) == 1
    hypothesis = active[0]
    assert hypothesis.title == (
        "Potential unauthenticated cross-account Basket access through basketId on "
        "GET /rest/basket/{basketId}"
    )
    assert hypothesis.scores.total == 15
    assert hypothesis.generation_rule == {"id": "AUTH_OBJECT_ACCESS", "version": "3"}
    assert "Cross-substitution has not yet been tested" in hypothesis.reasoning
    assert "no request authentication credential observed" in hypothesis.eligibility_evidence
    assert any("Account A requesting Account B" in item for item in hypothesis.missing_evidence)
    assert any("Account B requesting Account A" in item for item in hypothesis.missing_evidence)


def test_public_product_baselines_do_not_promote_bola(tmp_path: Path) -> None:
    workspace = _multi_actor_workspace(
        tmp_path,
        [
            (
                "ACCOUNT_A",
                _entry(
                    1,
                    "GET",
                    "/api/products/1",
                    {
                        "data": {
                            "id": 1,
                            "merchantId": 100,
                            "name": "Synthetic Product A",
                            "price": 10,
                        }
                    },
                    authenticated=False,
                ),
            ),
            (
                "ACCOUNT_B",
                _entry(
                    2,
                    "GET",
                    "/api/products/2",
                    {
                        "data": {
                            "id": 2,
                            "merchantId": 200,
                            "name": "Synthetic Product B",
                            "price": 20,
                        }
                    },
                    authenticated=False,
                ),
            ),
        ],
    )

    endpoint = _endpoints(workspace).endpoints[0]
    assert endpoint.resource.type == "Product"
    assert endpoint.object_access[0].actor_object_binding_observed is True
    assert not any(
        item.category == "authorization" and item.disposition == "ACTIVE"
        for item in _records(workspace).hypotheses
    )


def test_multiple_objects_per_actor_preserve_account_scoped_binding(tmp_path: Path) -> None:
    workspace = _multi_actor_workspace(
        tmp_path,
        [
            (
                "ACCOUNT_A",
                _entry(
                    1,
                    "GET",
                    "/rest/basket/6",
                    {"status": "success", "data": {"id": 6, "UserId": 10}},
                    authenticated=False,
                ),
            ),
            (
                "ACCOUNT_A",
                _entry(
                    2,
                    "GET",
                    "/rest/basket/8",
                    {"status": "success", "data": {"id": 8, "UserId": 10}},
                    authenticated=False,
                ),
            ),
            (
                "ACCOUNT_B",
                _entry(
                    3,
                    "GET",
                    "/rest/basket/7",
                    {"status": "success", "data": {"id": 7, "UserId": 11}},
                    authenticated=False,
                ),
            ),
            (
                "ACCOUNT_B",
                _entry(
                    4,
                    "GET",
                    "/rest/basket/9",
                    {"status": "success", "data": {"id": 9, "UserId": 11}},
                    authenticated=False,
                ),
            ),
        ],
    )

    endpoint = _endpoints(workspace).endpoints[0]
    assert endpoint.object_access[0].actor_object_binding_observed is True
    assert endpoint.object_access[0].distinct_objects == 4
    assert (
        sum(
            item.category == "authorization" and item.disposition == "ACTIVE"
            for item in _records(workspace).hypotheses
        )
        == 1
    )


def test_one_actor_basket_baseline_does_not_promote_cross_account_bola(tmp_path: Path) -> None:
    workspace = _multi_actor_workspace(
        tmp_path,
        [
            (
                "ACCOUNT_A",
                _entry(
                    1,
                    "GET",
                    "/rest/basket/6",
                    {"status": "success", "data": {"id": 6, "UserId": 10}},
                    authenticated=False,
                ),
            ),
            (
                "ACCOUNT_A",
                _entry(
                    2,
                    "GET",
                    "/rest/basket/8",
                    {"status": "success", "data": {"id": 8, "UserId": 10}},
                    authenticated=False,
                ),
            ),
        ],
    )

    assert not any(
        item.category == "authorization" and item.disposition == "ACTIVE"
        for item in _records(workspace).hypotheses
    )


def test_distinct_objects_without_owner_signal_do_not_promote_bola(tmp_path: Path) -> None:
    workspace = _multi_actor_workspace(
        tmp_path,
        [
            (
                "ACCOUNT_A",
                _entry(
                    1,
                    "GET",
                    "/api/private-records/6",
                    {"data": {"id": 6, "label": "Synthetic Record A"}},
                    authenticated=False,
                ),
            ),
            (
                "ACCOUNT_B",
                _entry(
                    2,
                    "GET",
                    "/api/private-records/7",
                    {"data": {"id": 7, "label": "Synthetic Record B"}},
                    authenticated=False,
                ),
            ),
        ],
    )

    endpoint = _endpoints(workspace).endpoints[0]
    assert endpoint.object_access == []
    assert not any(
        item.category == "authorization" and item.disposition == "ACTIVE"
        for item in _records(workspace).hypotheses
    )
