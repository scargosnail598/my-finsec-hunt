"""Phase 5 passive GraphQL and mobile reconnaissance tests."""

import json
import zipfile
from pathlib import Path

import pytest

from finsec.config.workspace import create_workspace
from finsec.errors import FinsecError
from finsec.hypotheses.domain import HypothesisStore
from finsec.modeling.models import ObservationStore
from finsec.recon.domain import GraphQLStore, MobileDiscoveryStore
from finsec.recon.graphql import ingest_graphql
from finsec.recon.mobile import scan_mobile
from finsec.utils.yaml_store import load_yaml, write_yaml


def test_graphql_sdl_inventory_supports_custom_roots_and_preserves_edits(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces")
    source = tmp_path / "schema.graphql"
    source.write_text(
        """
        schema { query: RootQuery mutation: RootMutation }
        type RootQuery {
          payment(id: ID!): Payment!
        }
        extend type RootQuery {
          payments(limit: Int = 10): [Payment!]!
        }
        type RootMutation {
          cancelPayment(id: ID!, password: String = "GRAPHQL_SECRET"): Payment
            @requiresRole(role: ADMIN)
        }
        """,
        encoding="utf-8",
    )

    first = ingest_graphql(source, workspace, endpoint="https://api.example.test/graphql")
    store = GraphQLStore.model_validate(load_yaml(workspace.graphql))

    assert first.operations == 3
    assert {(item.operation_type, item.field) for item in store.operations} == {
        ("query", "payment"),
        ("query", "payments"),
        ("mutation", "cancelPayment"),
    }
    payments = next(item for item in store.operations if item.field == "payments")
    assert payments.return_type == "[Payment!]!"
    assert [(item.name, item.type) for item in payments.arguments] == [("limit", "Int")]
    assert "GRAPHQL_SECRET" not in first.redacted_capture.read_text(encoding="utf-8")
    assert all("not confirmed" in (item.notes or "") for item in store.operations)

    document = load_yaml(workspace.graphql)
    document["operations"][0]["notes"] = "Researcher annotation"
    write_yaml(workspace.graphql, document)
    second = ingest_graphql(source, workspace, endpoint="https://api.example.test/graphql")
    preserved = GraphQLStore.model_validate(load_yaml(workspace.graphql))

    assert second.conflicts
    assert any(item.notes == "Researcher annotation" for item in preserved.operations)


def test_graphql_introspection_inventory_extracts_wrapped_types(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces")
    source = tmp_path / "introspection.json"
    document = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "subscriptionType": None,
                "types": [
                    {
                        "name": "Query",
                        "fields": [
                            {
                                "name": "transactions",
                                "args": [
                                    {
                                        "name": "walletId",
                                        "type": {
                                            "kind": "NON_NULL",
                                            "name": None,
                                            "ofType": {"kind": "SCALAR", "name": "ID"},
                                        },
                                    }
                                ],
                                "type": {
                                    "kind": "NON_NULL",
                                    "name": None,
                                    "ofType": {
                                        "kind": "LIST",
                                        "name": None,
                                        "ofType": {"kind": "OBJECT", "name": "Transaction"},
                                    },
                                },
                            }
                        ],
                    }
                ],
            }
        }
    }
    source.write_text(json.dumps(document), encoding="utf-8")

    result = ingest_graphql(source, workspace)
    store = GraphQLStore.model_validate(load_yaml(workspace.graphql))

    assert result.operations == 1
    assert store.operations[0].return_type == "[Transaction]!"
    assert store.operations[0].arguments[0].type == "ID!"


def test_mobile_directory_scan_extracts_only_static_leads(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces")
    artifact = tmp_path / "jadx"
    artifact.mkdir()
    (artifact / "strings.txt").write_text(
        "\n".join(
            [
                "https://mobile:URL_PASSWORD@api.example.test/api/v2/payments?access_token=MOBILE_SECRET",
                "https://api.example.test/graphql",
                "wss://stream.example.test/events",
                "fintech-demo://withdrawals/confirm",
                "/api/v1/refunds/{refundId}",
                "X-Client-Version",
            ]
        ),
        encoding="utf-8",
    )

    first = scan_mobile(artifact, workspace)
    second = scan_mobile(artifact, workspace)
    store = MobileDiscoveryStore.model_validate(load_yaml(workspace.mobile_discoveries))

    assert first.files_scanned == 1
    assert first.discoveries >= 6
    assert second.discoveries == first.discoveries
    kinds = {item.kind for item in store.discoveries}
    assert {
        "BASE_URL",
        "API_PATH",
        "GRAPHQL_ENDPOINT",
        "WEBSOCKET",
        "DEEP_LINK",
        "CUSTOM_HEADER",
    } <= kinds
    stored = workspace.mobile_discoveries.read_text(encoding="utf-8")
    assert "URL_PASSWORD" not in stored
    assert "MOBILE_SECRET" not in stored
    assert "REDACTED" in stored
    assert all("not confirmed" in item.notes for item in store.discoveries)

    observations = ObservationStore.model_validate(load_yaml(workspace.observations))
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    assert observations.observations == []
    assert hypotheses.hypotheses == []


def test_mobile_apk_scan_is_bounded_without_extracting_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces")
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/config.txt", "https://api.example.test/api/v1/wallets")

    result = scan_mobile(apk, workspace)
    assert result.files_scanned == 1
    assert not (workspace.root / "observations/mobile/sample.apk").exists()

    import finsec.recon.mobile as mobile

    monkeypatch.setattr(mobile, "MAX_TOTAL_BYTES", 8)
    with pytest.raises(FinsecError, match="uncompressed content"):
        scan_mobile(apk, workspace)
