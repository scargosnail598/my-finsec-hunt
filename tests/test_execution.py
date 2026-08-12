"""Bounded active-validation policy and local mock-server integration tests."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import pytest
from typer.testing import CliRunner

from finsec.cli import app
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.errors import FinsecError
from finsec.execution.policy import approve_plan, prepare_execution
from finsec.execution.runner import execute_prepared
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.normalization.inventory import build_inventory
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml, write_yaml


@pytest.fixture(autouse=True)
def _synthetic_runtime_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FINSEC_ACCOUNT_A_AUTH", "Bearer SYNTHETIC_ACCOUNT_A")
    monkeypatch.setenv("FINSEC_ACCOUNT_B_AUTH", "Bearer SYNTHETIC_ACCOUNT_B")


class BasketServer(ThreadingHTTPServer):
    """Local-only deterministic server with exact request accounting."""

    mode: str
    received_paths: list[str]


class BasketHandler(BaseHTTPRequestHandler):
    server: BasketServer

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self.server.received_paths.append(self.path)
        if self.server.mode == "baseline-auth-401" and self.path == "/rest/basket/7":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"invalid token"}')
            return
        if self.server.mode == "baseline-403" and self.path == "/rest/basket/7":
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"forbidden"}')
            return
        if self.server.mode == "baseline-login" and self.path == "/rest/basket/7":
            body = (
                b'<html><form><input type="password"></form>Login '
                b"Authorization: Bearer HTML_LOGIN_SECRET</html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.server.mode == "mutation-auth-401" and self.path == "/rest/basket/6":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"expired jwt"}')
            return
        if self.server.mode == "redirect" and self.path == "/rest/basket/7":
            self.send_response(302)
            self.send_header("Location", "http://outside.example.test/private")
            self.end_headers()
            return
        if self.server.mode == "server-error" and self.path == "/rest/basket/7":
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"synthetic"}')
            return
        if self.server.mode == "oversized" and self.path == "/rest/basket/7":
            body = b"x" * 2048
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        basket_id = 7 if self.path == "/rest/basket/7" else 6
        if self.server.mode == "mismatch" and basket_id == 7:
            basket_id = 99
        if self.server.mode == "inconclusive" and basket_id == 6:
            basket_id = 7
        owner_id = 11 if basket_id in {7, 99} else 10
        body = json.dumps(
            {
                "status": "success",
                "data": {"id": basket_id, "UserId": owner_id, "Products": []},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def basket_server(mode: str = "success") -> Iterator[BasketServer]:
    server = BasketServer(("127.0.0.1", 0), BasketHandler)
    server.mode = mode
    server.received_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _entry(port: int, basket_id: int, owner_id: int) -> dict[str, Any]:
    response = {
        "status": "success",
        "data": {"id": basket_id, "UserId": owner_id, "Products": []},
    }
    return {
        "startedDateTime": "2026-07-27T10:00:00Z",
        "request": {
            "method": "GET",
            "url": f"http://127.0.0.1:{port}/rest/basket/{basket_id}",
            "headers": [
                {"name": "Accept", "value": "application/json"},
                {"name": "Authorization", "value": "Bearer SYNTHETIC_CAPTURE"},
            ],
        },
        "response": {
            "status": 200,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": json.dumps(response)},
        },
    }


def _workspace(
    tmp_path: Path,
    port: int,
    *,
    active_execution: bool = True,
    maximum_response_bytes: int = 2 * 1024 * 1024,
) -> tuple[WorkspacePaths, str]:
    workspace = create_workspace("bounded-runner", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["127.0.0.1"]
    target["accounts"] = [
        {"id": "ACCOUNT_A", "ownership": "researcher"},
        {"id": "ACCOUNT_B", "ownership": "researcher"},
    ]
    target["testing"].update(
        {
            "production": False,
            "synthetic": True,
            "local_lab": True,
            "active_execution_enabled": active_execution,
            "maximum_parallel_requests": 1,
            "maximum_requests_per_plan": 2,
            "read_only_only": True,
            "maximum_response_bytes": maximum_response_bytes,
        }
    )
    write_yaml(workspace.target, target)
    for index, (actor, basket_id, owner_id) in enumerate(
        [("ACCOUNT_A", 6, 10), ("ACCOUNT_B", 7, 11)], start=1
    ):
        capture = tmp_path / f"actor-{index}.har"
        capture.write_text(
            json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "bounded-runner-tests", "version": "1"},
                        "entries": [_entry(port, basket_id, owner_id)],
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
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    hypothesis = next(
        item
        for item in hypotheses.hypotheses
        if item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
    )
    generate_plan(workspace, hypothesis.id)
    return workspace, hypothesis.id


def _approved(workspace: WorkspacePaths, hypothesis_id: str) -> None:
    approve_plan(workspace, hypothesis_id, approved_by="pytest")


def test_authentication_comparison_plan_removes_one_runtime_marker(tmp_path: Path) -> None:
    workspace = create_workspace("auth-comparison", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [{"id": "ACCOUNT_A", "ownership": "researcher"}]
    target["testing"].update({"production": False, "active_execution_enabled": True})
    write_yaml(workspace.target, target)
    entries = [
        {
            "startedDateTime": "2026-07-27T10:00:00Z",
            "request": {
                "method": "GET",
                "url": "https://api.example.test/api/auth/profile",
                "headers": [{"name": "Authorization", "value": "Bearer SYNTHETIC"}],
            },
            "response": {
                "status": 200,
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "content": {"mimeType": "application/json", "text": '{"id":1}'},
            },
        },
        {
            "startedDateTime": "2026-07-27T10:01:00Z",
            "request": {
                "method": "GET",
                "url": "https://api.example.test/api/auth/profile",
                "headers": [],
            },
            "response": {
                "status": 200,
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "content": {"mimeType": "application/json", "text": '{"id":1}'},
            },
        },
    ]
    capture = tmp_path / "auth.har"
    capture.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "auth-comparison", "version": "1"},
                    "entries": entries,
                }
            }
        ),
        encoding="utf-8",
    )
    ingest_har(capture, workspace, actor="ACCOUNT_A", channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    hypothesis = next(item for item in hypotheses.hypotheses if item.category == "authentication")

    plan = generate_plan(workspace, hypothesis.id).plan

    assert plan.execution.pattern == "AUTHENTICATION_COMPARISON"
    assert plan.execution.supported is True
    assert len(plan.requests) == 2
    assert plan.requests[0].runtime_secrets[0].variable == "FINSEC_ACCOUNT_A_AUTH"
    assert plan.requests[1].runtime_secrets == []
    assert plan.requests[1].remove_headers == ["Authorization"]
    assert plan.requests[1].mutations[0].dimension == "AUTHENTICATION"
    approve_plan(workspace, hypothesis.id, approved_by="pytest")


def test_version_comparison_plan_uses_two_observed_read_only_routes(tmp_path: Path) -> None:
    workspace = create_workspace("version-comparison", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [{"id": "ACCOUNT_A", "ownership": "researcher"}]
    target["testing"].update({"production": False, "active_execution_enabled": True})
    write_yaml(workspace.target, target)

    def version_entry(path: str) -> dict[str, Any]:
        return {
            "startedDateTime": "2026-07-27T10:00:00Z",
            "request": {
                "method": "GET",
                "url": f"https://api.example.test{path}",
                "headers": [{"name": "Authorization", "value": "Bearer SYNTHETIC"}],
            },
            "response": {
                "status": 200,
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "content": {"mimeType": "application/json", "text": '{"id":1}'},
            },
        }

    capture = tmp_path / "versions.har"
    capture.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "version-comparison", "version": "1"},
                    "entries": [
                        version_entry("/api/v2/payments/1"),
                        version_entry("/api/v3/payments/1"),
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    ingest_har(capture, workspace, actor="ACCOUNT_A", channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    hypothesis = next(item for item in hypotheses.hypotheses if item.category == "version_parity")

    plan = generate_plan(workspace, hypothesis.id).plan

    assert plan.execution.pattern == "VERSION_COMPARISON"
    assert plan.execution.supported is True
    assert [item.path for item in plan.requests] == [
        "/api/v2/payments/1",
        "/api/v3/payments/1",
    ]
    assert plan.requests[1].mutations[0].dimension == "VERSION"
    approve_plan(workspace, hypothesis.id, approved_by="pytest")


def test_channel_comparison_plan_uses_two_observed_read_only_channels(tmp_path: Path) -> None:
    workspace = create_workspace("channel-comparison", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [{"id": "ACCOUNT_A", "ownership": "researcher"}]
    target["testing"].update({"production": False, "active_execution_enabled": True})
    write_yaml(workspace.target, target)
    for index, channel in enumerate(["WEB", "MOBILE"], start=1):
        capture = tmp_path / f"channel-{index}.har"
        capture.write_text(
            json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "channel-comparison", "version": str(index)},
                        "entries": [
                            {
                                "startedDateTime": f"2026-07-2{index}T10:00:00Z",
                                "request": {
                                    "method": "GET",
                                    "url": "https://api.example.test/api/profile",
                                    "headers": [
                                        {
                                            "name": "Authorization",
                                            "value": "Bearer SYNTHETIC",
                                        }
                                    ],
                                },
                                "response": {
                                    "status": 200,
                                    "headers": [
                                        {"name": "Content-Type", "value": "application/json"}
                                    ],
                                    "content": {
                                        "mimeType": "application/json",
                                        "text": '{"id":1}',
                                    },
                                },
                            }
                        ],
                    }
                }
            ),
            encoding="utf-8",
        )
        ingest_har(capture, workspace, actor="ACCOUNT_A", channel=cast(Any, channel))
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    hypothesis = next(item for item in hypotheses.hypotheses if item.category == "channel_parity")

    plan = generate_plan(workspace, hypothesis.id).plan

    assert plan.execution.pattern == "CHANNEL_COMPARISON"
    assert plan.execution.supported is True
    assert [item.channel for item in plan.requests] == ["WEB", "MOBILE"]
    assert plan.requests[1].mutations[0].dimension == "CHANNEL"
    approve_plan(workspace, hypothesis.id, approved_by="pytest")


def test_dry_run_sends_zero_requests_and_incomplete_approval_is_refused(tmp_path: Path) -> None:
    with basket_server() as server:
        workspace, hypothesis_id = _workspace(tmp_path, server.server_port)
        _approved(workspace, hypothesis_id)
        prepared = prepare_execution(workspace, hypothesis_id, dry_run=True)
        assert len(prepared.plan.requests) == 2
        assert prepared.plan.execution.mutation_dimensions == ["OBJECT"]
        assert server.received_paths == []

        document = load_yaml(workspace.test_plans)
        document["plans"][0]["approval"] = None
        write_yaml(workspace.test_plans, document)
        with pytest.raises(FinsecError, match="approval_status alone"):
            prepare_execution(workspace, hypothesis_id, dry_run=False)
        assert server.received_paths == []


def test_successful_object_substitution_sends_two_requests_and_writes_redacted_evidence(
    tmp_path: Path,
) -> None:
    with basket_server() as server:
        workspace, hypothesis_id = _workspace(tmp_path, server.server_port)
        _approved(workspace, hypothesis_id)
        result = execute_prepared(prepare_execution(workspace, hypothesis_id, dry_run=False))

        assert server.received_paths == ["/rest/basket/7", "/rest/basket/6"]
        assert result.requests_sent == 2
        assert result.comparison.outcome == "CROSS_OBJECT_RESPONSE_OBSERVED"
        evidence_root = Path(result.evidence_root) / "executions/execution-v1"
        assert (evidence_root / "baseline-request.txt").is_file()
        assert (evidence_root / "mutated-request.txt").is_file()
        assert (evidence_root / "comparison.yaml").is_file()
        responses = (evidence_root / "baseline-response.json").read_text(encoding="utf-8")
        responses += (evidence_root / "mutated-response.json").read_text(encoding="utf-8")
        assert '"UserId": 10' not in responses
        assert '"UserId": 11' not in responses
        assert "OWNER-FINGERPRINT" in responses
        audit = load_yaml(Path(result.audit_path))
        assert audit["request_count"] == 2
        assert audit["outcome"] == "CROSS_OBJECT_RESPONSE_OBSERVED"
        assert audit["status"] == "COMPLETED"
        assert result.status == "COMPLETED"
        hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
        hypothesis = next(item for item in hypotheses.hypotheses if item.id == hypothesis_id)
        assert hypothesis.status == "TEST_PLANNED"


def test_non_interactive_local_lab_requires_the_approved_environment_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with basket_server() as server:
        workspace, hypothesis_id = _workspace(tmp_path, server.server_port)
        approve_plan(
            workspace,
            hypothesis_id,
            approved_by="pytest",
            approval_token="synthetic-approval-token",
        )
        monkeypatch.setenv("FINSEC_TEST_APPROVAL", "wrong-token")
        with pytest.raises(FinsecError, match="does not match"):
            prepare_execution(
                workspace,
                hypothesis_id,
                dry_run=False,
                non_interactive=True,
                approval_token_env="FINSEC_TEST_APPROVAL",
            )
        assert server.received_paths == []

        monkeypatch.setenv("FINSEC_TEST_APPROVAL", "synthetic-approval-token")
        prepared = prepare_execution(
            workspace,
            hypothesis_id,
            dry_run=False,
            non_interactive=True,
            approval_token_env="FINSEC_TEST_APPROVAL",
        )
        assert prepared.plan.approval is not None
        assert server.received_paths == []


def test_inconclusive_comparison_uses_inconclusive_execution_status(tmp_path: Path) -> None:
    with basket_server("inconclusive") as server:
        workspace, hypothesis_id = _workspace(tmp_path, server.server_port)
        _approved(workspace, hypothesis_id)
        result = execute_prepared(prepare_execution(workspace, hypothesis_id, dry_run=False))

        assert server.received_paths == ["/rest/basket/7", "/rest/basket/6"]
        assert result.comparison.outcome == "INCONCLUSIVE"
        assert result.status == "INCONCLUSIVE"
        assert load_yaml(Path(result.audit_path))["status"] == "INCONCLUSIVE"


def test_partial_evidence_revision_is_never_reused(tmp_path: Path) -> None:
    with basket_server() as server:
        workspace, hypothesis_id = _workspace(tmp_path, server.server_port)
        partial = workspace.evidence_for(hypothesis_id) / "executions" / "execution-v1"
        partial.mkdir(parents=True)
        (partial / "partial.txt").write_text("previous interrupted write\n", encoding="utf-8")
        _approved(workspace, hypothesis_id)

        result = execute_prepared(prepare_execution(workspace, hypothesis_id, dry_run=False))

        assert Path(result.audit_path).name == "execution-v2.yaml"
        assert (Path(result.evidence_root) / "executions/execution-v2/comparison.yaml").is_file()
        assert (partial / "partial.txt").read_text(encoding="utf-8") == (
            "previous interrupted write\n"
        )


@pytest.mark.parametrize(
    ("mode", "maximum_response_bytes", "expected_outcome"),
    [
        ("mismatch", 2 * 1024 * 1024, "BASELINE_MISMATCH"),
        ("redirect", 2 * 1024 * 1024, "OUT_OF_SCOPE_REDIRECT"),
        ("oversized", 1024, "RESPONSE_SIZE_EXCEEDED"),
        ("server-error", 2 * 1024 * 1024, "BASELINE_FAILED"),
    ],
)
def test_baseline_stop_conditions_prevent_the_mutated_request(
    tmp_path: Path,
    mode: str,
    maximum_response_bytes: int,
    expected_outcome: str,
) -> None:
    with basket_server(mode) as server:
        workspace, hypothesis_id = _workspace(
            tmp_path,
            server.server_port,
            maximum_response_bytes=maximum_response_bytes,
        )
        _approved(workspace, hypothesis_id)
        result = execute_prepared(prepare_execution(workspace, hypothesis_id, dry_run=False))

        assert server.received_paths == ["/rest/basket/7"]
        assert result.requests_sent == 1
        assert result.comparison.outcome == expected_outcome


@pytest.mark.parametrize(
    ("mode", "expected_outcome"),
    [
        ("baseline-auth-401", "BASELINE_AUTH_FAILED"),
        ("baseline-login", "BASELINE_AUTH_FAILED"),
        ("baseline-403", "BASELINE_AUTHORIZATION_DENIED"),
    ],
)
def test_authentication_and_authorization_baseline_failures_stay_distinct(
    tmp_path: Path, mode: str, expected_outcome: str
) -> None:
    with basket_server(mode) as server:
        workspace, hypothesis_id = _workspace(tmp_path, server.server_port)
        _approved(workspace, hypothesis_id)

        result = execute_prepared(prepare_execution(workspace, hypothesis_id, dry_run=False))

        assert server.received_paths == ["/rest/basket/7"]
        assert result.requests_sent == 1
        assert result.comparison.outcome == expected_outcome
        assert result.status == "STOPPED"
        if mode == "baseline-login":
            evidence = Path(result.evidence_root) / "executions/execution-v1/baseline-response.json"
            text = evidence.read_text(encoding="utf-8")
            assert "HTML_LOGIN_SECRET" not in text


def test_authentication_failure_after_valid_baseline_blocks_result_interpretation(
    tmp_path: Path,
) -> None:
    with basket_server("mutation-auth-401") as server:
        workspace, hypothesis_id = _workspace(tmp_path, server.server_port)
        _approved(workspace, hypothesis_id)

        result = execute_prepared(prepare_execution(workspace, hypothesis_id, dry_run=False))

        assert server.received_paths == ["/rest/basket/7", "/rest/basket/6"]
        assert result.comparison.outcome == "TEST_BLOCKED_BY_AUTH"
        assert result.status == "STOPPED"


@pytest.mark.parametrize(
    "mutation",
    ["blocked", "out-of-scope", "multi-dimension", "hidden-auth-change", "post"],
)
def test_invalid_or_unsafe_plans_send_zero_requests(tmp_path: Path, mutation: str) -> None:
    with basket_server() as server:
        workspace, hypothesis_id = _workspace(tmp_path, server.server_port)
        _approved(workspace, hypothesis_id)
        document = load_yaml(workspace.test_plans)
        plan = document["plans"][0]
        if mutation == "blocked":
            plan["status"] = "BLOCKED"
        elif mutation == "out-of-scope":
            plan["requests"][0]["host"] = "outside.example.test"
        elif mutation == "multi-dimension":
            plan["execution"]["mutation_dimensions"] = ["OBJECT", "VERSION"]
        elif mutation == "hidden-auth-change":
            plan["requests"][1]["remove_headers"] = ["Authorization"]
        else:
            plan["requests"][0]["method"] = "POST"
        write_yaml(workspace.test_plans, document)

        with pytest.raises(FinsecError):
            prepare_execution(workspace, hypothesis_id, dry_run=False)
        assert server.received_paths == []


def test_ctrl_c_stops_without_sending_an_additional_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with basket_server() as server:
        workspace, hypothesis_id = _workspace(tmp_path, server.server_port)
        _approved(workspace, hypothesis_id)
        prepared = prepare_execution(workspace, hypothesis_id, dry_run=False)

        def interrupt(*args: object, **kwargs: object) -> Any:
            raise KeyboardInterrupt

        monkeypatch.setattr("finsec.execution.runner._send_request", interrupt)
        result = execute_prepared(prepared)

        assert result.comparison.outcome == "INTERRUPTED"
        assert result.requests_sent == 0
        assert server.received_paths == []
        audit = load_yaml(Path(result.audit_path))
        assert audit["status"] == "STOPPED"
        assert audit["request_count"] == 0


def test_cli_explains_checksum_bound_approval_requirement(tmp_path: Path) -> None:
    runner = CliRunner()
    with basket_server() as server:
        workspace, hypothesis_id = _workspace(tmp_path, server.server_port)
        document = load_yaml(workspace.test_plans)
        document["plans"][0]["approval_status"] = "APPROVED"
        write_yaml(workspace.test_plans, document)

        result = runner.invoke(
            app,
            ["execute", hypothesis_id, "--workspace", str(workspace.root)],
        )

        assert result.exit_code == 1
        assert "approval_status alone is not sufficient" in result.output
        assert "Requests sent: 0" in result.output
        assert server.received_paths == []


def test_unsupported_plan_reports_its_blocker_before_budget_validation(tmp_path: Path) -> None:
    workspace, hypothesis_id = _workspace(tmp_path, 9)
    document = load_yaml(workspace.test_plans)
    plan = document["plans"][0]
    plan["requests"] = []
    plan["authentication"] = []
    plan["execution"].update(
        {
            "supported": False,
            "pattern": "UNSUPPORTED",
            "blockers": ["Two controlled actor-object-owner baselines are required."],
            "request_budget": 0,
            "mutation_dimensions": [],
        }
    )
    write_yaml(workspace.test_plans, document)

    with pytest.raises(FinsecError, match="Two controlled actor-object-owner baselines"):
        approve_plan(workspace, hypothesis_id, approved_by="pytest")

    stored = load_yaml(workspace.test_plans)["plans"][0]
    assert stored["approval_status"] == "NOT_REQUESTED"
    assert "approval" not in stored
