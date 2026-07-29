"""Interactive workspace setup wizard tests."""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from finsec.cli import app
from finsec.config.models import AnalysisConfig, TargetDocument
from finsec.errors import FinsecError, WorkspaceError
from finsec.modeling.models import ObservationStore
from finsec.setup import (
    AccountInput,
    HarSelection,
    build_setup_config,
    create_setup_workspace,
    ingest_har_selections,
    normalize_host,
    update_gitignore,
    validate_capture_relative,
)
from finsec.utils.yaml_store import load_yaml

RUNNER = CliRunner()


def _setup_args(tmp_path: Path, slug: str = "divar") -> list[str]:
    return [
        "setup",
        "--name",
        "Divar",
        "--slug",
        slug,
        "--host",
        "divar.ir",
        "--host",
        "api.divar.ir",
        "--account",
        "ACCOUNT_A",
        "--account",
        "ACCOUNT_B",
        "--workspace-root",
        str(tmp_path / "workspaces"),
        "--capture-root",
        str(tmp_path / "captures"),
    ]


def _run_noninteractive_setup(tmp_path: Path, slug: str = "divar") -> Path:
    result = RUNNER.invoke(app, [*_setup_args(tmp_path, slug), "--yes"])
    assert result.exit_code == 0, result.output
    return tmp_path / "workspaces" / slug


def _basic_config(**overrides: Any) -> Any:
    values: dict[str, Any] = {
        "project_name": "Divar",
        "slug": "divar",
        "hosts": ["divar.ir", "api.divar.ir"],
        "accounts": [AccountInput("ACCOUNT_A"), AccountInput("ACCOUNT_B")],
        "production": True,
    }
    values.update(overrides)
    return build_setup_config(**values)


def test_simple_setup_creates_valid_workspace(tmp_path: Path) -> None:
    workspace = _run_noninteractive_setup(tmp_path)

    target = TargetDocument.model_validate(load_yaml(workspace / "target.yaml"))
    assert target.target.name == "Divar"
    assert target.target.slug == "divar"
    assert target.scope.hosts == ["divar.ir", "api.divar.ir"]
    assert [account.id for account in target.accounts] == ["ACCOUNT_A", "ACCOUNT_B"]
    assert all(account.ownership == "researcher" for account in target.accounts)
    assert (workspace / "SETUP_SUMMARY.md").is_file()


def test_advanced_setup_applies_optional_settings(tmp_path: Path) -> None:
    answers = "\n".join(
        [
            "",  # production
            "https://api.divar.ir/v1",  # target base URL
            "y",  # advanced
            "extra.divar.ir",
            "ads.example.com",
            "",  # static suppression
            "",  # telemetry suppression
            "",  # analytics suppression
            "",  # third-party suppression
            "/custom/",
            "avif",
            "n",  # advanced account attributes
            "",  # retain prohibited restrictions
            "authorization, authentication, state_transitions",
            "",  # BOLA gate
            "",  # state gate
            "",  # financial gate
            "custom/divar",
            "",  # create
            "n",  # HAR discovery
        ]
    )
    result = RUNNER.invoke(app, _setup_args(tmp_path), input=answers + "\n")
    assert result.exit_code == 0, result.output

    target = TargetDocument.model_validate(load_yaml(tmp_path / "workspaces/divar/target.yaml"))
    assert target.analysis.include_hosts == [
        "divar.ir",
        "api.divar.ir",
        "extra.divar.ir",
    ]
    assert target.analysis.exclude_hosts == ["ads.example.com"]
    assert target.target.base_url == "https://api.divar.ir/v1"
    assert "/custom/" in target.analysis.excluded_path_patterns
    assert "avif" in target.analysis.excluded_extensions
    assert target.focus == ["authorization", "authentication", "state_transitions"]
    assert (tmp_path / "captures/custom/divar/incoming").is_dir()


def test_default_settings_are_safe() -> None:
    target = _basic_config().target

    assert target.testing.production is True
    assert target.testing.synthetic is False
    assert target.testing.local_lab is False
    assert target.testing.human_approval_required is True
    assert target.testing.destructive_testing is False
    assert target.testing.active_execution_enabled is False
    assert target.testing.maximum_parallel_requests == 1
    assert target.testing.maximum_requests_per_plan == 3
    assert target.testing.read_only_only is True
    assert not any(target.restrictions.model_dump(mode="json").values())
    assert all(target.analysis.suppress.model_dump(mode="json").values())


def test_duplicate_account_labels_are_rejected() -> None:
    with pytest.raises(FinsecError, match="unique"):
        _basic_config(accounts=[AccountInput("ACCOUNT_A"), AccountInput("ACCOUNT_A")])


def test_invalid_slug_is_rejected() -> None:
    with pytest.raises(WorkspaceError):
        _basic_config(slug="../divar")


def test_empty_scope_is_rejected() -> None:
    with pytest.raises(FinsecError, match="in-scope host"):
        _basic_config(hosts=[])


def test_scope_hosts_are_normalized_without_broadening() -> None:
    config = _basic_config(hosts=["https://api.divar.ir/", "divar.ir/path", "*.static.divar.ir"])
    assert config.target.scope.hosts == ["api.divar.ir", "divar.ir", "*.static.divar.ir"]
    with pytest.raises(FinsecError, match="IP ranges"):
        normalize_host("10.0.0.0/24")
    with pytest.raises(FinsecError, match="synthetic"):
        normalize_host("localhost")


@pytest.mark.parametrize("value", ["../divar", "/tmp/divar", "divar/../other"])
def test_capture_path_traversal_is_rejected(value: str) -> None:
    with pytest.raises(FinsecError):
        validate_capture_relative(value)


@pytest.mark.parametrize(
    "label",
    [
        "Bearer SECRET_VALUE",
        "user@example.com",
        "eyJabcdefgh.abcdefgh.abcdefgh",
        "PASSWORD",
        "ACCOUNT_TOKEN",
    ],
)
def test_credentials_are_not_accepted(label: str) -> None:
    with pytest.raises(FinsecError):
        _basic_config(accounts=[AccountInput(label)])


def test_existing_workspace_is_not_overwritten(tmp_path: Path) -> None:
    workspace = _run_noninteractive_setup(tmp_path)
    original = (workspace / "target.yaml").read_bytes()

    second = RUNNER.invoke(app, [*_setup_args(tmp_path), "--yes"])

    assert second.exit_code == 1
    assert "already exists" in second.output
    assert (workspace / "target.yaml").read_bytes() == original


def test_setup_resume_continues_only_incomplete_actor_authentication(tmp_path: Path) -> None:
    workspace = _run_noninteractive_setup(tmp_path)
    original_scope = load_yaml(workspace / "target.yaml")["scope"]

    resumed = RUNNER.invoke(
        app,
        [
            "setup",
            "--workspace",
            str(workspace),
            "--capture-root",
            str(tmp_path / "captures"),
        ],
        input="5\n4\n4\n",
    )

    assert resumed.exit_code == 0, resumed.output
    target = TargetDocument.model_validate(load_yaml(workspace / "target.yaml"))
    assert target.scope.model_dump(mode="json") == original_scope
    assert all(
        actor.authentication is not None and actor.authentication.status == "MISSING"
        for actor in target.accounts
    )


def test_setup_authentication_resolves_bare_har_name_from_capture_incoming(
    tmp_path: Path,
) -> None:
    workspace = _run_noninteractive_setup(tmp_path)
    token = "opaque-synthetic-setup-token"
    har = tmp_path / "captures/divar/incoming/account-a.har"
    har.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "https://divar.ir/profile",
                                "headers": [{"name": "Authorization", "value": f"Bearer {token}"}],
                                "cookies": [],
                            },
                            "response": {"status": 200, "headers": [], "content": {}},
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    resumed = RUNNER.invoke(
        app,
        [
            "setup",
            "--workspace",
            str(workspace),
            "--capture-root",
            str(tmp_path / "captures"),
        ],
        input="5\n1\naccount-a.har\n\n4\n",
    )

    assert resumed.exit_code == 0, resumed.output
    assert token not in resumed.output
    target = TargetDocument.model_validate(load_yaml(workspace / "target.yaml"))
    account_a = next(actor for actor in target.accounts if actor.id == "ACCOUNT_A")
    assert account_a.authentication is not None
    assert account_a.authentication.status == "READY"


def test_add_missing_capture_directories_preserves_readme(tmp_path: Path) -> None:
    _run_noninteractive_setup(tmp_path)
    readme = tmp_path / "captures/divar/README.md"
    readme.write_text("# Researcher Notes\n", encoding="utf-8")

    result = RUNNER.invoke(
        app,
        [
            "setup",
            "--name",
            "Divar",
            "--slug",
            "divar",
            "--workspace-root",
            str(tmp_path / "workspaces"),
            "--capture-root",
            str(tmp_path / "captures"),
        ],
        input="3\ny\n",
    )

    assert result.exit_code == 0, result.output
    assert readme.read_text(encoding="utf-8") == "# Researcher Notes\n"


def test_target_yaml_validates(tmp_path: Path) -> None:
    workspace = _run_noninteractive_setup(tmp_path)
    document = TargetDocument.model_validate(load_yaml(workspace / "target.yaml"))
    assert document.target.slug == workspace.name


def test_har_directories_are_created(tmp_path: Path) -> None:
    _run_noninteractive_setup(tmp_path)
    capture = tmp_path / "captures/divar"
    assert all((capture / name).is_dir() for name in ("incoming", "processed", "rejected"))
    readme = (capture / "README.md").read_text(encoding="utf-8")
    assert "credential-bearing originals outside the repository" in readme
    assert "hunt ingest --capture-auth" in readme
    assert "normally creates `workflow.yaml` with `captures: []`" in readme
    assert "Non-interactive `hunt setup --yes` leaves it empty" in readme


def test_gitignore_is_updated_without_duplicates(tmp_path: Path) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("existing-entry\nworkspaces/*/observations/raw/*\n", encoding="utf-8")

    update_gitignore(gitignore)
    update_gitignore(gitignore)

    lines = gitignore.read_text(encoding="utf-8").splitlines()
    assert lines.count("captures/") == 1
    assert lines.count("*.har") == 1
    assert lines.count("workspaces/*/observations/raw/*") == 1
    assert "workspaces/*/observations/raw/" not in lines


def test_cancel_leaves_no_partial_workspace(tmp_path: Path) -> None:
    result = RUNNER.invoke(app, _setup_args(tmp_path), input="\x03")

    assert result.exit_code == 130
    assert "no partial workspace" in result.output
    assert not (tmp_path / "workspaces/divar").exists()
    assert not (tmp_path / "captures/divar").exists()


def test_optional_ingestion_uses_actor_labels(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    created = create_setup_workspace(
        _basic_config(), tmp_path / "workspaces", tmp_path / "captures"
    )
    har_path, _ = sample_har

    results = ingest_har_selections([HarSelection(har_path, "ACCOUNT_B", "WEB")], created.workspace)

    assert results[0][1] == "success"
    observations = ObservationStore.model_validate(load_yaml(created.workspace.observations))
    assert {item.actor for item in observations.observations} == {"ACCOUNT_B"}
    assert har_path.is_file()


def test_synthetic_setup_allows_localhost(tmp_path: Path) -> None:
    result = RUNNER.invoke(
        app,
        [
            "setup",
            "--name",
            "Local Demo",
            "--host",
            "localhost",
            "--account",
            "ACCOUNT_A",
            "--workspace-root",
            str(tmp_path / "workspaces"),
            "--capture-root",
            str(tmp_path / "captures"),
            "--synthetic",
            "--yes",
        ],
    )
    assert result.exit_code == 0, result.output
    target = TargetDocument.model_validate(
        load_yaml(tmp_path / "workspaces/local-demo/target.yaml")
    )
    assert target.scope.hosts == ["localhost"]
    assert target.testing.synthetic is True
    assert target.testing.local_lab is True
    assert target.testing.active_execution_enabled is False


def test_noninteractive_setup_supports_explicit_anonymous_and_privileged_actors(
    tmp_path: Path,
) -> None:
    result = RUNNER.invoke(
        app,
        [
            "setup",
            "--name",
            "Actor Types",
            "--host",
            "api.example.test",
            "--account",
            "ACCOUNT_A",
            "--anonymous-actor",
            "ANONYMOUS",
            "--privileged-actor",
            "ADMIN",
            "--workspace-root",
            str(tmp_path / "workspaces"),
            "--capture-root",
            str(tmp_path / "captures"),
            "--yes",
        ],
    )
    assert result.exit_code == 0, result.output
    target = TargetDocument.model_validate(
        load_yaml(tmp_path / "workspaces/actor-types/target.yaml")
    )
    by_id = {actor.id: actor for actor in target.accounts}
    assert by_id["ANONYMOUS"].actor_type == "anonymous"
    assert by_id["ANONYMOUS"].authentication is not None
    assert by_id["ANONYMOUS"].authentication.status == "NONE"
    assert by_id["ADMIN"].actor_type == "privileged_user"


def test_advanced_config_builder_preserves_supported_gates() -> None:
    analysis = AnalysisConfig(
        include_hosts=["divar.ir"],
        exclude_hosts=["telemetry.example.com"],
        excluded_extensions=["jpg", "avif"],
        excluded_path_patterns=["/static/", "/custom/"],
    )
    config = _basic_config(analysis=analysis, focus=["authorization", "channel_differences"])
    assert config.target.analysis.exclude_hosts == ["telemetry.example.com"]
    assert config.target.focus == ["authorization", "channel_differences"]
