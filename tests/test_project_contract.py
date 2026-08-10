"""Static project contract tests."""

import json
from pathlib import Path

import yaml


def test_json_schemas_are_valid() -> None:
    root = Path(__file__).parents[1]
    schemas = sorted((root / "schemas").glob("*.schema.json"))
    assert {path.name for path in schemas} == {
        "actor-authentication.schema.json",
        "behavior-workflow.schema.json",
        "business-invariant.schema.json",
        "business-logic-hypothesis.schema.json",
        "capture.schema.json",
        "endpoint.schema.json",
        "graphql-operation.schema.json",
        "hypothesis.schema.json",
        "mobile-discovery.schema.json",
        "observation.schema.json",
        "target.schema.json",
        "workflow.schema.json",
    }
    for schema in schemas:
        assert json.loads(schema.read_text(encoding="utf-8"))["$schema"]


def test_project_has_no_llm_runtime_dependency() -> None:
    root = Path(__file__).parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8").lower()
    assert "openai" not in pyproject
    assert "anthropic" not in pyproject


def test_github_workflows_are_parseable_and_use_read_only_permissions() -> None:
    root = Path(__file__).parents[1]
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    assert {path.name for path in workflows} == {"ci.yml", "synthetic-validation.yml"}
    for path in workflows:
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        assert document["permissions"] == {"contents": "read"}
