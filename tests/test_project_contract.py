"""Static project contract tests."""

import json
from pathlib import Path


def test_json_schemas_are_valid() -> None:
    root = Path(__file__).parents[1]
    schemas = sorted((root / "schemas").glob("*.schema.json"))
    assert {path.name for path in schemas} == {
        "endpoint.schema.json",
        "graphql-operation.schema.json",
        "hypothesis.schema.json",
        "mobile-discovery.schema.json",
        "observation.schema.json",
        "target.schema.json",
    }
    for schema in schemas:
        assert json.loads(schema.read_text(encoding="utf-8"))["$schema"]


def test_phase_one_has_no_llm_runtime_dependency() -> None:
    root = Path(__file__).parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8").lower()
    assert "openai" not in pyproject
    assert "anthropic" not in pyproject
