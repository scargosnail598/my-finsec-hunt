"""Strongly typed target configuration models."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Reject unknown fields so workspace configuration stays explicit."""

    model_config = ConfigDict(extra="forbid")


class TargetIdentity(StrictModel):
    """Basic target identity."""

    name: str
    type: str = "fintech"


class ScopeConfig(StrictModel):
    """Authorized hosts recorded by the researcher."""

    hosts: list[str] = Field(default_factory=list)


class AccountConfig(StrictModel):
    """A non-secret account label used in observations and tests."""

    id: str
    ownership: Literal["researcher", "external"] = "researcher"


class TestingConfig(StrictModel):
    """Safety controls for later active-testing phases."""

    production: bool = False
    human_approval_required: bool = True
    destructive_testing: bool = False


class RestrictionsConfig(StrictModel):
    """Explicitly disabled test categories."""

    denial_of_service: bool = False
    brute_force: bool = False
    social_engineering: bool = False
    spam: bool = False
    destructive_actions: bool = False


class TargetDocument(StrictModel):
    """Top-level target.yaml structure."""

    target: TargetIdentity
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    accounts: list[AccountConfig] = Field(default_factory=list)
    testing: TestingConfig = Field(default_factory=TestingConfig)
    restrictions: RestrictionsConfig = Field(default_factory=RestrictionsConfig)
    focus: list[str] = Field(
        default_factory=lambda: [
            "authorization",
            "business_logic",
            "financial_workflows",
            "authentication",
            "race_conditions",
        ]
    )
