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


class SuppressionConfig(StrictModel):
    """Noise classes excluded from active hypothesis generation by default."""

    static_assets: bool = True
    telemetry: bool = True
    analytics: bool = True
    third_party: bool = True


class HypothesisGateConfig(StrictModel):
    """Minimum relevance required before a candidate becomes active."""

    bola_minimum_score: int = 6
    state_transition_minimum_score: int = 7
    financial_minimum_score: int = 5


class AnalysisConfig(StrictModel):
    """Researcher-editable deterministic classification and gating policy."""

    include_hosts: list[str] = Field(default_factory=list)
    exclude_hosts: list[str] = Field(default_factory=list)
    suppress: SuppressionConfig = Field(default_factory=SuppressionConfig)
    excluded_extensions: list[str] = Field(
        default_factory=lambda: [
            "jpg",
            "jpeg",
            "png",
            "webp",
            "gif",
            "svg",
            "ico",
            "css",
            "js",
            "map",
            "woff",
            "woff2",
            "ttf",
            "eot",
            "mp4",
            "webm",
        ]
    )
    excluded_path_patterns: list[str] = Field(
        default_factory=lambda: [
            "/static/",
            "/assets/",
            "/images/",
            "/img/",
            "/fonts/",
            "/css/",
            "/js/",
            "/media/",
            "/gen_204",
            "/envelope/",
            "/client-exporter/",
            "/actionlog/",
        ]
    )
    hypothesis_gates: HypothesisGateConfig = Field(default_factory=HypothesisGateConfig)
    classification_overrides: dict[str, str] = Field(default_factory=dict)


class TargetDocument(StrictModel):
    """Top-level target.yaml structure."""

    target: TargetIdentity
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    accounts: list[AccountConfig] = Field(default_factory=list)
    testing: TestingConfig = Field(default_factory=TestingConfig)
    restrictions: RestrictionsConfig = Field(default_factory=RestrictionsConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    focus: list[str] = Field(
        default_factory=lambda: [
            "authorization",
            "business_logic",
            "financial_workflows",
            "authentication",
            "race_conditions",
        ]
    )
