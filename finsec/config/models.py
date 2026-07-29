"""Strongly typed target configuration models."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ClassificationOverride = Literal[
    "FIRST_PARTY_API",
    "STATIC_ASSET",
    "TELEMETRY",
    "ANALYTICS",
    "THIRD_PARTY",
    "PAGE_NAVIGATION",
    "FILE_DOWNLOAD",
    "AUTHENTICATION",
    "FINANCIAL",
    "UNKNOWN",
]


class StrictModel(BaseModel):
    """Reject unknown fields so workspace configuration stays explicit."""

    model_config = ConfigDict(extra="forbid")


class TargetIdentity(StrictModel):
    """Basic target identity."""

    name: str
    slug: str | None = None
    type: str = "fintech"
    base_url: str | None = None


class ScopeConfig(StrictModel):
    """Authorized hosts recorded by the researcher."""

    hosts: list[str] = Field(default_factory=list)


class AccountAttributes(StrictModel):
    """Non-sensitive researcher-supplied account context."""

    verification_level: str = "unknown"
    channel: Literal["web", "mobile", "api", "unknown"] = "web"
    tier: str | None = None
    merchant_customer_role: str | None = None
    notes: str | None = None


AuthenticationStatus = Literal[
    "READY",
    "EXPIRING_SOON",
    "EXPIRED",
    "INVALID",
    "MISSING",
    "AVAILABLE_NOT_VALIDATED",
    "REFRESH_REQUIRED",
    "REFRESH_FAILED",
    "AUTH_CONTEXT_CHANGED",
    "NONE",
]
ActorType = Literal[
    "authenticated_user",
    "privileged_user",
    "anonymous",
    "other",
]


class AuthenticationSourceConfig(StrictModel):
    """Non-secret provenance for an actor credential profile."""

    type: Literal["har", "raw_request", "manual", "legacy_environment", "none"]
    file_reference: str | None = None
    captured_at: datetime | None = None


class AuthenticationExpirationConfig(StrictModel):
    """Locally observable credential lifetime metadata."""

    detectable: bool = False
    expires_at: datetime | None = None
    issued_at: datetime | None = None
    not_before: datetime | None = None
    last_checked_at: datetime | None = None
    source: Literal["jwt", "cookie", "target", "unknown"] = "unknown"


class AuthenticationIdentityConfig(StrictModel):
    """Non-secret, untrusted identity hints used for continuity checks."""

    subject: str | None = None
    roles: list[str] = Field(default_factory=list)
    tenant: str | None = None
    baseline_identifier_fingerprint: str | None = None
    baseline_confirmed: bool = False


class AuthenticationComponentConfig(StrictModel):
    """One replay component resolved from the secret store at execution time."""

    name: str
    location: Literal["header", "cookie", "body"] = "header"
    credential_ref: str
    purpose: Literal["access", "session", "api_key", "csrf", "refresh", "other"]
    replay_required: bool = True
    value_prefix: str = ""
    cookie_domain: str | None = None
    cookie_path: str | None = None
    cookie_session_only: bool | None = None


class AuthenticationBaselineConfig(StrictModel):
    """Previously observed read-only request safe enough for actor validation."""

    method: Literal["GET", "HEAD"]
    scheme: Literal["http", "https"]
    host: str
    port: int | None = Field(default=None, ge=1, le=65535)
    path: str
    query_parameters: dict[str, list[str]] = Field(default_factory=dict)
    safe_headers: dict[str, str] = Field(default_factory=dict)
    expected_status: int | None = None
    expected_content_type: str | None = None


class AuthenticationRefreshConfig(StrictModel):
    """Observed refresh-flow metadata; the secret request template is stored separately."""

    configured: bool = False
    flow_ref: str | None = None
    request_template_ref: str | None = None
    mode: Literal["observed_request"] | None = None
    method: str | None = None
    scheme: str | None = None
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    path: str | None = None
    response_access_path: str | None = None
    response_refresh_path: str | None = None
    expected_status: int | None = None
    expected_content_type: str | None = None
    request_budget: int = Field(default=1, ge=1, le=1)
    auto_refresh: bool = False


class ActorAuthenticationConfig(StrictModel):
    """Actor-owned authentication metadata containing references but never secret values."""

    auth_type: str
    profile_ref: str | None = None
    components: list[AuthenticationComponentConfig] = Field(default_factory=list)
    source: AuthenticationSourceConfig
    expiration: AuthenticationExpirationConfig = Field(
        default_factory=AuthenticationExpirationConfig
    )
    refresh: AuthenticationRefreshConfig = Field(default_factory=AuthenticationRefreshConfig)
    baseline: AuthenticationBaselineConfig | None = None
    identity: AuthenticationIdentityConfig = Field(default_factory=AuthenticationIdentityConfig)
    status: AuthenticationStatus
    context_fingerprint: str | None = None
    target_hosts: list[str] = Field(default_factory=list)
    last_validated_at: datetime | None = None
    legacy_environment: dict[str, str] = Field(default_factory=dict)


class AccountConfig(StrictModel):
    """A non-secret account label used in observations and tests."""

    id: str
    ownership: Literal["researcher", "external"] = "researcher"
    role: str = "user"
    authenticated: bool = True
    actor_type: ActorType | None = None
    authentication: ActorAuthenticationConfig | None = None
    attributes: AccountAttributes = Field(default_factory=AccountAttributes)


class TestingConfig(StrictModel):
    """Safety controls for later active-testing phases."""

    production: bool = False
    synthetic: bool = False
    local_lab: bool = False
    human_approval_required: bool = True
    destructive_testing: bool = False
    active_execution_enabled: bool = False
    maximum_parallel_requests: int = Field(default=1, ge=1)
    maximum_requests_per_plan: int = Field(default=3, ge=1, le=10)
    read_only_only: bool = True
    maximum_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=10 * 1024 * 1024)
    connection_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    read_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    authentication_expiring_soon_seconds: int = Field(default=300, ge=30, le=86400)
    authentication_execution_margin_seconds: int = Field(default=120, ge=30, le=3600)


class RestrictionsConfig(StrictModel):
    """Explicit program permissions; every category is denied by default."""

    denial_of_service: bool = False
    brute_force: bool = False
    social_engineering: bool = False
    spam: bool = False
    destructive_actions: bool = False
    real_user_testing: bool = False


class SuppressionConfig(StrictModel):
    """Noise classes excluded from active hypothesis generation by default."""

    static_assets: bool = True
    telemetry: bool = True
    analytics: bool = True
    third_party: bool = True


class HypothesisGateConfig(StrictModel):
    """Minimum relevance required before a candidate becomes active."""

    bola_minimum_score: int = Field(default=6, ge=0, le=10)
    state_transition_minimum_score: int = Field(default=7, ge=0, le=10)
    financial_minimum_score: int = Field(default=5, ge=0, le=10)


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
    classification_overrides: dict[str, ClassificationOverride] = Field(default_factory=dict)


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
            "replay_and_idempotency",
        ]
    )
