"""Strongly typed target configuration models."""

from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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

DEFAULT_TRUSTED_OWNERSHIP_SCOPE_PARAMETERS = [
    "accountId",
    "tenantId",
    "organizationId",
    "orgId",
    "workspaceId",
    "customerId",
]
DEFAULT_PUBLIC_SHARED_SCOPE_PARAMETERS = [
    "regionId",
    "zoneId",
    "productId",
    "categoryId",
    "countryId",
    "languageId",
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

    type: Literal["har", "burp_xml", "raw_request", "manual", "legacy_environment", "none"]
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
    confirmed: bool = False
    confirmed_at: datetime | None = None
    confirmation_reference: str | None = None
    last_assertion_status: Literal[
        "NOT_CONFIGURED",
        "NOT_CHECKED",
        "CONFIRMED",
        "STATUS_MISMATCH",
        "LOGIN_OR_ERROR_RESPONSE",
        "MALFORMED_BODY",
        "SELECTOR_MISSING",
        "SELECTOR_AMBIGUOUS",
        "EXPECTED_VALUE_MISSING",
        "VALUE_MISMATCH",
        "LEGACY_UNTRUSTED",
    ] = "NOT_CONFIGURED"

    @model_validator(mode="before")
    @classmethod
    def discard_legacy_generic_confirmation(cls, value: Any) -> Any:
        """Old generic 2xx confirmations cannot establish actor identity."""

        if not isinstance(value, dict) or "baseline_confirmed" not in value:
            return value
        migrated = dict(value)
        legacy_confirmed = bool(migrated.pop("baseline_confirmed"))
        migrated.setdefault("confirmed", False)
        if legacy_confirmed and not migrated.get("confirmed"):
            migrated.setdefault("last_assertion_status", "LEGACY_UNTRUSTED")
        return migrated

    @model_validator(mode="after")
    def validate_confirmation_evidence(self) -> Self:
        if self.confirmed and (
            self.last_assertion_status != "CONFIRMED" or self.confirmation_reference is None
        ):
            raise ValueError(
                "confirmed actor identity requires a structured assertion status and reference"
            )
        if not self.confirmed and (
            self.confirmed_at is not None or self.confirmation_reference is not None
        ):
            raise ValueError("unconfirmed actor identity cannot retain confirmation evidence")
        return self


IdentityAssertionScalar = str | int | float | bool


class AuthenticationIdentityAssertionConfig(StrictModel):
    """Exact actor-specific response assertion evaluated without retaining response content."""

    source: Literal["JSON_BODY", "RESPONSE_HEADER"]
    selector: str
    expected_value: IdentityAssertionScalar | None = None
    expected_actor_reference: Literal[
        "account.id",
        "identity.subject",
        "identity.tenant",
    ] | None = None
    expected_status: int | None = Field(default=None, ge=200, le=299)
    redaction: Literal["OMIT", "SHA256"] = "OMIT"

    @model_validator(mode="after")
    def validate_assertion(self) -> Self:
        if (self.expected_value is None) == (self.expected_actor_reference is None):
            raise ValueError(
                "identity assertion requires exactly one expected_value or "
                "expected_actor_reference"
            )
        selector = self.selector.strip()
        if not selector:
            raise ValueError("identity assertion selector cannot be empty")
        if self.source == "JSON_BODY":
            if not selector.startswith("/") or "*" in selector:
                raise ValueError("JSON identity selectors must be exact JSON Pointers")
        else:
            lowered = selector.lower()
            unsafe_names = {
                "authorization",
                "cookie",
                "proxy-authenticate",
                "set-cookie",
                "www-authenticate",
            }
            if (
                lowered in unsafe_names
                or any(marker in lowered for marker in ("token", "secret", "api-key", "apikey"))
                or any(character in selector for character in "\r\n:\0")
            ):
                raise ValueError("identity assertion response header is not safe")
        self.selector = selector
        if isinstance(self.expected_value, str) and not self.expected_value.strip():
            raise ValueError("identity assertion expected_value cannot be empty")
        return self


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
    identity_assertion: AuthenticationIdentityAssertionConfig | None = None


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
    credential_accepted: bool = False
    credential_accepted_at: datetime | None = None
    scope_validated: bool = False
    scope_validated_at: datetime | None = None
    legacy_environment: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def discard_legacy_validation_timestamp(cls, value: Any) -> Any:
        """Do not infer current acceptance or scope validation from legacy timestamps."""

        if not isinstance(value, dict) or "last_validated_at" not in value:
            return value
        migrated = dict(value)
        migrated.pop("last_validated_at", None)
        return migrated


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


class CapturePolicy(StrictModel):
    """Low-friction defaults for session-aware passive capture ingestion."""

    preferred_style: Literal["focused_journey"] = "focused_journey"
    default_mode: Literal[
        "NORMAL_BEHAVIOR",
        "RESEARCHER_PROBE",
        "AUTHENTICATION",
        "MIXED",
        "UNKNOWN",
    ] = "NORMAL_BEHAVIOR"
    require_actor_resolution: bool = True
    infer_intent: bool = True


class HypothesisGateConfig(StrictModel):
    """Minimum relevance required before a candidate becomes active."""

    bola_minimum_score: int = Field(default=6, ge=0, le=10)
    state_transition_minimum_score: int = Field(default=7, ge=0, le=10)
    financial_minimum_score: int = Field(default=5, ge=0, le=10)


class OwnershipInferenceConfig(StrictModel):
    """Explicit path-parameter semantics used by fail-closed ownership inference."""

    trusted_parent_parameters: list[str] = Field(
        default_factory=lambda: list(DEFAULT_TRUSTED_OWNERSHIP_SCOPE_PARAMETERS)
    )
    public_shared_parameters: list[str] = Field(
        default_factory=lambda: list(DEFAULT_PUBLIC_SHARED_SCOPE_PARAMETERS)
    )


class FunctionAuthorizationRule(StrictModel):
    """Researcher-authored policy describing which roles may invoke one function."""

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str
    resource: str
    allowed_roles: list[str] = Field(min_length=1)
    rationale: str

    @field_validator("path")
    @classmethod
    def path_is_normalized(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith("/") or "?" in normalized or "#" in normalized:
            raise ValueError("path must be an absolute normalized path without query or fragment")
        return normalized

    @field_validator("resource", "rationale")
    @classmethod
    def text_is_not_empty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value cannot be empty")
        return normalized

    @field_validator("allowed_roles")
    @classmethod
    def roles_are_not_empty(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item for item in normalized):
            raise ValueError("allowed roles cannot contain empty values")
        return list(dict.fromkeys(normalized))


class JwtAlgorithmRule(StrictModel):
    """Researcher-authored policy for JWT algorithm enforcement on one endpoint."""

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str
    token_location: Literal["header", "cookie", "body", "query"]
    token_parameter: str
    rejected_algorithms: list[str] = Field(min_length=1)
    rationale: str

    @field_validator("path")
    @classmethod
    def path_is_normalized(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith("/") or "?" in normalized or "#" in normalized:
            raise ValueError("path must be an absolute normalized path without query or fragment")
        return normalized

    @field_validator("token_parameter", "rationale")
    @classmethod
    def text_is_not_empty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value cannot be empty")
        return normalized

    @field_validator("rejected_algorithms")
    @classmethod
    def algorithms_are_not_empty(cls, value: list[str]) -> list[str]:
        normalized = [item.strip().lower() for item in value]
        if any(not item for item in normalized):
            raise ValueError("rejected algorithms cannot contain empty values")
        return list(dict.fromkeys(normalized))


class EndpointSideEffectRule(StrictModel):
    """Trusted annotation that a nominally safe route has a backend side effect."""

    method: Literal["GET", "HEAD", "OPTIONS"]
    path: str
    action: str
    rationale: str
    evidence_refs: list[str] = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def side_effect_path_is_normalized(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith("/") or "?" in normalized or "#" in normalized:
            raise ValueError("path must be an absolute normalized path without query or fragment")
        return normalized

    @field_validator("action", "rationale")
    @classmethod
    def side_effect_text_is_not_empty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value cannot be empty")
        return normalized

    @field_validator("evidence_refs")
    @classmethod
    def side_effect_refs_are_not_empty(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item for item in normalized):
            raise ValueError("evidence refs cannot contain empty values")
        return list(dict.fromkeys(normalized))


class DomainIntentRule(StrictModel):
    """Reviewed policy annotation for a route's protected subject and access boundary."""

    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    path: str
    subject_resource: str | None = None
    parent_resource: str | None = None
    operation: (
        Literal[
            "READ",
            "CREATE",
            "CREATE_CHILD",
            "UPDATE",
            "DELETE",
            "TRANSITION",
            "VERIFY_CREDENTIAL",
            "ACTION",
            "UNKNOWN",
        ]
        | None
    ) = None
    visibility: Literal[
        "PUBLIC",
        "SHARED",
        "OWNER_SCOPED",
        "ROLE_SCOPED",
        "ACTOR_BOUND",
        "UNKNOWN",
    ]
    binding: Literal[
        "OWNERSHIP",
        "INITIATING_ACTOR",
        "PRODUCER_CONSUMER",
        "SESSION",
        "ROLE",
        "TENANT_ACCOUNT",
        "UNKNOWN",
    ] = "UNKNOWN"
    rationale: str
    evidence_refs: list[str] = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def domain_intent_path_is_normalized(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith("/") or "?" in normalized or "#" in normalized:
            raise ValueError("path must be an absolute normalized path without query or fragment")
        return normalized

    @field_validator("subject_resource", "parent_resource", "rationale")
    @classmethod
    def domain_intent_text_is_not_empty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("value cannot be empty")
        return normalized

    @field_validator("evidence_refs")
    @classmethod
    def domain_intent_refs_are_not_empty(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item for item in normalized):
            raise ValueError("evidence refs cannot contain empty values")
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def visibility_and_binding_agree(self) -> Self:
        scoped = {"OWNER_SCOPED", "ROLE_SCOPED", "ACTOR_BOUND"}
        if self.visibility in scoped and self.binding == "UNKNOWN":
            raise ValueError("scoped domain intent requires an explicit binding")
        if self.visibility in {"PUBLIC", "SHARED"} and self.binding != "UNKNOWN":
            raise ValueError("public or shared domain intent cannot assert an exclusive binding")
        return self


class CleanupControlRule(StrictModel):
    """Reviewed cleanup capability for one stable semantic hypothesis target."""

    semantic_fingerprint: str
    strategy: Literal[
        "DISPOSABLE_RESEARCHER_RESOURCE",
        "REVERSIBLE_ROLLBACK_OR_RECREATION",
        "MANUAL_CONTROLLED_RESTORE",
    ]
    actor_ids: list[str] = Field(min_length=1)
    resource_type: str
    route_family: str
    parent_resource_type: str | None = None
    resource_refs: list[str] = Field(min_length=1)
    oracle_refs: list[str] = Field(min_length=1)
    source_checksum: str
    rationale: str

    @field_validator(
        "semantic_fingerprint",
        "resource_type",
        "route_family",
        "parent_resource_type",
        "source_checksum",
        "rationale",
    )
    @classmethod
    def cleanup_text_is_not_empty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("value cannot be empty")
        return normalized

    @field_validator("actor_ids", "resource_refs", "oracle_refs")
    @classmethod
    def cleanup_lists_are_not_empty(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item for item in normalized):
            raise ValueError("cleanup controls cannot contain empty values")
        return list(dict.fromkeys(normalized))


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
    ownership_inference: OwnershipInferenceConfig = Field(default_factory=OwnershipInferenceConfig)
    function_authorization_rules: list[FunctionAuthorizationRule] = Field(default_factory=list)
    jwt_algorithm_rules: list[JwtAlgorithmRule] = Field(default_factory=list)
    endpoint_side_effect_rules: list[EndpointSideEffectRule] = Field(default_factory=list)
    domain_intent_rules: list[DomainIntentRule] = Field(default_factory=list)
    cleanup_controls: list[CleanupControlRule] = Field(default_factory=list)
    classification_overrides: dict[str, ClassificationOverride] = Field(default_factory=dict)

    @model_validator(mode="after")
    def analysis_rules_are_unique(self) -> Self:
        keys = [(item.method, item.path) for item in self.function_authorization_rules]
        if len(keys) != len(set(keys)):
            raise ValueError("function authorization rules must use unique method/path pairs")
        jwt_keys = [
            (item.method, item.path, item.token_location, item.token_parameter.casefold())
            for item in self.jwt_algorithm_rules
        ]
        if len(jwt_keys) != len(set(jwt_keys)):
            raise ValueError(
                "JWT algorithm rules must use unique method/path/location/parameter tuples"
            )
        side_effect_keys = [(item.method, item.path) for item in self.endpoint_side_effect_rules]
        if len(side_effect_keys) != len(set(side_effect_keys)):
            raise ValueError("endpoint side-effect rules must use unique method/path pairs")
        domain_intent_keys = [(item.method, item.path) for item in self.domain_intent_rules]
        if len(domain_intent_keys) != len(set(domain_intent_keys)):
            raise ValueError("domain-intent rules must use unique method/path pairs")
        cleanup_keys = [item.semantic_fingerprint for item in self.cleanup_controls]
        if len(cleanup_keys) != len(set(cleanup_keys)):
            raise ValueError("cleanup controls must use unique semantic fingerprints")
        return self


class TargetDocument(StrictModel):
    """Top-level target.yaml structure."""

    target: TargetIdentity
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    accounts: list[AccountConfig] = Field(default_factory=list)
    testing: TestingConfig = Field(default_factory=TestingConfig)
    restrictions: RestrictionsConfig = Field(default_factory=RestrictionsConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    capture_policy: CapturePolicy = Field(default_factory=CapturePolicy)
    focus: list[str] = Field(
        default_factory=lambda: [
            "authorization",
            "business_logic",
            "financial_workflows",
            "authentication",
            "replay_and_idempotency",
        ]
    )
