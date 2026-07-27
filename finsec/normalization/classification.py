"""Deterministic endpoint classification and security relevance scoring."""

from dataclasses import dataclass
from pathlib import PurePosixPath

from finsec.config.models import TargetDocument
from finsec.config.scope import host_is_covered
from finsec.modeling.models import (
    Confidence,
    EndpointClassification,
    EndpointDisposition,
    EndpointPrimaryClassification,
    Observation,
)

STATIC_CONTENT_PREFIXES = ("image/", "font/", "video/")
STATIC_CONTENT_TYPES = {"text/css", "application/javascript", "text/javascript"}
STATIC_PATH_PREFIXES = (
    "/static/",
    "/assets/",
    "/images/",
    "/img/",
    "/fonts/",
    "/css/",
    "/js/",
    "/media/",
)
TELEMETRY_PATTERNS = (
    "/envelope/",
    "/gen_204",
    "/actionlog/",
    "/client-exporter/",
    "/send-report",
    "/telemetry/",
    "/metrics/",
    "/sentry/",
)
ANALYTICS_PATTERNS = ("/analytics/", "/events/", "/collect")
AUTHENTICATION_HINTS = (
    "auth",
    "authenticate",
    "login",
    "signin",
    "signup",
    "otp",
    "verification",
    "challenge",
    "session",
)
FINANCIAL_HINTS = (
    "wallet",
    "payment",
    "transaction",
    "refund",
    "withdraw",
    "transfer",
    "settlement",
    "balance",
    "invoice",
)


@dataclass(frozen=True)
class ClassificationContext:
    """Host and policy context shared by classification rules."""

    target: TargetDocument

    @property
    def included_hosts(self) -> set[str]:
        return set(self.target.analysis.include_hosts or self.target.scope.hosts)


def _extension(path: str) -> str:
    suffix = PurePosixPath(path.rstrip("/")).suffix.lower()
    return suffix.removeprefix(".")


def classify_observation(
    observation: Observation, context: ClassificationContext
) -> EndpointClassification:
    """Classify one observation without dropping its audit trail."""

    override = context.target.analysis.classification_overrides.get(observation.path)
    if override:
        return EndpointClassification(
            primary=EndpointPrimaryClassification(override),
            confidence=Confidence.HIGH,
            reasons=["researcher classification override"],
        )

    path = observation.path.lower()
    content_type = (observation.content_type or "").split(";", 1)[0].strip().lower()
    extension = _extension(path)
    excluded_extensions = {
        item.lower().lstrip(".") for item in context.target.analysis.excluded_extensions
    }
    tags: list[EndpointPrimaryClassification] = []
    reasons: list[str] = []

    included_patterns = list(context.included_hosts)
    is_third_party = bool(included_patterns) and not host_is_covered(
        observation.host, included_patterns
    )
    if host_is_covered(observation.host, context.target.analysis.exclude_hosts):
        is_third_party = True

    static_reasons: list[str] = []
    if extension in excluded_extensions:
        static_reasons.append(f"path ends with .{extension}")
    if content_type.startswith(STATIC_CONTENT_PREFIXES) or content_type in STATIC_CONTENT_TYPES:
        static_reasons.append(f"response content type is {content_type}")
    for prefix in STATIC_PATH_PREFIXES:
        if path.startswith(prefix):
            static_reasons.append(f"path starts with {prefix}")
            break
    if static_reasons:
        if is_third_party:
            tags.append(EndpointPrimaryClassification.THIRD_PARTY)
        return EndpointClassification(
            primary=EndpointPrimaryClassification.STATIC_ASSET,
            tags=tags,
            confidence=Confidence.HIGH,
            reasons=static_reasons,
        )

    if any(pattern in path for pattern in TELEMETRY_PATTERNS):
        if is_third_party:
            tags.append(EndpointPrimaryClassification.THIRD_PARTY)
        return EndpointClassification(
            primary=EndpointPrimaryClassification.TELEMETRY,
            tags=tags,
            confidence=Confidence.HIGH,
            reasons=[
                f"path matches telemetry pattern {pattern}"
                for pattern in TELEMETRY_PATTERNS
                if pattern in path
            ],
        )

    if any(pattern in path for pattern in ANALYTICS_PATTERNS):
        if is_third_party:
            return EndpointClassification(
                primary=EndpointPrimaryClassification.THIRD_PARTY,
                tags=[EndpointPrimaryClassification.ANALYTICS],
                confidence=Confidence.HIGH,
                reasons=[
                    "host is not included in target analysis scope",
                    *[
                        f"path matches analytics pattern {pattern}"
                        for pattern in ANALYTICS_PATTERNS
                        if pattern in path
                    ],
                ],
            )
        return EndpointClassification(
            primary=EndpointPrimaryClassification.ANALYTICS,
            tags=tags,
            confidence=Confidence.HIGH,
            reasons=[
                f"path matches analytics pattern {pattern}"
                for pattern in ANALYTICS_PATTERNS
                if pattern in path
            ],
        )

    configured_exclusions = [
        pattern
        for pattern in context.target.analysis.excluded_path_patterns
        if pattern.lower() in path
    ]
    if configured_exclusions:
        if is_third_party:
            tags.append(EndpointPrimaryClassification.THIRD_PARTY)
        return EndpointClassification(
            primary=EndpointPrimaryClassification.UNKNOWN,
            tags=tags,
            confidence=Confidence.HIGH,
            reasons=[
                f"path matches configured exclusion pattern {pattern}"
                for pattern in configured_exclusions
            ],
        )

    if any(hint in path for hint in AUTHENTICATION_HINTS):
        tags.append(EndpointPrimaryClassification.AUTHENTICATION)
    if any(hint in path for hint in FINANCIAL_HINTS):
        tags.append(EndpointPrimaryClassification.FINANCIAL)

    if is_third_party:
        primary = EndpointPrimaryClassification.THIRD_PARTY
        reasons.append("host is not included in target analysis scope")
    elif observation.method == "GET" and content_type.startswith("text/html"):
        primary = EndpointPrimaryClassification.PAGE_NAVIGATION
        reasons.append("GET response content type is text/html")
    elif host_is_covered(observation.host, included_patterns):
        primary = EndpointPrimaryClassification.FIRST_PARTY_API
        reasons.append("host is included in target analysis scope")
    else:
        primary = EndpointPrimaryClassification.UNKNOWN
        reasons.append("host role is not configured")

    return EndpointClassification(
        primary=primary,
        tags=sorted(set(tags), key=lambda item: item.value),
        confidence=Confidence.HIGH
        if primary != EndpointPrimaryClassification.UNKNOWN
        else Confidence.LOW,
        reasons=reasons,
    )


def endpoint_disposition(
    classification: EndpointClassification, target: TargetDocument
) -> EndpointDisposition:
    """Map classification and policy to an explicit endpoint disposition."""

    suppress = target.analysis.suppress
    primary = classification.primary
    if primary == EndpointPrimaryClassification.STATIC_ASSET and suppress.static_assets:
        return "SUPPRESSED_STATIC_ASSET"
    if primary == EndpointPrimaryClassification.TELEMETRY and suppress.telemetry:
        return "SUPPRESSED_TELEMETRY"
    if primary == EndpointPrimaryClassification.ANALYTICS and suppress.analytics:
        return "SUPPRESSED_ANALYTICS"
    if primary == EndpointPrimaryClassification.THIRD_PARTY and suppress.third_party:
        return "SUPPRESSED_THIRD_PARTY"
    if any(
        reason.startswith("path matches configured exclusion pattern ")
        for reason in classification.reasons
    ):
        return "SUPPRESSED_INSUFFICIENT_EVIDENCE"
    return "ACTIVE"
