"""Credential-free capture previews for concise ingest-wizard decisions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from finsec.captures.analysis import (
    CaptureSignal,
    IntentAnalysis,
    assess_quality,
    classify_relevance,
    infer_intent,
    inferred_intent,
)
from finsec.captures.domain import (
    CaptureConfidence,
    CaptureIntent,
    CaptureMode,
    CaptureQuality,
    CaptureSourceType,
)
from finsec.config.models import TargetDocument
from finsec.config.scope import host_is_covered
from finsec.errors import FinsecError
from finsec.ingest.har_io import load_har_json
from finsec.ingest.traffic import load_burp_xml


@dataclass(frozen=True)
class CapturePreview:
    """Explainable metadata proposal shown before passive ingestion."""

    path: Path
    source_type: CaptureSourceType
    signals: tuple[CaptureSignal, ...]
    actor_id: str | None
    actor_confidence: CaptureConfidence
    actor_evidence: tuple[str, ...]
    capture_mode: CaptureMode
    capture_mode_confidence: CaptureConfidence
    capture_mode_evidence: tuple[str, ...]
    intent: CaptureIntent
    intent_analysis: IntentAnalysis
    quality: CaptureQuality

    @property
    def first_party_requests(self) -> int:
        return sum(item.first_party for item in self.signals)

    @property
    def state_changing_requests(self) -> int:
        return sum(item.method in {"POST", "PUT", "PATCH", "DELETE"} for item in self.signals)


def source_type_for(path: Path) -> CaptureSourceType:
    """Resolve a supported incoming passive source from its safe extension."""

    suffix = path.suffix.lower()
    if suffix == ".har":
        return CaptureSourceType.HAR
    if suffix == ".xml":
        return CaptureSourceType.BURP_XML
    raise FinsecError(f"Unsupported capture source: {path.name}; expected .har or Burp .xml.")


def _patterns(target: TargetDocument) -> list[str]:
    return target.analysis.include_hosts or target.scope.hosts


def _har_signals(path: Path, target: TargetDocument) -> tuple[CaptureSignal, ...]:
    _source_path, _raw, document = load_har_json(path)
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise FinsecError("HAR must contain a log.entries array.")
    signals: list[CaptureSignal] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        response = entry.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        url = request.get("url")
        if not isinstance(url, str):
            continue
        parsed = urlsplit(url)
        if parsed.hostname is None:
            continue
        status = response.get("status")
        signals.append(
            CaptureSignal(
                observation_id=f"PREVIEW-{index:06d}",
                position=index,
                host=parsed.hostname.lower(),
                method=str(request.get("method", "GET")).upper(),
                path=parsed.path or "/",
                status_code=int(status) if isinstance(status, int | float) else None,
                first_party=host_is_covered(parsed.hostname, _patterns(target))
                if _patterns(target)
                else True,
            )
        )
    return tuple(signals)


def _burp_signals(path: Path, target: TargetDocument) -> tuple[CaptureSignal, ...]:
    document = load_burp_xml(path)
    signals: list[CaptureSignal] = []
    for exchange in document.exchanges:
        parsed = urlsplit(exchange.url)
        if parsed.hostname is None:
            continue
        signals.append(
            CaptureSignal(
                observation_id=f"PREVIEW-{exchange.index:06d}",
                position=exchange.index,
                host=parsed.hostname.lower(),
                method=exchange.method,
                path=parsed.path or "/",
                status_code=exchange.status,
                first_party=host_is_covered(parsed.hostname, _patterns(target))
                if _patterns(target)
                else True,
            )
        )
    return tuple(signals)


def _actor(
    path: Path, target: TargetDocument
) -> tuple[str | None, CaptureConfidence, tuple[str, ...]]:
    normalized_name = re.sub(r"[^a-z0-9]+", "_", path.stem.lower()).strip("_")
    matches = [
        account.id
        for account in target.accounts
        if re.sub(r"[^a-z0-9]+", "_", account.id.lower()).strip("_") in normalized_name
    ]
    if len(matches) == 1:
        return (
            matches[0],
            CaptureConfidence.HIGH,
            (f"Filename contains configured actor label {matches[0]}.",),
        )
    return None, CaptureConfidence.LOW, ("No unique configured actor label was detected.",)


def _mode(
    path: Path, signals: tuple[CaptureSignal, ...], analysis: IntentAnalysis, target: TargetDocument
) -> tuple[CaptureMode, CaptureConfidence, tuple[str, ...]]:
    tokens = set(re.sub(r"[^a-z0-9]+", " ", path.stem.lower()).split())
    if tokens & {"probe", "replay", "tamper", "attack", "security"}:
        return (
            CaptureMode.RESEARCHER_PROBE,
            CaptureConfidence.MEDIUM,
            ("Filename contains a researcher-probe marker.",),
        )
    if "mixed" in tokens:
        return CaptureMode.MIXED, CaptureConfidence.HIGH, ("Filename marks mixed activity.",)
    auth_requests = sum(
        any(token in signal.path.lower() for token in ("login", "auth", "token", "session", "otp"))
        for signal in signals
    )
    if signals and auth_requests * 2 >= len(signals):
        return (
            CaptureMode.AUTHENTICATION,
            CaptureConfidence.HIGH,
            (f"{auth_requests} of {len(signals)} requests are authentication-related.",),
        )
    configured = CaptureMode(target.capture_policy.default_mode)
    return (
        configured,
        CaptureConfidence.LOW,
        (f"Workspace capture policy defaults new captures to {configured.value}.",),
    )


def preview_capture(path: Path, target: TargetDocument) -> CapturePreview:
    """Analyze an incoming source without persisting it or retaining credentials."""

    source_type = source_type_for(path)
    signals = (
        _har_signals(path, target)
        if source_type == CaptureSourceType.HAR
        else _burp_signals(path, target)
    )
    analysis = infer_intent(signals)
    intent = inferred_intent(analysis) if target.capture_policy.infer_intent else CaptureIntent()
    relevance = classify_relevance(signals, intent, analysis)
    quality = assess_quality(signals, analysis, relevance)
    actor_id, actor_confidence, actor_evidence = _actor(path, target)
    mode, mode_confidence, mode_evidence = _mode(path, signals, analysis, target)
    return CapturePreview(
        path=path,
        source_type=source_type,
        signals=signals,
        actor_id=actor_id,
        actor_confidence=actor_confidence,
        actor_evidence=actor_evidence,
        capture_mode=mode,
        capture_mode_confidence=mode_confidence,
        capture_mode_evidence=mode_evidence,
        intent=intent,
        intent_analysis=analysis,
        quality=quality,
    )
