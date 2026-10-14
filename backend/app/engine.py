from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from backend.app.detectors.attachments import detect_suspicious_attachments
from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.detectors.credentials import detect_credential_phishing_context
from backend.app.detectors.financial import detect_financial_fraud
from backend.app.detectors.sender import detect_sender_impersonation
from backend.app.detectors.urls import detect_deceptive_urls
from backend.app.models import EmailPayload
from backend.app.parsing import EvidenceSource, ParsedEmail, ParseIssue, parse_email_payload


IMPLEMENTATION_VERSION = "engine-0.3.0"

DetectorFunction = Callable[[ParsedEmail], DetectorResult]


@dataclass(frozen=True)
class DetectorRunner:
    detector_id: str
    run: DetectorFunction


@dataclass(frozen=True)
class EngineResult:
    parsed_email: ParsedEmail
    detector_results: tuple[DetectorResult, ...]
    findings: tuple[DetectorFinding, ...] = field(default_factory=tuple)
    evidence_sources: tuple[str, ...] = field(default_factory=tuple)
    limitations: tuple[str, ...] = field(default_factory=tuple)
    parse_issues: tuple[ParseIssue, ...] = field(default_factory=tuple)
    implementation_version: str = IMPLEMENTATION_VERSION


IMPLEMENTED_DETECTORS: tuple[DetectorRunner, ...] = (
    DetectorRunner("sender_identity", detect_sender_impersonation),
    DetectorRunner("url_deception", detect_deceptive_urls),
    DetectorRunner("credential_context", detect_credential_phishing_context),
    DetectorRunner("attachment_metadata", detect_suspicious_attachments),
    DetectorRunner("financial_fraud", detect_financial_fraud),
)

PLANNED_DETECTOR_IDS: tuple[str, ...] = (
    "nlp_phishing",
)


def analyze_with_detectors(payload: EmailPayload) -> EngineResult:
    parsed_email = parse_email_payload(payload)
    detector_results: list[DetectorResult] = []

    for runner in IMPLEMENTED_DETECTORS:
        detector_results.append(_run_detector(runner, parsed_email))

    detector_results.extend(_planned_detector_result(detector_id) for detector_id in PLANNED_DETECTOR_IDS)

    return EngineResult(
        parsed_email=parsed_email,
        detector_results=tuple(detector_results),
        findings=_collect_findings(detector_results),
        evidence_sources=_collect_evidence_sources(detector_results),
        limitations=_collect_limitations(parsed_email, detector_results),
        parse_issues=parsed_email.issues,
    )


def _run_detector(runner: DetectorRunner, parsed_email: ParsedEmail) -> DetectorResult:
    try:
        return runner.run(parsed_email)
    except Exception as exc:
        return DetectorResult(
            detector_id=runner.detector_id,
            status=DetectorStatus.NOT_RUN,
            limitations=(
                "Detector execution failed internally; the result is unavailable and must not be treated as clean.",
                f"Internal failure type: {type(exc).__name__}.",
            ),
            implementation_version=f"{IMPLEMENTATION_VERSION}:detector-failure",
        )


def _planned_detector_result(detector_id: str) -> DetectorResult:
    return DetectorResult(
        detector_id=detector_id,
        status=DetectorStatus.NOT_RUN,
        limitations=(
            "This approved detector family is planned but not implemented in the current engine.",
            "No security check was performed for this detector family.",
        ),
        implementation_version="not-implemented",
    )


def _collect_findings(detector_results: list[DetectorResult]) -> tuple[DetectorFinding, ...]:
    findings: list[DetectorFinding] = []
    for result in detector_results:
        findings.extend(result.findings)
    return tuple(findings)


def _collect_evidence_sources(detector_results: list[DetectorResult]) -> tuple[str, ...]:
    sources: list[str] = []
    for result in detector_results:
        sources.extend(result.evidence_sources)
        for finding in result.findings:
            sources.extend(finding.evidence_sources)
    return tuple(dict.fromkeys(source for source in sources if source))


def _collect_limitations(
    parsed_email: ParsedEmail,
    detector_results: list[DetectorResult],
) -> tuple[str, ...]:
    limitations: list[str] = []
    # Reply-To is optional, so its absence is not an input problem worth reporting.
    if any(
        not (issue.code == "mailbox_missing" and issue.source == EvidenceSource.REPLY_TO)
        for issue in parsed_email.issues
    ):
        limitations.append("Parser recorded input normalization issues; review parse_issues before scoring.")
    for result in detector_results:
        limitations.extend(result.limitations)
    return tuple(dict.fromkeys(limitations))
