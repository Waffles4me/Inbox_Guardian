import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .detectors.base import DetectorFinding, DetectorStatus
from .engine import EngineResult, analyze_with_detectors
from .models import (
    AnalyzeRequest,
    AnalyzeResponse,
    AttachmentCollection,
    AttachmentMetadata,
    AttachmentNameClip,
    EmailPayload,
    EnrichmentOptions,
    Finding,
)
from .parsing import AttachmentCollectionState
from .reputation import enrich_with_virustotal
from .scoring import ScoredFinding, ScoringResult, score_engine_result

API_TOKEN_ENV = "INBOXGUARDIAN_API_TOKEN"
SCORE_TYPE = "heuristic_risk_index_not_probability"
PLANNED_CHECK_NAMES = {
    "nlp_phishing": "machine-learning (NLP) phishing classification",
}

app = FastAPI(
    title="InboxGuardian Backend",
    version="0.1.0",
    description="Backend skeleton for the InboxGuardian Gmail Add-on.",
)

MAX_VALIDATION_ERRORS = 20
VALIDATION_LOCATION_ROOTS = frozenset({"body", "query", "header", "path", "cookie"})
# Location parts that name a request-schema field. Anything else in a location, such as a header name taken
# from the message, came from the request and is replaced.
SCHEMA_FIELD_NAMES = frozenset(
    name
    for model in (
        AnalyzeRequest,
        EmailPayload,
        AttachmentMetadata,
        AttachmentNameClip,
        AttachmentCollection,
        EnrichmentOptions,
    )
    for field_name, info in model.model_fields.items()
    for name in (field_name, info.alias)
    if name
)


def require_api_token(x_inboxguardian_token: str | None = Header(default=None)) -> None:
    expected_token = os.environ.get(API_TOKEN_ENV)
    if not expected_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend authentication is not configured.",
        )
    # Compare bytes: compare_digest rejects non-ASCII str input, which must be a 401 rather than a crash.
    if not x_inboxguardian_token or not secrets.compare_digest(
        x_inboxguardian_token.encode("utf-8"),
        expected_token.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid backend authentication.",
        )


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI parses the body before running dependencies, so check the token here as well: an
    # unauthenticated request gets the same 401 or 503 as any other and learns nothing about validation.
    try:
        require_api_token(request.headers.get("X-InboxGuardian-Token"))
    except HTTPException as auth_error:
        return JSONResponse(status_code=auth_error.status_code, content={"detail": auth_error.detail})
    # The default handler echoes the rejected input and parser messages, which can be message content or
    # attachment names. Only the location (schema field names and list positions) and the error type are
    # returned, and nothing is logged. (Literal 422: Starlette renamed the status constant.)
    errors = [
        {"loc": [_safe_location_part(part) for part in error.get("loc", ())], "type": str(error.get("type", "invalid"))}
        for error in exc.errors()[:MAX_VALIDATION_ERRORS]
    ]
    return JSONResponse(
        status_code=422,
        content={"detail": errors, "message": "Request validation failed; rejected values are not returned."},
    )


def _safe_location_part(part: object) -> str | int:
    if isinstance(part, int) and not isinstance(part, bool):
        return part
    if isinstance(part, str) and (part in SCHEMA_FIELD_NAMES or part in VALIDATION_LOCATION_ROOTS):
        return part
    return "*"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "inboxguardian-backend"}


@app.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(require_api_token)])
def analyze_email(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze a validated email payload with the internal engine and scorer."""
    try:
        engine_result = analyze_with_detectors(request.email)
        scoring_result = score_engine_result(engine_result)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email analysis failed before a reliable assessment could be produced.",
        ) from exc

    try:
        reputation_context = enrich_with_virustotal(
            engine_result.parsed_email,
            opt_in=request.enrichments.virustotal,
        )
    except Exception:
        reputation_context = ()

    return _response_from_scoring(scoring_result, engine_result, reputation_context=reputation_context)


def _response_from_scoring(
    scoring_result: ScoringResult,
    engine_result: EngineResult,
    *,
    reputation_context=(),
) -> AnalyzeResponse:
    incomplete = scoring_result.verdict == "INCOMPLETE"
    public_score = 0 if incomplete else scoring_result.risk_score
    public_findings = _public_findings(scoring_result.scored_findings)
    limitations = _public_limitations(scoring_result, engine_result, incomplete=incomplete)

    return AnalyzeResponse(
        risk_score=public_score,
        score_type=SCORE_TYPE,
        verdict=scoring_result.verdict,
        findings=public_findings,
        limitations=limitations,
        recommended_action=_recommended_action(scoring_result, incomplete=incomplete),
        detector_version=f"{engine_result.implementation_version}+{scoring_result.implementation_version}",
        reputation_context=list(reputation_context),
    )


def _public_findings(scored_findings: tuple[ScoredFinding, ...]) -> list[Finding]:
    # Strongest first, so clients that show only the first few findings show the ones behind the score.
    # The sort is stable: findings with equal contributions keep their detector order.
    ordered = sorted(scored_findings, key=lambda scored: -scored.effective_contribution)
    return [
        _finding_from_detector_finding(
            scored.finding,
            contribution=scored.effective_contribution,
        )
        for scored in ordered
    ]


def _finding_from_detector_finding(finding: DetectorFinding, *, contribution: int) -> Finding:
    return Finding(
        id=finding.id,
        severity=finding.severity,
        title=finding.title,
        observation=finding.observation,
        interpretation=finding.interpretation,
        contribution=contribution,
    )


def _public_limitations(
    scoring_result: ScoringResult,
    engine_result: EngineResult,
    *,
    incomplete: bool,
) -> list[str]:
    # Clients may show only the first few limitations, so the list leads with why an assessment was
    # incomplete, then content that was excluded, then the planned checks that never ran.
    coverage_gaps = [gap for detector in engine_result.detector_results for gap in detector.coverage_gaps]
    limitations = [
        *scoring_result.coverage.reasons,
        *coverage_gaps,
        *_planned_checks_not_run(engine_result),
        *_attachment_status_lines(engine_result),
        *scoring_result.limitations,
    ]
    if incomplete:
        limitations.insert(
            0,
            "No meaningful risk score was produced, so the score is unavailable; the returned risk_score of 0 "
            "is a required-schema placeholder and does not mean low risk.",
        )
    return list(dict.fromkeys(limitations))


def _planned_checks_not_run(engine_result: EngineResult) -> list[str]:
    names = [
        PLANNED_CHECK_NAMES[detector.detector_id]
        for detector in engine_result.detector_results
        if detector.detector_id in PLANNED_CHECK_NAMES and detector.status == DetectorStatus.NOT_RUN
    ]
    # A V1 client sends no attachment information. Attachments then lead this line, as they did before the
    # attachment check existed, rather than adding a line that pushes message-specific reasons out of view.
    legacy = engine_result.parsed_email.attachment_coverage.declared_state is None
    if legacy:
        names.insert(0, "attachments")
    if not names:
        return []
    listed = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
    if legacy and len(names) == 1:
        return ["Not checked: attachments. This request included no attachment information, so they were not assessed."]
    if legacy:
        return [
            f"Not checked: {listed}. This request included no attachment information, and the other checks are "
            "planned but not implemented, so nothing was assessed for them."
        ]
    return [f"Not checked: {listed}. These planned checks are not implemented, so nothing was assessed for them."]


def _attachment_status_lines(engine_result: EngineResult) -> list[str]:
    # Counts only, never filenames. Whenever names were checked, the line says that content was not. A V1
    # client's missing attachment information is reported in the "Not checked" line instead.
    coverage = engine_result.parsed_email.attachment_coverage
    content_not_inspected = "Only attachment names were checked; attachment content was not inspected."
    if coverage.state == AttachmentCollectionState.UNKNOWN:
        if coverage.declared_state is None:
            return []
        return ["Attachments: the attachment information received was inconsistent, so attachments were not assessed."]
    if coverage.state == AttachmentCollectionState.NONE:
        return ["Attachments: Gmail listed none. Inline images and linked Drive files are not counted."]
    if coverage.state == AttachmentCollectionState.UNAVAILABLE:
        return ["Attachments: attachment information could not be collected from Gmail, so attachments were not assessed."]
    if coverage.state == AttachmentCollectionState.TRUNCATED:
        return [
            f"Attachments: Gmail listed {coverage.regular_count} and details for {coverage.listed_count} were "
            f"received; the others were not assessed individually. {content_not_inspected}"
        ]
    return [f"Attachments: Gmail listed {coverage.listed_count}. {content_not_inspected}"]


def _recommended_action(scoring_result: ScoringResult, *, incomplete: bool) -> str:
    if incomplete:
        return (
            "InboxGuardian could not assess this message sufficiently. Do not treat the placeholder score as "
            "evidence of safety; verify the message through another trusted channel."
        )

    finding_ids = {scored.finding.id for scored in scoring_result.scored_findings}
    actions: list[str] = []
    if any(finding_id.startswith("url_") for finding_id in finding_ids):
        actions.append("avoid clicking email links and navigate to the service directly")
    if any(finding_id.startswith("credential_") for finding_id in finding_ids):
        actions.append("do not submit passwords, OTP codes, or login approvals from this email")
    if any(finding_id.startswith("sender_") for finding_id in finding_ids):
        actions.append("verify the sender through an independently established contact channel")
    if any(finding_id.startswith("attachment_") for finding_id in finding_ids):
        actions.append(
            "do not open attachments or enable editing or macros until the sender confirms them through a trusted channel"
        )
    if any(finding_id.startswith("financial_") for finding_id in finding_ids):
        actions.append("verify payment requests through the normal finance workflow before sending money or codes")

    if actions:
        return "Treat this message with caution: " + "; ".join(actions) + "."

    return (
        "No significant indicators were observed by the checks that ran. This does not guarantee the message is safe; "
        "continue using normal caution with links, attachments, and unusual requests."
    )
