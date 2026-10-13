import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, status

from .detectors.base import DetectorFinding, DetectorStatus
from .engine import EngineResult, analyze_with_detectors
from .models import AnalyzeRequest, AnalyzeResponse, Finding
from .scoring import ScoredFinding, ScoringResult, score_engine_result

API_TOKEN_ENV = "INBOXGUARDIAN_API_TOKEN"
SCORE_TYPE = "heuristic_risk_index_not_probability"
PLANNED_CHECK_NAMES = {
    "attachment_metadata": "attachments",
    "financial_fraud": "payment or financial-fraud requests",
    "nlp_phishing": "machine-learning (NLP) phishing classification",
}

app = FastAPI(
    title="InboxGuardian Backend",
    version="0.1.0",
    description="Backend skeleton for the InboxGuardian Gmail Add-on.",
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

    return _response_from_scoring(scoring_result, engine_result)


def _response_from_scoring(scoring_result: ScoringResult, engine_result: EngineResult) -> AnalyzeResponse:
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
    if not names:
        return []
    listed = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
    return [f"Not checked: {listed}. These planned checks are not implemented, so nothing was assessed for them."]


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

    if actions:
        return "Treat this message with caution: " + "; ".join(actions) + "."

    return (
        "No significant indicators were observed by the checks that ran. This does not guarantee the message is safe; "
        "continue using normal caution with links, attachments, and unusual requests."
    )
