import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, status

from .detectors.base import DetectorFinding
from .engine import analyze_with_detectors
from .models import AnalyzeRequest, AnalyzeResponse, Finding
from .scoring import ScoredFinding, ScoringResult, score_engine_result

API_TOKEN_ENV = "INBOXGUARDIAN_API_TOKEN"
SCORE_TYPE = "heuristic_risk_index_not_probability"

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
    if not x_inboxguardian_token or not secrets.compare_digest(
        x_inboxguardian_token,
        expected_token,
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

    return _response_from_scoring(scoring_result, engine_version=engine_result.implementation_version)


def _response_from_scoring(scoring_result: ScoringResult, *, engine_version: str) -> AnalyzeResponse:
    incomplete = scoring_result.verdict == "INCOMPLETE"
    public_score = 0 if incomplete else scoring_result.risk_score
    public_findings = _public_findings(scoring_result.scored_findings)
    limitations = _public_limitations(scoring_result, incomplete=incomplete)

    return AnalyzeResponse(
        risk_score=public_score,
        score_type=SCORE_TYPE,
        verdict=scoring_result.verdict,
        findings=public_findings,
        limitations=limitations,
        recommended_action=_recommended_action(scoring_result, incomplete=incomplete),
        detector_version=f"{engine_version}+{scoring_result.implementation_version}",
    )


def _public_findings(scored_findings: tuple[ScoredFinding, ...]) -> list[Finding]:
    return [
        _finding_from_detector_finding(
            scored.finding,
            contribution=scored.effective_contribution,
        )
        for scored in scored_findings
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


def _public_limitations(scoring_result: ScoringResult, *, incomplete: bool) -> list[str]:
    limitations = list(scoring_result.limitations)
    if scoring_result.coverage.reasons:
        limitations.extend(scoring_result.coverage.reasons)
    if incomplete:
        limitations.insert(
            0,
            "No meaningful risk score was produced; risk_score is a required-schema placeholder.",
        )
    return list(dict.fromkeys(limitations))


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
        return "Recommended action: " + "; ".join(actions) + "."

    return (
        "No significant indicators were observed by the checks that ran. This does not guarantee the message is safe; "
        "continue using normal caution with links, attachments, and unusual requests."
    )
