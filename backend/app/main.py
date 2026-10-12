import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, status

from .models import AnalyzeRequest, AnalyzeResponse

API_TOKEN_ENV = "INBOXGUARDIAN_API_TOKEN"

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
def analyze_email(_: AnalyzeRequest) -> AnalyzeResponse:
    """Return a non-detection stub until the real engine is implemented."""
    return AnalyzeResponse(
        risk_score=0,
        score_type="heuristic_risk_index_not_probability",
        verdict="INCOMPLETE",
        findings=[
            {
                "id": "demo_not_analyzed",
                "severity": "info",
                "title": "DEMO / NOT ANALYZED",
                "observation": "The Gmail add-on reached the backend successfully.",
                "interpretation": "No phishing or maliciousness analysis has been run yet.",
                "contribution": 0,
            }
        ],
        limitations=[
            "Threat detection is not implemented yet.",
            "This response only verifies authenticated Gmail add-on to backend connectivity.",
        ],
        recommended_action="Do not use this demo response as a security assessment.",
        detector_version="stub-0.1.0",
    )
