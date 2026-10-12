from fastapi import FastAPI

from .models import AnalyzeRequest, AnalyzeResponse

app = FastAPI(
    title="InboxGuardian Backend",
    version="0.1.0",
    description="Backend skeleton for the InboxGuardian Gmail Add-on.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "inboxguardian-backend"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_email(_: AnalyzeRequest) -> AnalyzeResponse:
    """Return a non-detection stub until the real engine is implemented."""
    return AnalyzeResponse(
        risk_score=0,
        score_type="heuristic_risk_index_not_probability",
        verdict="INCOMPLETE",
        findings=[],
        limitations=[
            "Threat detection is not implemented yet.",
            "This response only verifies the backend API shape.",
        ],
        recommended_action="Continue setup; do not use this stub as a security assessment.",
        detector_version="stub-0.1.0",
    )
