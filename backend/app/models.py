from typing import Literal

from pydantic import BaseModel, Field


Verdict = Literal[
    "HIGH_RISK",
    "SUSPICIOUS",
    "NO_SIGNIFICANT_SIGNALS",
    "INCOMPLETE",
]


class AttachmentMetadata(BaseModel):
    filename: str = Field(default="", max_length=512)
    content_type: str = Field(default="", max_length=255)
    size_bytes: int | None = Field(default=None, ge=0)


class EmailPayload(BaseModel):
    subject: str = Field(default="", max_length=998)
    from_address: str = Field(default="", alias="from", max_length=998)
    reply_to: str = Field(default="", max_length=998)
    text_body: str = Field(default="", max_length=50_000)
    html_body: str = Field(default="", max_length=50_000)
    headers: dict[str, str] = Field(default_factory=dict)
    attachment_metadata: list[AttachmentMetadata] = Field(default_factory=list, max_length=25)


class AnalyzeRequest(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    email: EmailPayload


class Finding(BaseModel):
    id: str
    severity: Literal["info", "low", "medium", "high"]
    title: str
    observation: str
    interpretation: str
    contribution: int = Field(ge=0, le=100)


class AnalyzeResponse(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    risk_score: int = Field(ge=0, le=100)
    score_type: Literal["heuristic_risk_index_not_probability"]
    verdict: Verdict
    findings: list[Finding]
    limitations: list[str]
    recommended_action: str
    detector_version: str
