from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal


class DetectorStatus(StrEnum):
    TRIGGERED = "TRIGGERED"
    NOT_TRIGGERED = "NOT_TRIGGERED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_RUN = "NOT_RUN"


Severity = Literal["info", "low", "medium", "high"]


@dataclass(frozen=True)
class DetectorFinding:
    id: str
    severity: Severity
    title: str
    observation: str
    interpretation: str
    evidence_id: str
    evidence_sources: tuple[str, ...]
    contribution: int = 0


@dataclass(frozen=True)
class DetectorResult:
    detector_id: str
    status: DetectorStatus
    findings: tuple[DetectorFinding, ...] = field(default_factory=tuple)
    evidence_sources: tuple[str, ...] = field(default_factory=tuple)
    limitations: tuple[str, ...] = field(default_factory=tuple)
    implementation_version: str = "0.1.0"

