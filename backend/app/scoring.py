from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.engine import EngineResult
from backend.app.parsing import ParseStatus


ScoreVerdict = Literal["HIGH_RISK", "SUSPICIOUS", "NO_SIGNIFICANT_SIGNALS", "INCOMPLETE"]

IMPLEMENTATION_VERSION = "scoring-0.1.0"
CORRELATION_BONUS = 0
SUSPICIOUS_THRESHOLD = 20

IMPLEMENTED_FAMILIES = frozenset({"sender_identity", "url_deception", "credential_context"})
PLANNED_FAMILIES = frozenset({"attachment_metadata", "financial_fraud", "nlp_phishing"})

FAMILY_CAPS: dict[str, int] = {
    "sender_identity": 20,
    "url_deception": 40,
    "credential_context": 25,
}

FINDING_WEIGHTS: dict[str, int] = {
    "sender_reply_to_domain_mismatch": 5,
    "sender_display_domain_mismatch": 20,
    "url_display_destination_mismatch": 30,
    "url_deceptive_subdomain": 35,
    "url_ip_address_host": 5,
    "url_userinfo_hostname": 30,
    "credential_secret_collection_request": 20,
    "credential_account_verification_with_link": 10,
    "credential_urgent_account_threat": 10,
    "credential_request_with_link": 0,
    "credential_security_bypass_instruction": 20,
}

INDEPENDENT_FINDING_IDS = frozenset(
    {
        "sender_reply_to_domain_mismatch",
        "sender_display_domain_mismatch",
        "url_display_destination_mismatch",
        "url_deceptive_subdomain",
        "url_ip_address_host",
        "url_userinfo_hostname",
        "credential_secret_collection_request",
        "credential_urgent_account_threat",
        "credential_security_bypass_instruction",
    }
)


@dataclass(frozen=True)
class ScoredFinding:
    finding: DetectorFinding
    detector_id: str
    approved_weight: int
    effective_contribution: int
    counted: bool
    accounting_note: str = ""


@dataclass(frozen=True)
class FamilyScore:
    detector_id: str
    raw_points: int
    capped_points: int
    cap: int
    findings: tuple[ScoredFinding, ...] = field(default_factory=tuple)
    limitations: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CoverageAssessment:
    is_complete: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)
    sufficient_for_no_significant_signals: bool = False


@dataclass(frozen=True)
class ScoringResult:
    risk_score: int
    verdict: ScoreVerdict
    family_scores: tuple[FamilyScore, ...]
    scored_findings: tuple[ScoredFinding, ...]
    limitations: tuple[str, ...]
    coverage: CoverageAssessment
    independent_evidence_families: tuple[str, ...]
    correlation_bonus: int = CORRELATION_BONUS
    implementation_version: str = IMPLEMENTATION_VERSION


def score_engine_result(result: EngineResult) -> ScoringResult:
    detector_results = {detector.detector_id: detector for detector in result.detector_results}
    family_scores = tuple(
        _score_family(detector_results[detector_id])
        for detector_id in ("sender_identity", "url_deception", "credential_context")
        if detector_id in detector_results
    )
    scored_findings = tuple(scored for family in family_scores for scored in family.findings)
    base_score = sum(family.capped_points for family in family_scores)
    risk_score = max(0, min(100, base_score + CORRELATION_BONUS))
    limitations = _collect_limitations(result, family_scores)
    coverage = _assess_coverage(result, detector_results, risk_score)
    independent_families = _independent_evidence_families(family_scores)
    verdict = _assign_verdict(risk_score, coverage, independent_families)

    return ScoringResult(
        risk_score=risk_score,
        verdict=verdict,
        family_scores=family_scores,
        scored_findings=scored_findings,
        limitations=limitations,
        coverage=coverage,
        independent_evidence_families=independent_families,
    )


def _score_family(detector_result: DetectorResult) -> FamilyScore:
    cap = FAMILY_CAPS[detector_result.detector_id]
    scored = [_initial_scored_finding(detector_result.detector_id, finding) for finding in detector_result.findings]
    scored = _reconcile_duplicate_evidence(scored)
    raw_points = sum(finding.approved_weight for finding in scored if finding.counted)
    scored = _apply_family_cap(scored, cap)
    capped_points = sum(finding.effective_contribution for finding in scored)
    limitations: list[str] = []
    if raw_points > capped_points:
        limitations.append(
            f"{detector_result.detector_id} contribution was capped from {raw_points} to {capped_points}."
        )
    if any(finding.finding.id not in FINDING_WEIGHTS for finding in scored):
        limitations.append(f"{detector_result.detector_id} emitted an unknown finding ID that was not scored.")
    if detector_result.detector_id == "credential_context" and detector_result.findings:
        limitations.append(
            "Credential-context evidence IDs are rule-level; observation-level IDs would improve future deduplication."
        )

    return FamilyScore(
        detector_id=detector_result.detector_id,
        raw_points=raw_points,
        capped_points=capped_points,
        cap=cap,
        findings=tuple(scored),
        limitations=tuple(limitations),
    )


def _initial_scored_finding(detector_id: str, finding: DetectorFinding) -> ScoredFinding:
    weight = FINDING_WEIGHTS.get(finding.id, 0)
    note = "Approved finding weight applied."
    counted = True
    if finding.id not in FINDING_WEIGHTS:
        note = "Unknown finding ID; no invented score was assigned."
        counted = False
    elif weight == 0:
        note = "Contextual finding with approved zero contribution."
        counted = False
    return ScoredFinding(
        finding=finding,
        detector_id=detector_id,
        approved_weight=weight,
        effective_contribution=weight,
        counted=counted,
        accounting_note=note,
    )


def _reconcile_duplicate_evidence(scored: list[ScoredFinding]) -> list[ScoredFinding]:
    strongest_by_key: dict[str, ScoredFinding] = {}
    for item in scored:
        key = _deduplication_key(item.finding)
        strongest = strongest_by_key.get(key)
        if strongest is None or item.approved_weight > strongest.approved_weight:
            strongest_by_key[key] = item

    reconciled: list[ScoredFinding] = []
    for item in scored:
        key = _deduplication_key(item.finding)
        if strongest_by_key[key] is item:
            reconciled.append(item)
        else:
            reconciled.append(
                ScoredFinding(
                    finding=item.finding,
                    detector_id=item.detector_id,
                    approved_weight=item.approved_weight,
                    effective_contribution=0,
                    counted=False,
                    accounting_note="Suppressed because stronger finding covers the same evidence.",
                )
            )
    return reconciled


def _deduplication_key(finding: DetectorFinding) -> str:
    if finding.id in {"url_display_destination_mismatch", "url_deceptive_subdomain"}:
        return f"url.link_deception:{_evidence_tail(finding.evidence_id)}"
    return f"{finding.id}:{finding.evidence_id}"


def _evidence_tail(evidence_id: str) -> str:
    return evidence_id.split(":", 1)[1] if ":" in evidence_id else evidence_id


def _apply_family_cap(scored: list[ScoredFinding], cap: int) -> list[ScoredFinding]:
    remaining = cap
    allocation_order = sorted(
        range(len(scored)),
        key=lambda index: (-scored[index].approved_weight, index),
    )
    effective_by_index = [0] * len(scored)
    for index in allocation_order:
        item = scored[index]
        if not item.counted:
            continue
        effective = min(item.approved_weight, remaining)
        effective_by_index[index] = effective
        remaining -= effective
        if remaining <= 0:
            break

    capped: list[ScoredFinding] = []
    for index, item in enumerate(scored):
        effective = effective_by_index[index]
        if not item.counted:
            capped.append(item)
            continue
        if effective == item.approved_weight:
            capped.append(item)
        elif effective > 0:
            capped.append(
                ScoredFinding(
                    finding=item.finding,
                    detector_id=item.detector_id,
                    approved_weight=item.approved_weight,
                    effective_contribution=effective,
                    counted=True,
                    accounting_note="Partially reduced by detector-family cap.",
                )
            )
        else:
            capped.append(
                ScoredFinding(
                    finding=item.finding,
                    detector_id=item.detector_id,
                    approved_weight=item.approved_weight,
                    effective_contribution=0,
                    counted=False,
                    accounting_note="Suppressed by detector-family cap.",
                )
            )
    return capped


def _collect_limitations(result: EngineResult, family_scores: tuple[FamilyScore, ...]) -> tuple[str, ...]:
    limitations: list[str] = list(result.limitations)
    limitations.append("Correlation bonus is 0 in Method C v1.")
    for detector_result in result.detector_results:
        if detector_result.detector_id in PLANNED_FAMILIES and detector_result.status == DetectorStatus.NOT_RUN:
            limitations.append(f"{detector_result.detector_id} is planned but not implemented; it contributed 0 points.")
    for family in family_scores:
        limitations.extend(family.limitations)
    return tuple(dict.fromkeys(limitations))


def _assess_coverage(
    result: EngineResult,
    detector_results: dict[str, DetectorResult],
    risk_score: int,
) -> CoverageAssessment:
    reasons: list[str] = []
    implemented_results = [
        detector_results[detector_id] for detector_id in IMPLEMENTED_FAMILIES if detector_id in detector_results
    ]
    if any(detector.status == DetectorStatus.NOT_RUN for detector in implemented_results):
        reasons.append("At least one implemented detector did not run; assessment is incomplete.")

    parsed = result.parsed_email
    has_valid_sender = parsed.from_mailbox.status == ParseStatus.PRESENT
    # A subject line alone is not body evidence: an empty, whitespace-only or image-only body may mean the
    # content was not collected, so it must not support a NO_SIGNIFICANT_SIGNALS verdict.
    has_body_evidence = bool(
        parsed.text_body.strip()
        or parsed.html_visible_text.strip()
        or any(url.status == ParseStatus.PRESENT for url in parsed.text_urls)
        or any(link.href.status == ParseStatus.PRESENT for link in parsed.html_links)
    )
    below_suspicious = risk_score < SUSPICIOUS_THRESHOLD
    if not has_valid_sender and below_suspicious:
        reasons.append("No valid sender identity was available and no significant suspicious evidence was found.")
    if not has_body_evidence and below_suspicious:
        if parsed.subject.strip():
            reasons.append(
                "The message body contained no readable text or supported links, so only the subject line "
                "could be checked."
            )
        else:
            reasons.append("No analyzable subject, body text, HTML text or URL evidence was available.")

    if below_suspicious:
        for detector in implemented_results:
            reasons.extend(detector.coverage_gaps)

    inconsistent = [
        detector.detector_id
        for detector in implemented_results
        if detector.status == DetectorStatus.NOT_TRIGGERED and detector.findings
    ]
    if inconsistent:
        reasons.append(f"Inconsistent detector output from: {', '.join(sorted(inconsistent))}.")

    complete = not reasons
    sufficient_for_no_significant = complete and has_valid_sender and has_body_evidence
    return CoverageAssessment(
        is_complete=complete,
        reasons=tuple(reasons),
        sufficient_for_no_significant_signals=sufficient_for_no_significant,
    )


def _independent_evidence_families(family_scores: tuple[FamilyScore, ...]) -> tuple[str, ...]:
    families: list[str] = []
    for family in family_scores:
        if any(
            scored.effective_contribution > 0 and scored.finding.id in INDEPENDENT_FINDING_IDS
            for scored in family.findings
        ):
            families.append(family.detector_id)
    return tuple(families)


def _assign_verdict(
    risk_score: int,
    coverage: CoverageAssessment,
    independent_families: tuple[str, ...],
) -> ScoreVerdict:
    if not coverage.is_complete:
        return "INCOMPLETE"
    if risk_score >= 60:
        if len(independent_families) >= 2:
            return "HIGH_RISK"
        return "SUSPICIOUS"
    if risk_score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    if coverage.sufficient_for_no_significant_signals:
        return "NO_SIGNIFICANT_SIGNALS"
    return "INCOMPLETE"
