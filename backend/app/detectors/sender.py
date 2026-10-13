from __future__ import annotations

import re

from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.parsing import EvidenceSource, ParsedEmail, ParsedMailbox, ParseStatus


DETECTOR_ID = "sender_identity"
IMPLEMENTATION_VERSION = "sender-0.1.0"

_DOMAIN_IN_DISPLAY_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])",
    re.IGNORECASE,
)


def detect_sender_impersonation(parsed_email: ParsedEmail) -> DetectorResult:
    findings: list[DetectorFinding] = []
    limitations: list[str] = [
        "Sender identity checks are heuristic and do not verify domain ownership, reputation, or authentication results.",
        "Registered-domain/public-suffix comparison is not implemented; subdomain handling is conservative.",
    ]
    evidence_sources = (EvidenceSource.FROM.value, EvidenceSource.REPLY_TO.value)

    from_box = parsed_email.from_mailbox
    reply_to_box = parsed_email.reply_to_mailbox

    if from_box.status != ParseStatus.PRESENT:
        return DetectorResult(
            detector_id=DETECTOR_ID,
            status=DetectorStatus.INCONCLUSIVE,
            evidence_sources=evidence_sources,
            limitations=tuple(
                [
                    "From mailbox is missing, malformed, or ambiguous, so sender identity could not be evaluated.",
                    *limitations,
                ]
            ),
            implementation_version=IMPLEMENTATION_VERSION,
        )

    if reply_to_box.status in {ParseStatus.MALFORMED, ParseStatus.UNSUPPORTED, ParseStatus.UNKNOWN}:
        return DetectorResult(
            detector_id=DETECTOR_ID,
            status=DetectorStatus.INCONCLUSIVE,
            evidence_sources=evidence_sources,
            limitations=tuple(
                [
                    "Reply-To mailbox is malformed or ambiguous, so Reply-To comparison could not be evaluated safely.",
                    *limitations,
                ]
            ),
            implementation_version=IMPLEMENTATION_VERSION,
        )

    if reply_to_box.status == ParseStatus.PRESENT and not _same_domain_or_subdomain(
        from_box.domain_idna,
        reply_to_box.domain_idna,
    ):
        findings.append(_reply_to_mismatch_finding(from_box, reply_to_box))

    display_claim_domains = _display_claim_domains(from_box.display_name)
    for claimed_domain in display_claim_domains:
        if not _same_domain_or_subdomain(claimed_domain, from_box.domain_idna):
            findings.append(_display_domain_mismatch_finding(claimed_domain, from_box))
            break

    status = DetectorStatus.TRIGGERED if findings else DetectorStatus.NOT_TRIGGERED
    if not findings:
        limitations = [
            "No sender-identity rule triggered; this is not a guarantee that the sender is legitimate.",
            *limitations,
        ]

    return DetectorResult(
        detector_id=DETECTOR_ID,
        status=status,
        findings=tuple(findings),
        evidence_sources=evidence_sources,
        limitations=tuple(limitations),
        implementation_version=IMPLEMENTATION_VERSION,
    )


def _reply_to_mismatch_finding(from_box: ParsedMailbox, reply_to_box: ParsedMailbox) -> DetectorFinding:
    return DetectorFinding(
        id="sender_reply_to_domain_mismatch",
        severity="low",
        title="Reply-To domain differs from sender domain",
        observation=(
            f"The From domain is {from_box.domain_idna}, but replies are directed to "
            f"{reply_to_box.domain_idna}."
        ),
        interpretation=(
            "Replies may go to a different operator than the visible sender. This can be legitimate for "
            "support desks, newsletters, or delegated services, so it is supporting evidence only."
        ),
        evidence_id=f"sender.reply_to_domain:{from_box.domain_idna}->{reply_to_box.domain_idna}",
        evidence_sources=(EvidenceSource.FROM.value, EvidenceSource.REPLY_TO.value),
        contribution=0,
    )


def _display_domain_mismatch_finding(claimed_domain: str, from_box: ParsedMailbox) -> DetectorFinding:
    return DetectorFinding(
        id="sender_display_domain_mismatch",
        severity="medium",
        title="Display name claims a different domain",
        observation=(
            f"The sender display name contains {claimed_domain}, but the From domain is "
            f"{from_box.domain_idna}."
        ),
        interpretation=(
            "An explicit domain in the display name can be a claimed identity. A different sending domain "
            "may indicate impersonation, but legitimate delegated senders and aliases can also behave this way."
        ),
        evidence_id=f"sender.display_domain:{claimed_domain}->{from_box.domain_idna}",
        evidence_sources=(EvidenceSource.FROM.value,),
        contribution=0,
    )


def _display_claim_domains(display_name: str) -> tuple[str, ...]:
    domains: list[str] = []
    for match in _DOMAIN_IN_DISPLAY_RE.finditer(display_name):
        normalized = _normalize_domain(match.group(0))
        if normalized and normalized not in domains:
            domains.append(normalized)
    return tuple(domains)


def _same_domain_or_subdomain(left: str, right: str) -> bool:
    if not left or not right:
        return False
    left_normalized = _normalize_domain(left)
    right_normalized = _normalize_domain(right)
    if not left_normalized or not right_normalized:
        return False
    return (
        left_normalized == right_normalized
        or left_normalized.endswith(f".{right_normalized}")
        or right_normalized.endswith(f".{left_normalized}")
        or _same_apparent_parent_domain(left_normalized, right_normalized)
    )


def _same_apparent_parent_domain(left: str, right: str) -> bool:
    left_labels = left.split(".")
    right_labels = right.split(".")
    if len(left_labels) < 3 or len(right_labels) < 3:
        return False
    return left_labels[-2:] == right_labels[-2:]


def _normalize_domain(domain: str) -> str:
    candidate = domain.strip().rstrip(".").lower()
    if not candidate:
        return ""
    try:
        return candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""
