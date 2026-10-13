from __future__ import annotations

import re

from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.parsing import EvidenceSource, ParsedEmail


DETECTOR_ID = "credential_context"
IMPLEMENTATION_VERSION = "credentials-0.1.0"

_SECRET_TERMS = r"(?:password|passcode|otp|mfa|2fa|verification code|authentication code|security code|login code)"
_REQUEST_VERBS = r"(?:enter|submit|provide|share|send|reply with|confirm|verify|give us|update)"
_CREDENTIAL_REQUEST_RE = re.compile(
    rf"\b{_REQUEST_VERBS}\b[\w\s,.;:'\"/-]{{0,80}}\b{_SECRET_TERMS}\b"
    rf"|\b{_SECRET_TERMS}\b[\w\s,.;:'\"/-]{{0,80}}\b(?:to continue|to restore|to keep|to avoid|on the form|in the link)\b",
    re.IGNORECASE,
)
_ACCOUNT_VERIFICATION_RE = re.compile(
    r"\b(?:verify|validate|confirm|reactivate|restore|unlock)\b[\w\s,.;:'\"/-]{0,80}\b(?:account|access|identity|login)\b"
    r"|\b(?:account|access|identity|login)\b[\w\s,.;:'\"/-]{0,80}\b(?:verify|validation|confirmation|reactivation|restore|unlock)\b",
    re.IGNORECASE,
)
_URGENCY_RE = re.compile(
    r"\b(?:urgent|immediately|now|today|within\s+\d+\s+(?:hour|hours|day|days)|before midnight)\b",
    re.IGNORECASE,
)
_THREAT_RE = re.compile(
    r"\b(?:suspend|suspended|suspension|close|closed|closure|lock|locked|restrict|restricted|disable|disabled|lose access)\b",
    re.IGNORECASE,
)
_SECURITY_BYPASS_RE = re.compile(
    r"\b(?:ignore|bypass|disable|turn off)\b[\w\s,.;:'\"/-]{0,60}\b(?:security|mfa|2fa|verification|approval)\b",
    re.IGNORECASE,
)
_FORWARDED_MARKER_RE = re.compile(r"^\s*(?:[-]+\s*)?(?:forwarded message|original message)(?:\s*[-]+)?\s*$", re.IGNORECASE)
_HEADER_LINE_RE = re.compile(r"^\s*(?:from|sent|to|subject):\s+.+", re.IGNORECASE)


def detect_credential_phishing_context(parsed_email: ParsedEmail) -> DetectorResult:
    subject = parsed_email.subject.strip()
    active_body = _active_message_text(parsed_email)
    combined_text = " ".join(part for part in [subject, active_body] if part).strip()
    has_links = bool(parsed_email.text_urls or parsed_email.html_links)
    evidence_sources = _evidence_sources(parsed_email, subject, active_body)
    limitations = [
        "Credential-context checks are English-focused heuristic language rules.",
        "The detector does not determine whether linked websites are malicious and does not score risk.",
    ]

    if not combined_text:
        return DetectorResult(
            detector_id=DETECTOR_ID,
            status=DetectorStatus.INCONCLUSIVE,
            evidence_sources=evidence_sources,
            limitations=tuple(
                [
                    "No subject or active body text was available for credential-context analysis.",
                    *limitations,
                ]
            ),
            implementation_version=IMPLEMENTATION_VERSION,
        )

    findings: list[DetectorFinding] = []
    credential_request = _find_match(_CREDENTIAL_REQUEST_RE, combined_text)
    account_verification = _find_match(_ACCOUNT_VERIFICATION_RE, combined_text)
    urgency = bool(_URGENCY_RE.search(combined_text) and _THREAT_RE.search(combined_text))
    bypass = _find_match(_SECURITY_BYPASS_RE, combined_text)

    if credential_request:
        findings.append(_credential_collection_finding(credential_request, evidence_sources))

    if account_verification and has_links:
        findings.append(_account_verification_link_finding(account_verification, evidence_sources))

    if urgency and (credential_request or account_verification):
        findings.append(_urgency_threat_finding(evidence_sources))

    if has_links and credential_request:
        findings.append(_credential_request_with_link_finding(evidence_sources))

    if bypass:
        findings.append(_security_bypass_finding(bypass, evidence_sources))

    deduped_findings = _dedupe_findings(findings)
    if deduped_findings:
        status = DetectorStatus.TRIGGERED
    elif _has_ambiguous_context(combined_text):
        status = DetectorStatus.INCONCLUSIVE
        limitations = [
            "Credential-related language was present but lacked enough request context for a rule to trigger.",
            *limitations,
        ]
    else:
        status = DetectorStatus.NOT_TRIGGERED
        limitations = [
            "No credential-context rule triggered; this is not a guarantee that the message is safe.",
            *limitations,
        ]

    return DetectorResult(
        detector_id=DETECTOR_ID,
        status=status,
        findings=tuple(deduped_findings),
        evidence_sources=evidence_sources,
        limitations=tuple(limitations),
        implementation_version=IMPLEMENTATION_VERSION,
    )


def _credential_collection_finding(snippet: str, evidence_sources: tuple[str, ...]) -> DetectorFinding:
    return DetectorFinding(
        id="credential_secret_collection_request",
        severity="medium",
        title="Message asks for login secrets",
        observation=f"The message includes a request pattern involving login secrets: \"{_safe_snippet(snippet)}\".",
        interpretation=(
            "Requests to provide passwords or authentication codes can indicate credential phishing. "
            "Legitimate account workflows may mention these terms, so the request wording matters."
        ),
        evidence_id="credential.secret_collection_request",
        evidence_sources=evidence_sources,
        contribution=0,
    )


def _account_verification_link_finding(snippet: str, evidence_sources: tuple[str, ...]) -> DetectorFinding:
    return DetectorFinding(
        id="credential_account_verification_with_link",
        severity="medium",
        title="Account verification request appears with a link",
        observation=f"The message asks for account verification or reactivation near this text: \"{_safe_snippet(snippet)}\".",
        interpretation=(
            "Account verification links are common in both legitimate and phishing emails. This finding records "
            "the credential-themed workflow but does not judge the linked site."
        ),
        evidence_id="credential.account_verification_with_link",
        evidence_sources=evidence_sources,
        contribution=0,
    )


def _urgency_threat_finding(evidence_sources: tuple[str, ...]) -> DetectorFinding:
    return DetectorFinding(
        id="credential_urgent_account_threat",
        severity="medium",
        title="Credential request includes account-loss pressure",
        observation="The message combines credential or account-verification language with urgent account-loss pressure.",
        interpretation=(
            "Urgency and account suspension threats can pressure users into unsafe actions. Urgency alone is not "
            "conclusive, so this finding is only emitted with credential-related request context."
        ),
        evidence_id="credential.urgent_account_threat",
        evidence_sources=evidence_sources,
        contribution=0,
    )


def _credential_request_with_link_finding(evidence_sources: tuple[str, ...]) -> DetectorFinding:
    return DetectorFinding(
        id="credential_request_with_link",
        severity="low",
        title="Credential request appears alongside links",
        observation="The message contains credential-request language and at least one parsed link.",
        interpretation=(
            "A credential request paired with a link can be risky, but many legitimate services also use links. "
            "URL destination analysis is handled by the separate URL detector."
        ),
        evidence_id="credential.request_with_link",
        evidence_sources=evidence_sources,
        contribution=0,
    )


def _security_bypass_finding(snippet: str, evidence_sources: tuple[str, ...]) -> DetectorFinding:
    return DetectorFinding(
        id="credential_security_bypass_instruction",
        severity="medium",
        title="Message asks to bypass security procedures",
        observation=f"The message includes security-bypass wording: \"{_safe_snippet(snippet)}\".",
        interpretation=(
            "Instructions to ignore or bypass security controls are suspicious, but still require context and "
            "out-of-band verification."
        ),
        evidence_id="credential.security_bypass_instruction",
        evidence_sources=evidence_sources,
        contribution=0,
    )


def _active_message_text(parsed_email: ParsedEmail) -> str:
    raw_text = "\n".join(part for part in [parsed_email.text_body, parsed_email.html_visible_text] if part)
    active_lines: list[str] = []
    in_forwarded_block = False
    for line in raw_text.splitlines():
        stripped = line.strip()
        if _FORWARDED_MARKER_RE.match(stripped):
            in_forwarded_block = True
            continue
        if in_forwarded_block:
            continue
        if stripped.startswith(">") or _HEADER_LINE_RE.match(stripped):
            continue
        active_lines.append(stripped)
    return " ".join(line for line in active_lines if line)


def _find_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    return _sentence_containing(text, match.start(), match.end())


def _sentence_containing(text: str, start: int, end: int) -> str:
    left_boundaries = [text.rfind(mark, 0, start) for mark in ".!?\n"]
    right_boundaries = [index for mark in ".!?\n" if (index := text.find(mark, end)) != -1]
    left = max(left_boundaries) + 1
    right = min(right_boundaries) if right_boundaries else len(text)
    return text[left:right].strip()


def _has_ambiguous_context(text: str) -> bool:
    lowered = text.lower()
    credential_terms = ("password", "otp", "mfa", "verification code", "security code", "verify your account")
    return any(term in lowered for term in credential_terms)


def _evidence_sources(parsed_email: ParsedEmail, subject: str, active_body: str) -> tuple[str, ...]:
    sources: list[str] = []
    if subject:
        sources.append("subject")
    if parsed_email.text_body and active_body:
        sources.append(EvidenceSource.TEXT_BODY.value)
    if parsed_email.html_visible_text and active_body:
        sources.append(EvidenceSource.HTML_BODY.value)
    if parsed_email.text_urls:
        sources.append("text_urls")
    if parsed_email.html_links:
        sources.append("html_links")
    return tuple(dict.fromkeys(sources))


def _safe_snippet(value: str) -> str:
    collapsed = " ".join(value.split())
    redacted = re.sub(r"\b\d{4,8}\b", "[redacted-code]", collapsed)
    return redacted[:160]


def _dedupe_findings(findings: list[DetectorFinding]) -> list[DetectorFinding]:
    seen: set[str] = set()
    deduped: list[DetectorFinding] = []
    for finding in findings:
        if finding.evidence_id in seen:
            continue
        seen.add(finding.evidence_id)
        deduped.append(finding)
    return deduped
