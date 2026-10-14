from __future__ import annotations

import re

from backend.app.detectors import text_context
from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.parsing import ParsedEmail


DETECTOR_ID = "credential_context"
IMPLEMENTATION_VERSION = "credentials-0.1.0"

_CODE_SECRET_TERMS = (
    r"(?:(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten)[-\s]?digit\s+)?"
    r"(?:verification|authentication|security|login)\s+code"
)
_SECRET_TERMS = rf"(?:password|passcode|otp|mfa|2fa|{_CODE_SECRET_TERMS})"
_REQUEST_ACTIONS = (
    r"(?:enter|submit|provide|share|send|reply\s+with|reply\s+to[\w\s,.;:'\"/-]{0,40}\s+with|"
    r"confirm|verify|give us|update)"
)
_CREDENTIAL_REQUEST_RE = re.compile(
    rf"\b{_REQUEST_ACTIONS}\b[\w\s,.;:'\"/-]{{0,80}}\b{_SECRET_TERMS}\b"
    rf"|\b{_SECRET_TERMS}\b[\w\s,.;:'\"/-]{{0,80}}\b(?:to continue|to restore|to keep|to avoid|on the form|in the link)\b",
    re.IGNORECASE,
)
_SAFETY_WARNING_RE = re.compile(
    rf"\b(?:never|do not|don't|dont)\b[\w\s,.;:'\"/-]{{0,40}}\b{_REQUEST_ACTIONS}\b"
    rf"[\w\s,.;:'\"/-]{{0,80}}\b{_SECRET_TERMS}\b",
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
_BYPASS_VERB_RE = re.compile(r"\b(?:ignore|bypass|disable|turn off)\b", re.IGNORECASE)
# A negation shortly before the verb, with no comma or clause break in between, marks a warning such as
# "do not disable MFA" or "will never ask you to bypass security checks". Double negatives that still
# urge the action ("don't forget to disable MFA") are not warnings.
_NEGATED_INSTRUCTION_RE = re.compile(
    r"\b(?:never|do not|don['’]?t|should not|shouldn['’]?t|must not|mustn['’]?t|will not|won['’]?t"
    r"|cannot|can['’]?t)\b"
    r"(?:(?!\b(?:but|however|forget|hesitate|fail|delay|wait|neglect)\b)[\w\s'’/-]){0,25}$",
    re.IGNORECASE,
)
_NORMAL_LOGIN_BYPASS_RE = re.compile(
    r"\b(?:do not|don't|dont|avoid|skip)\b[\w\s,.;:'\"/-]{0,40}\b(?:normal|usual|official)\s+login\s+page\b",
    re.IGNORECASE,
)
FORWARDED_CONTENT_GAP = (
    "This message contains forwarded content that was not assessed for credential requests; only text written "
    "by the forwarding sender was checked."
)
QUOTED_ONLY_GAP = (
    "The message body contained only quoted or header-style lines, which were not assessed for credential requests."
)
QUOTED_LINES_NOTE = "Quoted reply lines in the plain-text body were not assessed for credential requests."


def detect_credential_phishing_context(parsed_email: ParsedEmail) -> DetectorResult:
    # Subject, plain-text body and visible HTML text are separate contexts, with forwarded and quoted
    # content removed; see text_context.active_text.
    active = text_context.active_text(parsed_email)
    subject, active_bodies, contexts = active.subject, list(active.active_bodies), list(active.contexts)
    forwarded_excluded, quoted_excluded = active.forwarded_excluded, active.quoted_excluded
    has_links = bool(parsed_email.text_urls or parsed_email.html_links)
    evidence_sources = text_context.evidence_sources(parsed_email, subject, active.active_body)
    # Excluded content is never attributed to the sender, but it is reported so that it cannot pass as assessed.
    coverage_gaps: tuple[str, ...] = ()
    exclusion_notes: list[str] = []
    if forwarded_excluded:
        coverage_gaps = (FORWARDED_CONTENT_GAP,)
    elif quoted_excluded and not active_bodies:
        coverage_gaps = (QUOTED_ONLY_GAP,)
    elif quoted_excluded:
        exclusion_notes.append(QUOTED_LINES_NOTE)
    limitations = [
        *coverage_gaps,
        *exclusion_notes,
        "Credential-context checks are English-focused heuristic language rules.",
        "The detector does not determine whether linked websites are malicious and does not score risk.",
    ]

    if not contexts:
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
            coverage_gaps=coverage_gaps,
        )

    findings: list[DetectorFinding] = []
    credential_request = text_context.first_in_contexts(_find_credential_request, contexts)
    account_verification = text_context.first_in_contexts(
        lambda text: text_context.find_match(_ACCOUNT_VERIFICATION_RE, text), contexts
    )
    urgency = any(_has_urgent_threat(subject, body) for body in active_bodies or [""])
    bypass = text_context.first_in_contexts(_find_security_bypass, contexts)
    if not bypass and credential_request:
        bypass = text_context.first_in_contexts(
            lambda text: text_context.find_match(_NORMAL_LOGIN_BYPASS_RE, text), contexts
        )

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

    deduped_findings = text_context.dedupe_findings(findings)
    if deduped_findings:
        status = DetectorStatus.TRIGGERED
    elif coverage_gaps:
        status = DetectorStatus.INCONCLUSIVE
    elif any(_has_ambiguous_context(context) for context in contexts):
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
        coverage_gaps=coverage_gaps,
    )


def _credential_collection_finding(snippet: str, evidence_sources: tuple[str, ...]) -> DetectorFinding:
    return DetectorFinding(
        id="credential_secret_collection_request",
        severity="medium",
        title="Message asks for login secrets",
        observation=f"The message includes a request pattern involving login secrets: \"{text_context.safe_snippet(snippet)}\".",
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
        observation=f"The message asks for account verification or reactivation near this text: \"{text_context.safe_snippet(snippet)}\".",
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
        observation=f"The message includes security-bypass wording: \"{text_context.safe_snippet(snippet)}\".",
        interpretation=(
            "Instructions to ignore or bypass security controls are suspicious, but still require context and "
            "out-of-band verification."
        ),
        evidence_id="credential.security_bypass_instruction",
        evidence_sources=evidence_sources,
        contribution=0,
    )




def _has_urgent_threat(subject: str, body: str) -> bool:
    """Urgency and threat wording may co-occur across the subject and one body; neither is a spanning match."""
    texts = [text for text in (subject, body) if text]
    return any(_URGENCY_RE.search(text) for text in texts) and any(_THREAT_RE.search(text) for text in texts)






def _find_credential_request(text: str) -> str:
    for match in _CREDENTIAL_REQUEST_RE.finditer(text):
        sentence = text_context.sentence_containing(text, match.start(), match.end())
        if _SAFETY_WARNING_RE.search(sentence):
            continue
        return sentence
    return ""


def _find_security_bypass(text: str) -> str:
    """Return the first sentence that itself instructs the reader to bypass a security control."""
    for sentence in text_context.SENTENCE_BREAK_RE.split(text):
        for verb in _BYPASS_VERB_RE.finditer(sentence):
            if not _SECURITY_BYPASS_RE.match(sentence, verb.start()):
                continue
            if _NEGATED_INSTRUCTION_RE.search(sentence[: verb.start()]):
                continue
            return sentence.strip()
    return ""




def _has_ambiguous_context(text: str) -> bool:
    lowered = text.lower()
    credential_terms = ("password", "otp", "mfa", "verification code", "security code", "verify your account")
    return any(term in lowered for term in credential_terms)
