from __future__ import annotations

from collections.abc import Callable
import re

from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.parsing import EvidenceSource, ParsedEmail


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
_SENTENCE_BREAK_RE = re.compile(r"(?<=[.!?])\s+")
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
_FORWARDED_MARKER_RE = re.compile(r"^\s*(?:[-]+\s*)?(?:forwarded message|original message)(?:\s*[-]+)?\s*$", re.IGNORECASE)
_HEADER_LINE_RE = re.compile(r"^\s*(?:from|sent|to|subject):\s+.+", re.IGNORECASE)


def detect_credential_phishing_context(parsed_email: ParsedEmail) -> DetectorResult:
    subject = parsed_email.subject.strip()
    # The plain-text body and the visible HTML text are alternative representations of one message. Each is
    # matched as its own context so a pattern can never span the end of one and the start of the other.
    # A forwarded-message marker in the plain text hides everything after it. The HTML copy repeats that
    # forwarded content without line structure, so it is not used as a second context in that case.
    text_active, forwarded_excluded, quoted_excluded = _split_active_text(parsed_email.text_body)
    html_active, _, _ = _split_active_text("" if forwarded_excluded else parsed_email.html_visible_text)
    active_bodies = [body for body in (text_active, html_active) if body]
    active_body = " ".join(active_bodies)
    # The subject is a context of its own as well, so a pattern cannot span the subject/body boundary.
    contexts = list(dict.fromkeys(part for part in [subject, *active_bodies] if part))
    has_links = bool(parsed_email.text_urls or parsed_email.html_links)
    evidence_sources = _evidence_sources(parsed_email, subject, active_body)
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
    credential_request = _first_in_contexts(_find_credential_request, contexts)
    account_verification = _first_in_contexts(lambda text: _find_match(_ACCOUNT_VERIFICATION_RE, text), contexts)
    urgency = any(_has_urgent_threat(subject, body) for body in active_bodies or [""])
    bypass = _first_in_contexts(_find_security_bypass, contexts)
    if not bypass and credential_request:
        bypass = _first_in_contexts(lambda text: _find_match(_NORMAL_LOGIN_BYPASS_RE, text), contexts)

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


def _first_in_contexts(find: Callable[[str], str], contexts: list[str]) -> str:
    for context in contexts:
        found = find(context)
        if found:
            return found
    return ""


def _has_urgent_threat(subject: str, body: str) -> bool:
    """Urgency and threat wording may co-occur across the subject and one body; neither is a spanning match."""
    texts = [text for text in (subject, body) if text]
    return any(_URGENCY_RE.search(text) for text in texts) and any(_THREAT_RE.search(text) for text in texts)


def _split_active_text(raw_text: str) -> tuple[str, bool, bool]:
    """Return the sender's own text and whether forwarded or quoted content was excluded from it."""
    active_lines: list[str] = []
    forwarded_excluded = False
    quoted_excluded = False
    for line in raw_text.splitlines():
        stripped = line.strip()
        if _FORWARDED_MARKER_RE.match(stripped):
            forwarded_excluded = True
            continue
        if forwarded_excluded:
            continue
        if stripped.startswith(">") or _HEADER_LINE_RE.match(stripped):
            quoted_excluded = quoted_excluded or bool(stripped.lstrip("> "))
            continue
        active_lines.append(stripped)
    return " ".join(line for line in active_lines if line), forwarded_excluded, quoted_excluded


def _find_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    return _sentence_containing(text, match.start(), match.end())


def _find_credential_request(text: str) -> str:
    for match in _CREDENTIAL_REQUEST_RE.finditer(text):
        sentence = _sentence_containing(text, match.start(), match.end())
        if _SAFETY_WARNING_RE.search(sentence):
            continue
        return sentence
    return ""


def _find_security_bypass(text: str) -> str:
    """Return the first sentence that itself instructs the reader to bypass a security control."""
    for sentence in _SENTENCE_BREAK_RE.split(text):
        for verb in _BYPASS_VERB_RE.finditer(sentence):
            if not _SECURITY_BYPASS_RE.match(sentence, verb.start()):
                continue
            if _NEGATED_INSTRUCTION_RE.search(sentence[: verb.start()]):
                continue
            return sentence.strip()
    return ""


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
    redacted_urls = re.sub(
        r"(https?://[^\s\"'<>?#]+)(?:\?[^\s\"'<>#]*)?(?:#[^\s\"'<>]*)?",
        r"\1",
        collapsed,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(r"\b\d{4,8}\b", "[redacted-code]", redacted_urls)
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
