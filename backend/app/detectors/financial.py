"""Deterministic financial-fraud / BEC wording detector.

The detector reads only the sender's active subject/body text. It does not use mailbox history, payment history,
external reputation, link fetching, or account validation, so every finding is phrased as suspicious wording rather
than proof of fraud.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from backend.app.detectors import text_context
from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.parsing import ParsedEmail


DETECTOR_ID = "financial_fraud"
IMPLEMENTATION_VERSION = "financial-0.1.0"

FORWARDED_CONTENT_GAP = (
    "This message contains forwarded content that was not assessed for financial-fraud wording; only text written "
    "by the forwarding sender was checked."
)
QUOTED_ONLY_GAP = (
    "The message body contained only quoted or header-style lines, which were not assessed for financial-fraud wording."
)
QUOTED_LINES_NOTE = "Quoted reply lines in the plain-text body were not assessed for financial-fraud wording."

_PAYMENT_TERMS_RE = re.compile(
    r"\b(?:pay|payment|wire|transfer|remit|send funds|deposit|bank transfer|ach|swift|invoice|vendor|supplier|"
    r"beneficiary|payroll|salary|direct deposit|account payable|accounts payable)\b",
    re.IGNORECASE,
)
_DESTINATION_CHANGE_RE = re.compile(
    r"\b(?:new|updated|changed|different|revised|alternate|replacement)\b[\w\s,.;:'\"/-]{0,60}"
    r"\b(?:bank|account|iban|routing|beneficiary|payment details|wire instructions|remittance details|"
    r"direct deposit)\b"
    r"|\b(?:bank|account|iban|routing|beneficiary|payment details|wire instructions|remittance details|"
    r"direct deposit)\b[\w\s,.;:'\"/-]{0,60}\b(?:changed|updated|revised|new|different|alternate|replacement)\b",
    re.IGNORECASE,
)
_PAYMENT_ACTION_RE = re.compile(
    r"\b(?:pay|wire|transfer|remit|send|deposit|process|settle|release)\b[\w\s,.;:'\"/-]{0,50}"
    r"\b(?:payment|funds|money|invoice|balance|amount|wire|transfer|deposit)\b",
    re.IGNORECASE,
)
_URGENCY_RE = re.compile(
    r"\b(?:urgent|immediately|asap|right away|today|before close of business|before cob|before eod|"
    r"within\s+\d+\s+(?:hour|hours|day|days)|before midnight)\b",
    re.IGNORECASE,
)
_WIRE_RE = re.compile(r"\b(?:wire|bank transfer|ach|swift|funds transfer|transfer funds)\b", re.IGNORECASE)
_AUTHORITY_PRESSURE_RE = re.compile(
    r"\b(?:ceo|cfo|president|director|board|executive|boss|manager|client|vendor|supplier)\b"
    r"|(?:i am|i'm)\s+(?:in a meeting|travelling|traveling|unavailable|out of office)",
    re.IGNORECASE,
)
_GIFT_CARD_RE = re.compile(
    r"\b(?:gift card|gift cards|itunes card|apple card|google play card|steam card|amazon card|prepaid card|voucher)\b",
    re.IGNORECASE,
)
_CODE_SEND_RE = re.compile(
    r"\b(?:send|email|text|reply with|share|scratch|photograph|photo|picture)\b[\w\s,.;:'\"/-]{0,60}"
    r"\b(?:code|codes|pin|pins|redemption|claim code|serial)\b"
    r"|\b(?:code|codes|pin|pins|redemption|claim code|serial)\b[\w\s,.;:'\"/-]{0,60}"
    r"\b(?:send|email|text|reply|share|photo|picture)\b",
    re.IGNORECASE,
)
_BYPASS_RE = re.compile(
    r"\b(?:bypass|skip|ignore|avoid|do not use|don't use|dont use|no need for|without)\b"
    r"[\w\s,.;:'\"/-]{0,70}\b(?:approval|approvals|verification|verify|confirmation|confirm|purchase order|po|"
    r"procurement|finance|accounts payable|accounting|normal process|usual process|callback|call back)\b",
    re.IGNORECASE,
)
_SECRECY_RE = re.compile(
    r"\b(?:confidential|keep this between us|do not tell|don't tell|dont tell|do not discuss|don't discuss|"
    r"private matter|discreet|no calls|do not call|don't call|dont call|use my personal email|text me only|"
    r"reply only here|do not contact)\b",
    re.IGNORECASE,
)
_LEGITIMATE_UPDATE_RE = re.compile(
    r"\b(?:attached|signed|approved|approval|verified|confirmed|call back|callback|vendor portal|supplier portal|"
    r"change form|bank letter|voided check|effective\s+\w+\s+\d{1,2}|takes effect|as previously agreed)\b",
    re.IGNORECASE,
)
_NEGATED_REQUEST_RE = re.compile(
    r"\b(?:do not|don't|dont|never|will not|won't|wont|cannot|can't|cant|should not|shouldn't|shouldnt|"
    r"must not|mustn't|mustnt)\b[\w\s,.;:'\"/-]{0,80}"
    r"\b(?:pay|wire|transfer|send|deposit|change|update|bypass|skip|ignore|buy|purchase|share|send)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _Sentence:
    text: str
    evidence_id: str
    sources: tuple[str, ...]


def detect_financial_fraud(parsed_email: ParsedEmail) -> DetectorResult:
    active = text_context.active_text(parsed_email)
    evidence_sources = text_context.evidence_sources(parsed_email, active.subject, active.active_body)
    coverage_gaps: tuple[str, ...] = ()
    exclusion_notes: list[str] = []
    if active.forwarded_excluded:
        coverage_gaps = (FORWARDED_CONTENT_GAP,)
    elif active.quoted_excluded and not active.active_bodies:
        coverage_gaps = (QUOTED_ONLY_GAP,)
    elif active.quoted_excluded:
        exclusion_notes.append(QUOTED_LINES_NOTE)

    limitations = [
        *coverage_gaps,
        *exclusion_notes,
        "Financial-fraud checks are English-focused heuristic wording rules.",
        "The detector cannot verify payment history, vendor identity, bank-account ownership, or approval records.",
    ]

    if not active.contexts:
        return DetectorResult(
            detector_id=DETECTOR_ID,
            status=DetectorStatus.INCONCLUSIVE,
            evidence_sources=evidence_sources,
            limitations=tuple(["No subject or active body text was available for financial-fraud analysis.", *limitations]),
            implementation_version=IMPLEMENTATION_VERSION,
            coverage_gaps=coverage_gaps,
        )

    sentences = _sentences(active.contexts, evidence_sources)
    findings: list[DetectorFinding] = []
    for sentence in sentences:
        if _is_negated_warning(sentence.text):
            continue
        findings.extend(_findings_for(sentence))

    if findings:
        status = DetectorStatus.TRIGGERED
    elif coverage_gaps:
        status = DetectorStatus.INCONCLUSIVE
    elif any(_has_ambiguous_context(sentence.text) for sentence in sentences):
        status = DetectorStatus.INCONCLUSIVE
        limitations = ["Financial wording was present but lacked enough suspicious request context for a rule to trigger.", *limitations]
    else:
        status = DetectorStatus.NOT_TRIGGERED
        limitations = ["No financial-fraud rule triggered; this is not a guarantee that the message is safe.", *limitations]

    return DetectorResult(
        detector_id=DETECTOR_ID,
        status=status,
        findings=tuple(findings),
        evidence_sources=evidence_sources,
        limitations=tuple(limitations),
        implementation_version=IMPLEMENTATION_VERSION,
        coverage_gaps=coverage_gaps,
    )


def _sentences(contexts: tuple[str, ...], evidence_sources: tuple[str, ...]) -> list[_Sentence]:
    sentences: list[_Sentence] = []
    for context_index, context in enumerate(contexts):
        for sentence_index, raw_sentence in enumerate(text_context.SENTENCE_BREAK_RE.split(context)):
            sentence = raw_sentence.strip()
            if not sentence:
                continue
            digest = hashlib.sha256(sentence.lower().encode("utf-8", errors="ignore")).hexdigest()[:12]
            sentences.append(_Sentence(sentence, f"financial_fraud.sentence:{context_index}:{sentence_index}:{digest}", evidence_sources))
    return sentences


def _findings_for(sentence: _Sentence) -> list[DetectorFinding]:
    text = sentence.text
    has_payment = bool(_PAYMENT_TERMS_RE.search(text) or _PAYMENT_ACTION_RE.search(text))
    findings: list[DetectorFinding] = []
    if _DESTINATION_CHANGE_RE.search(text) and _PAYMENT_ACTION_RE.search(text) and not _LEGITIMATE_UPDATE_RE.search(text):
        findings.append(_finding("financial_payment_destination_change", "medium", "Payment destination change request", text, sentence))
    if has_payment and _URGENCY_RE.search(text) and (_WIRE_RE.search(text) or _AUTHORITY_PRESSURE_RE.search(text)):
        findings.append(_finding("financial_urgent_payment_request", "medium", "Urgent payment pressure", text, sentence))
    if _GIFT_CARD_RE.search(text) and _CODE_SEND_RE.search(text):
        findings.append(_finding("financial_gift_card_code_request", "medium", "Gift-card code request", text, sentence))
    if has_payment and _BYPASS_RE.search(text):
        findings.append(_finding("financial_verification_bypass_request", "medium", "Financial verification bypass request", text, sentence))
    if has_payment and _SECRECY_RE.search(text):
        findings.append(_finding("financial_secret_or_channel_avoidance", "medium", "Financial request asks for secrecy", text, sentence))
    return findings


def _is_negated_warning(sentence: str) -> bool:
    return bool(_NEGATED_REQUEST_RE.search(sentence))


def _has_ambiguous_context(sentence: str) -> bool:
    return bool(_PAYMENT_TERMS_RE.search(sentence) or _DESTINATION_CHANGE_RE.search(sentence) or _GIFT_CARD_RE.search(sentence))


def _finding(finding_id: str, severity: str, title: str, sentence: str, evidence: _Sentence) -> DetectorFinding:
    snippet = _safe_financial_snippet(sentence)
    interpretations = {
        "financial_payment_destination_change": (
            "Payment redirection is a common BEC pattern. Legitimate vendors can change details, so verify using an "
            "independently established process before paying."
        ),
        "financial_urgent_payment_request": (
            "Urgent wire or payment pressure can be used to rush financial controls. Urgency alone is not enough; "
            "this finding requires payment context plus additional pressure."
        ),
        "financial_gift_card_code_request": (
            "Requests to buy gift cards and send redemption codes are a common fraud pattern. Legitimate reward "
            "programs usually do not ask for codes by email."
        ),
        "financial_verification_bypass_request": (
            "Instructions to skip normal finance approval or callback checks are suspicious. They should be verified "
            "through the usual finance workflow."
        ),
        "financial_secret_or_channel_avoidance": (
            "Secrecy or avoiding normal contact channels can prevent routine verification of a financial request."
        ),
    }
    return DetectorFinding(
        id=finding_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        observation=f"The message contains this financial-request pattern: \"{snippet}\".",
        interpretation=interpretations[finding_id],
        evidence_id=evidence.evidence_id,
        evidence_sources=evidence.sources,
        contribution=0,
    )


def _safe_financial_snippet(value: str) -> str:
    snippet = text_context.safe_snippet(value)
    snippet = re.sub(r"\b[A-Z]{2}\d{2}[A-Z0-9]{8,30}\b", "[redacted-account]", snippet, flags=re.IGNORECASE)
    snippet = re.sub(
        r"\b(account|acct|iban|routing|sort code|swift)\s*(?:number|no\.?|#)?\s*[:#-]?\s*[A-Z0-9 -]{4,}\b",
        r"\1 [redacted-account]",
        snippet,
        flags=re.IGNORECASE,
    )
    snippet = re.sub(
        r"\b(invoice|inv|payment|reference|ref|transaction|txn)\s*(?:number|no\.?|id|#)?\s*[:#-]?\s*[A-Z0-9][A-Z0-9-]{3,}\b",
        r"\1 [redacted-id]",
        snippet,
        flags=re.IGNORECASE,
    )
    snippet = re.sub(r"\b\d[\d -]{8,}\d\b", "[redacted-number]", snippet)
    return snippet[:160]
