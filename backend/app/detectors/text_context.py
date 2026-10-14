"""Shared helpers for detectors that read message wording.

They separate the sender's own text from forwarded and quoted content, keep the subject and each body
representation as separate contexts, and turn matches into short, redacted evidence snippets. They hold no
detector-specific rules.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import re

from backend.app.detectors.base import DetectorFinding
from backend.app.parsing import EvidenceSource, ParsedEmail


SENTENCE_BREAK_RE = re.compile(r"(?<=[.!?])\s+")
_FORWARDED_MARKER_RE = re.compile(r"^\s*(?:[-]+\s*)?(?:forwarded message|original message)(?:\s*[-]+)?\s*$", re.IGNORECASE)
_HEADER_LINE_RE = re.compile(r"^\s*(?:from|sent|to|subject):\s+.+", re.IGNORECASE)


@dataclass(frozen=True)
class ActiveText:
    """The text a detector may attribute to the sender, and what was left out."""

    subject: str
    # The plain-text body and the visible HTML text, each without forwarded or quoted content.
    active_bodies: tuple[str, ...]
    # Subject and bodies as separate contexts, so a pattern can never span from one into another.
    contexts: tuple[str, ...]
    active_body: str
    forwarded_excluded: bool
    quoted_excluded: bool


def active_text(parsed_email: ParsedEmail) -> ActiveText:
    subject = parsed_email.subject.strip()
    # The plain-text body and the visible HTML text are alternative representations of one message. Each is
    # matched as its own context so a pattern can never span the end of one and the start of the other.
    # A forwarded-message marker in the plain text hides everything after it. The HTML copy repeats that
    # forwarded content without line structure, so it is not used as a second context in that case.
    text_active, forwarded_excluded, quoted_excluded = split_active_text(parsed_email.text_body)
    html_active, _, _ = split_active_text("" if forwarded_excluded else parsed_email.html_visible_text)
    active_bodies = tuple(body for body in (text_active, html_active) if body)
    return ActiveText(
        subject=subject,
        active_bodies=active_bodies,
        # The subject is a context of its own as well, so a pattern cannot span the subject/body boundary.
        contexts=tuple(dict.fromkeys(part for part in [subject, *active_bodies] if part)),
        active_body=" ".join(active_bodies),
        forwarded_excluded=forwarded_excluded,
        quoted_excluded=quoted_excluded,
    )


def split_active_text(raw_text: str) -> tuple[str, bool, bool]:
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


def first_in_contexts(find: Callable[[str], str], contexts: tuple[str, ...] | list[str]) -> str:
    for context in contexts:
        found = find(context)
        if found:
            return found
    return ""


def find_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    return sentence_containing(text, match.start(), match.end())


def sentence_containing(text: str, start: int, end: int) -> str:
    left_boundaries = [text.rfind(mark, 0, start) for mark in ".!?\n"]
    right_boundaries = [index for mark in ".!?\n" if (index := text.find(mark, end)) != -1]
    left = max(left_boundaries) + 1
    right = min(right_boundaries) if right_boundaries else len(text)
    return text[left:right].strip()


def evidence_sources(parsed_email: ParsedEmail, subject: str, active_body: str) -> tuple[str, ...]:
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


def safe_snippet(value: str) -> str:
    collapsed = " ".join(value.split())
    redacted_urls = re.sub(
        r"(https?://[^\s\"'<>?#]+)(?:\?[^\s\"'<>#]*)?(?:#[^\s\"'<>]*)?",
        r"\1",
        collapsed,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(r"\b\d{4,8}\b", "[redacted-code]", redacted_urls)
    return redacted[:160]


def dedupe_findings(findings: list[DetectorFinding]) -> list[DetectorFinding]:
    seen: set[str] = set()
    deduped: list[DetectorFinding] = []
    for finding in findings:
        if finding.evidence_id in seen:
            continue
        seen.add(finding.evidence_id)
        deduped.append(finding)
    return deduped
