"""Attachment metadata threat detector (WBS 2.5 Stage 2).

Checks attachment names as received from the Gmail add-on. Attachment content is never read, opened, hashed or
downloaded, and a name is untrusted metadata: an extension does not prove what a file contains. MIME types and
sizes are not scored.

Findings never quote a filename. Observations name only extensions from the fixed lists below and an
attachment's position in Gmail's list.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.parsing import AttachmentCollectionState, EvidenceSource, ParsedAttachment, ParsedEmail


DETECTOR_ID = "attachment_metadata"
IMPLEMENTATION_VERSION = "attachments-0.1.0"

# Exact final-extension lists. An extension not listed here is never scored, however unfamiliar.
# ATT-01: Windows programs and installers that run when opened.
EXECUTABLE_EXTENSIONS = frozenset({"exe", "scr", "com", "pif", "cpl", "msi", "msp", "msix", "appx", "jar"})
# ATT-02: script hosts and command interpreters, plus .lnk: a Windows shortcut stores a target command line and
# arguments, so opening one can run a command. Internet shortcuts (.url) are not listed: what they open depends on
# a target inside the file, which is not read.
SCRIPT_EXTENSIONS = frozenset({"bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk"})
# ATT-06: formats that render or embed active content when opened. Common in legitimate mail.
ACTIVE_CONTENT_EXTENSIONS = frozenset({"html", "htm", "xhtml", "shtml", "mht", "mhtml", "svg", "one"})
# ATT-07: Office formats that can carry macros. Common in legitimate business mail.
MACRO_OFFICE_EXTENSIONS = frozenset(
    {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm", "ppam", "sldm"}
)
# ATT-03: harmless-looking extensions that, placed before a program or script extension, disguise it.
DECOY_EXTENSIONS = frozenset(
    {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "odt", "ods", "odp",
        "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "mp3", "mp4", "mov", "avi", "wav",
        "zip", "rar", "7z",
    }
)
RUNNABLE_EXTENSIONS = EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS

# Zero-width characters with no ordinary use inside a filename.
_ALWAYS_SUSPICIOUS_ZERO_WIDTH = frozenset({"​", "⁠", "﻿"})
# Zero-width joiner and non-joiner are needed in Persian, Indic and emoji text. They count only when they sit
# next to an ASCII character, where they can split a Latin word or an extension.
_JOINERS = frozenset({"‌", "‍"})
_BIDI_CONTROLS = frozenset(chr(code) for first, last in ((0x202A, 0x202E), (0x2066, 0x2069)) for code in range(first, last + 1))
_INVISIBLE_FORMATTING = _BIDI_CONTROLS | _ALWAYS_SUSPICIOUS_ZERO_WIDTH | _JOINERS

# Windows ignores trailing dots and spaces in a filename, so the extension is read after removing them. This
# matches finalExtension_ in addon/Code.js, which summarizes omitted attachments the same way.
_TRAILING_DOTS_AND_SPACE_RE = re.compile(r"[.\s]+$")

# Rule codes used in the documentation, by finding ID.
RULE_CODES: dict[str, str] = {
    "attachment_executable_extension": "ATT-01",
    "attachment_script_extension": "ATT-02",
    "attachment_deceptive_double_extension": "ATT-03",
    "attachment_bidi_control_name": "ATT-04",
    "attachment_invisible_character_name": "ATT-05",
    "attachment_active_content_type": "ATT-06",
    "attachment_macro_enabled_office": "ATT-07",
}

CONTENT_NOT_INSPECTED = (
    "Attachment checks read only attachment names. Attachment content was not opened or scanned, and a name "
    "does not prove what a file contains."
)


@dataclass(frozen=True)
class _NameReading:
    """What can be read reliably from one attachment name."""

    final_extension: str | None
    decoy_extension: str | None
    has_bidi_control: bool
    has_suspicious_zero_width: bool
    # Zero-width characters were reported where their neighbours are unknown (a shortened-out part).
    unlocated_zero_width: bool
    name_unreadable: bool
    double_extension_unchecked: bool


def detect_suspicious_attachments(parsed_email: ParsedEmail) -> DetectorResult:
    coverage = parsed_email.attachment_coverage
    evidence_sources = (EvidenceSource.ATTACHMENTS.value,)

    if coverage.state == AttachmentCollectionState.NONE:
        return DetectorResult(
            detector_id=DETECTOR_ID,
            status=DetectorStatus.NOT_TRIGGERED,
            evidence_sources=evidence_sources,
            implementation_version=IMPLEMENTATION_VERSION,
        )
    if coverage.state not in {AttachmentCollectionState.COLLECTED, AttachmentCollectionState.TRUNCATED}:
        # UNAVAILABLE, or UNKNOWN: a client that sent no collection state, or a state that contradicted the
        # list. Any names that arrived are not trusted, and missing metadata never lowers risk.
        return DetectorResult(
            detector_id=DETECTOR_ID,
            status=DetectorStatus.INCONCLUSIVE,
            evidence_sources=evidence_sources,
            limitations=(_inconclusive_reason(coverage.state, coverage.declared_state),),
            implementation_version=IMPLEMENTATION_VERSION,
        )

    findings: list[DetectorFinding] = []
    limitations: list[str] = [CONTENT_NOT_INSPECTED]
    seen: set[tuple[object, ...]] = set()
    duplicates = 0
    unreadable = 0
    unchecked_double = 0
    unlocated_zero_width = 0

    for position, attachment in enumerate(parsed_email.attachments, start=1):
        key = _identity(attachment)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        reading = _read_name(attachment)
        unreadable += reading.name_unreadable
        unchecked_double += reading.double_extension_unchecked
        unlocated_zero_width += reading.unlocated_zero_width
        findings.extend(_findings_for(reading, f"attachment:{position}", _listed_subject(position)))

    truncated = coverage.state == AttachmentCollectionState.TRUNCATED
    if truncated and coverage.omitted_count > 0:
        findings.extend(_omitted_summary_findings(coverage.omitted_extensions, coverage.omitted_name_flags))
        limitations.append(_omitted_limitation(coverage.omitted_count, coverage.reasons))

    if duplicates:
        limitations.append(f"{duplicates} attachment entries repeated an earlier entry exactly and were checked once.")
    if unreadable:
        limitations.append(
            f"{unreadable} attachment names were unavailable or could not be read reliably, so they were not checked."
        )
    if unchecked_double:
        limitations.append(
            f"{unchecked_double} long attachment names were shortened before analysis; a double extension that "
            "spans the shortened part cannot be detected."
        )
    if unlocated_zero_width:
        limitations.append(
            f"{unlocated_zero_width} attachment names had zero-width characters in a shortened-out part, where "
            "they could not be told apart from ordinary text joining characters; they were not scored."
        )

    if findings:
        status = DetectorStatus.TRIGGERED
    elif truncated:
        status = DetectorStatus.INCONCLUSIVE
        limitations.insert(0, "Attachment metadata was incomplete and no supported attachment finding was made.")
    else:
        status = DetectorStatus.NOT_TRIGGERED

    return DetectorResult(
        detector_id=DETECTOR_ID,
        status=status,
        findings=tuple(findings),
        evidence_sources=evidence_sources,
        limitations=tuple(limitations),
        implementation_version=IMPLEMENTATION_VERSION,
    )


def _inconclusive_reason(state: AttachmentCollectionState, declared_state: str | None) -> str:
    if state == AttachmentCollectionState.UNAVAILABLE:
        return "Attachment information could not be collected, so the attachment check was inconclusive."
    if declared_state is None:
        return "No attachment collection state was sent, so the attachment check was inconclusive."
    return "The attachment information received was inconsistent, so the attachment check was inconclusive."


def _identity(attachment: ParsedAttachment) -> tuple[object, ...]:
    return (
        attachment.name_segments,
        attachment.name_original_length,
        attachment.content_type,
        attachment.size_bytes,
        attachment.unavailable_fields,
    )


def _read_name(attachment: ParsedAttachment) -> _NameReading:
    segments = attachment.name_segments
    if "filename" in attachment.unavailable_fields or not any(segment.strip() for segment in segments):
        return _NameReading(None, None, "BIDI_CONTROL" in attachment.name_flags, False, False, True, False)

    has_bidi = "BIDI_CONTROL" in attachment.name_flags
    visible_zero_width = any(_has_suspicious_zero_width(segment) for segment in segments)
    # name_flags also covers a shortened-out middle, where a joiner's neighbours are unknown.
    unlocated_zero_width = "ZERO_WIDTH" in attachment.name_flags and not visible_zero_width and not any(
        char in _INVISIBLE_FORMATTING - _BIDI_CONTROLS for segment in segments for char in segment
    )

    if not attachment.name_clipped:
        final, decoy = _extensions(segments[0])
        return _NameReading(final, decoy, has_bidi, visible_zero_width, unlocated_zero_width, False, False)

    tail = segments[-1]
    # A tail of only dots and spaces is dropped by Windows, so the real extension would lie in the shortened part.
    if not _clip_is_coherent(attachment) or not _TRAILING_DOTS_AND_SPACE_RE.sub("", tail):
        return _NameReading(None, None, has_bidi, visible_zero_width, unlocated_zero_width, True, False)
    # The tail is the end of the original name, so an extension whose dot is inside it is the real one. A tail
    # without a dot means any extension is longer than the tail, so none of the listed ones. A decoy extension
    # counts only if its dot is inside the tail too: nothing is read across the shortened part.
    final, decoy = _extensions(tail)
    unchecked = final in RUNNABLE_EXTENSIONS and decoy is None
    return _NameReading(final, decoy, has_bidi, visible_zero_width, unlocated_zero_width, False, unchecked)


def _clip_is_coherent(attachment: ParsedAttachment) -> bool:
    head, tail = attachment.name_segments[0], attachment.name_segments[-1]
    original = attachment.name_original_length
    return bool(tail) and original is not None and original > len(head) + len(tail)


def _extensions(name: str) -> tuple[str | None, str | None]:
    trimmed = _TRAILING_DOTS_AND_SPACE_RE.sub("", name)
    dot = trimmed.rfind(".")
    if dot < 0:
        return None, None
    final = trimmed[dot + 1 :].lower()
    if final not in RUNNABLE_EXTENSIONS:
        return final, None
    # Padding and invisible formatting before the real extension do not change what a reader sees.
    rest = "".join(char for char in trimmed[:dot] if char not in _INVISIBLE_FORMATTING).rstrip()
    decoy_dot = rest.rfind(".")
    if decoy_dot < 0:
        return final, None
    decoy = rest[decoy_dot + 1 :].lower()
    return final, decoy if decoy in DECOY_EXTENSIONS else None


def _has_suspicious_zero_width(segment: str) -> bool:
    for index, char in enumerate(segment):
        if char in _ALWAYS_SUSPICIOUS_ZERO_WIDTH:
            return True
        if char in _JOINERS:
            neighbours = segment[index - 1 : index] + segment[index + 1 : index + 2]
            if any(" " <= neighbour <= "~" for neighbour in neighbours):
                return True
    return False


def _listed_subject(position: int) -> str:
    return f"The name of attachment {position} in Gmail's list"


def _findings_for(reading: _NameReading, evidence_id: str, subject: str) -> list[DetectorFinding]:
    # Every rule that applies is reported; the scorer credits only the strongest per attachment.
    findings: list[DetectorFinding] = []
    final = reading.final_extension
    if final in RUNNABLE_EXTENSIONS and reading.decoy_extension:
        findings.append(_double_extension_finding(reading.decoy_extension, final, evidence_id, subject))
    if final in EXECUTABLE_EXTENSIONS:
        findings.append(_executable_finding(final, evidence_id, subject))
    elif final in SCRIPT_EXTENSIONS:
        findings.append(_script_finding(final, evidence_id, subject))
    elif final in ACTIVE_CONTENT_EXTENSIONS:
        findings.append(_active_content_finding(final, evidence_id, subject))
    elif final in MACRO_OFFICE_EXTENSIONS:
        findings.append(_macro_finding(final, evidence_id, subject))
    if reading.has_bidi_control:
        findings.append(_bidi_finding(evidence_id, subject))
    if reading.has_suspicious_zero_width:
        findings.append(_zero_width_finding(evidence_id, subject))
    return findings


def _omitted_summary_findings(extensions: tuple[str, ...], flags: frozenset[str]) -> list[DetectorFinding]:
    # The add-on reports omitted names only as a set of lower-cased final extensions and character-class flags.
    # Only exact list matches count; the summary cannot show double extensions or where a character sits, and it
    # cannot tell whether two signals come from the same file, so all of it shares one evidence ID and is
    # credited at most once.
    evidence_id = "attachment:omitted"
    subject = "The name of at least one attachment that was not sent individually"
    findings: list[DetectorFinding] = []
    for extension in sorted(set(extensions)):
        reading = _NameReading(extension, None, False, False, False, False, False)
        findings.extend(_findings_for(reading, evidence_id, subject))
    if "BIDI_CONTROL" in flags:
        findings.append(_bidi_finding(evidence_id, subject))
    return findings


def _omitted_limitation(omitted_count: int, reasons: tuple[str, ...]) -> str:
    line = (
        f"{omitted_count} attachments were not sent individually; only a summary of their final extensions and "
        "hidden-character types was checked."
    )
    if "names_not_read" in reasons:
        line += " Some of their names could not be read at all."
    if "extensions_limit" in reasons:
        line += " The extension summary itself was incomplete."
    return line


def _finding(
    finding_id: str,
    severity: str,
    title: str,
    observation: str,
    interpretation: str,
    evidence_id: str,
) -> DetectorFinding:
    return DetectorFinding(
        id=finding_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        observation=observation,
        interpretation=interpretation,
        evidence_id=evidence_id,
        evidence_sources=(EvidenceSource.ATTACHMENTS.value,),
        contribution=0,
    )


def _double_extension_finding(decoy: str, final: str, evidence_id: str, subject: str) -> DetectorFinding:
    return _finding(
        "attachment_deceptive_double_extension",
        "medium",
        "Deceptive attachment extension",
        f"{subject} ends in a document-like extension followed by a program or script extension (.{decoy}.{final}).",
        "This pattern can disguise a program or script as a document, especially where extensions are hidden. "
        "The file contents were not inspected.",
        evidence_id,
    )


def _executable_finding(final: str, evidence_id: str, subject: str) -> DetectorFinding:
    return _finding(
        "attachment_executable_extension",
        "medium",
        "Program file attached",
        f"{subject} ends in .{final}, an extension Windows runs as a program or installer.",
        "Programs are rarely sent by email legitimately and are a common way to deliver malware. The name alone "
        "does not prove what the file is; its contents were not inspected.",
        evidence_id,
    )


def _script_finding(final: str, evidence_id: str, subject: str) -> DetectorFinding:
    if final == "lnk":
        observation = f"{subject} ends in .lnk, a Windows shortcut that can launch a command when opened."
    else:
        observation = f"{subject} ends in .{final}, a script or command file that can run commands when opened."
    return _finding(
        "attachment_script_extension",
        "medium",
        "Script or command file attached",
        observation,
        "Scripts and shortcuts are a common way to start malware. Some are legitimate in technical work. The "
        "file contents were not inspected.",
        evidence_id,
    )


def _bidi_finding(evidence_id: str, subject: str) -> DetectorFinding:
    return _finding(
        "attachment_bidi_control_name",
        "medium",
        "Hidden text-direction control in attachment name",
        f"{subject} contains a bidirectional override or isolate control character.",
        "These invisible characters can make the end of a filename display in reverse, hiding its real "
        "extension. Ordinary Hebrew or Arabic names do not need them. The file contents were not inspected.",
        evidence_id,
    )


def _zero_width_finding(evidence_id: str, subject: str) -> DetectorFinding:
    return _finding(
        "attachment_invisible_character_name",
        "low",
        "Invisible characters in attachment name",
        f"{subject} contains zero-width characters next to Latin letters, digits or punctuation.",
        "Invisible characters can make a name look like a different one or slip past filters. This is weak "
        "evidence on its own. The file contents were not inspected.",
        evidence_id,
    )


def _active_content_finding(final: str, evidence_id: str, subject: str) -> DetectorFinding:
    return _finding(
        "attachment_active_content_type",
        "low",
        "Attachment type that can contain active content",
        f"{subject} ends in .{final}, a format that can render web pages, scripts or embedded files when opened.",
        "Such files are often legitimate, such as reports and logos, but are also used to deliver fake sign-in "
        "pages. This is weak evidence on its own. The file contents were not inspected.",
        evidence_id,
    )


def _macro_finding(final: str, evidence_id: str, subject: str) -> DetectorFinding:
    return _finding(
        "attachment_macro_enabled_office",
        "low",
        "Macro-enabled Office document",
        f"{subject} ends in .{final}, an Office format that can contain macros.",
        "Many business spreadsheets use macros legitimately; malicious macros usually need you to enable "
        "content. This is weak evidence on its own; whether the file contains a macro was not checked.",
        evidence_id,
    )
