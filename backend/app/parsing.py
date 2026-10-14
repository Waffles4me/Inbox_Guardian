from __future__ import annotations

from dataclasses import dataclass, field
from email.utils import getaddresses
from enum import StrEnum
from html import unescape
from html.parser import HTMLParser
import re
from urllib.parse import urlsplit, urlunsplit

from .models import AttachmentCollection, AttachmentMetadata, EmailPayload


MAX_URLS = 50
MAX_URL_LENGTH = 2_048
MAX_VISIBLE_TEXT_CHARS = 20_000

# Filename character classes as code point ranges, so this file contains no invisible characters itself.
# They must match NAME_FLAG_RANGES in addon/Code.js; a test compares the two.
NAME_FLAG_RANGES: dict[str, tuple[tuple[int, int], ...]] = {
    "BIDI_CONTROL": ((0x202A, 0x202E), (0x2066, 0x2069)),
    "ZERO_WIDTH": ((0x200B, 0x200D), (0x2060, 0x2060), (0xFEFF, 0xFEFF)),
    "CONTROL_CHAR": ((0x0000, 0x001F), (0x007F, 0x009F)),
}
_NAME_FLAG_PATTERNS = {
    flag: re.compile("[" + "".join(f"{re.escape(chr(first))}-{re.escape(chr(last))}" for first, last in ranges) + "]")
    for flag, ranges in NAME_FLAG_RANGES.items()
}
KNOWN_NAME_FLAGS = frozenset({*NAME_FLAG_RANGES, "MULTIPLE_DOTS"})
ATTACHMENT_REASONS = frozenset(
    {
        "collection_error",
        "unexpected_error",
        "count_limit",
        "time_limit",
        "names_not_read",
        "extensions_limit",
        "field_limit",
        "field_unavailable",
    }
)
ATTACHMENT_FIELDS = frozenset({"filename", "content_type", "size_bytes"})


class ParseStatus(StrEnum):
    PRESENT = "PRESENT"
    MISSING = "MISSING"
    MALFORMED = "MALFORMED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class EvidenceSource(StrEnum):
    FROM = "from"
    REPLY_TO = "reply_to"
    TEXT_BODY = "text_body"
    HTML_BODY = "html_body"
    ATTACHMENTS = "attachments"


class AttachmentCollectionState(StrEnum):
    COLLECTED = "COLLECTED"
    NONE = "NONE"
    TRUNCATED = "TRUNCATED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ParseIssue:
    code: str
    source: EvidenceSource
    message: str


@dataclass(frozen=True)
class ParsedMailbox:
    source: EvidenceSource
    raw: str
    status: ParseStatus
    display_name: str = ""
    address: str = ""
    local_part: str = ""
    domain: str = ""
    domain_idna: str = ""
    domain_unicode: str = ""
    is_multiple: bool = False


@dataclass(frozen=True)
class ParsedUrl:
    source: EvidenceSource
    raw_url: str
    status: ParseStatus
    scheme: str = ""
    hostname: str = ""
    hostname_idna: str = ""
    hostname_unicode: str = ""
    port: int | None = None
    path: str = ""
    has_query: bool = False
    has_fragment: bool = False
    redacted_url: str = ""
    canonical_url: str = ""


@dataclass(frozen=True)
class ParsedHtmlLink:
    href: ParsedUrl
    visible_text: str


@dataclass(frozen=True)
class ParsedAttachment:
    """Untrusted attachment metadata. Nothing here was opened, downloaded or executed."""

    # One segment for an intact name; head and tail for a clipped one. The segments were not adjacent in
    # the original name and must never be joined as if they were.
    name_segments: tuple[str, ...]
    content_type: str
    size_bytes: int | None
    name_original_length: int | None = None
    removed_dot_count: int = 0
    removed_whitespace_only: bool = False
    # Character classes found in any part of the name, including a clipped-out middle.
    name_flags: frozenset[str] = frozenset()
    content_type_clipped: bool = False
    unavailable_fields: tuple[str, ...] = ()

    @property
    def name_clipped(self) -> bool:
        return len(self.name_segments) > 1

    @property
    def is_partial(self) -> bool:
        return self.name_clipped or self.content_type_clipped or bool(self.unavailable_fields)


@dataclass(frozen=True)
class AttachmentCoverage:
    # UNKNOWN means not collected (or not trustworthy), never that the message has no attachments.
    state: AttachmentCollectionState = AttachmentCollectionState.UNKNOWN
    declared_state: str | None = None
    regular_count: int | None = None
    listed_count: int = 0
    inline_count: int | None = None
    omitted_count: int = 0
    omitted_extensions: tuple[str, ...] = ()
    omitted_name_flags: frozenset[str] = frozenset()
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedEmail:
    subject: str
    text_body: str
    from_mailbox: ParsedMailbox
    reply_to_mailbox: ParsedMailbox
    text_urls: tuple[ParsedUrl, ...]
    html_links: tuple[ParsedHtmlLink, ...]
    html_visible_text: str
    issues: tuple[ParseIssue, ...] = field(default_factory=tuple)
    input_completeness: ParseStatus = ParseStatus.UNKNOWN
    attachments: tuple[ParsedAttachment, ...] = field(default_factory=tuple)
    attachment_coverage: AttachmentCoverage = field(default_factory=AttachmentCoverage)


_TEXT_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_TRAILING_URL_CHARS = ".,;:!?)]]}"


def parse_email_payload(payload: EmailPayload) -> ParsedEmail:
    """Build a backend-internal canonical representation from validated input."""
    issues: list[ParseIssue] = []
    from_mailbox = parse_mailbox(payload.from_address, EvidenceSource.FROM, issues)
    reply_to_mailbox = parse_mailbox(payload.reply_to, EvidenceSource.REPLY_TO, issues)

    html_parser = _InertHtmlParser()
    html_parser.feed(payload.html_body)
    html_parser.close()

    text_urls = _extract_text_urls(payload.text_body, issues)
    html_links = _extract_html_links(html_parser.links, issues)

    html_visible_text = _collapse_space(" ".join(html_parser.visible_text_parts))
    if len(html_visible_text) > MAX_VISIBLE_TEXT_CHARS:
        html_visible_text = html_visible_text[:MAX_VISIBLE_TEXT_CHARS]
        issues.append(
            ParseIssue(
                code="html_visible_text_truncated_by_parser",
                source=EvidenceSource.HTML_BODY,
                message="HTML visible text exceeded parser output bounds.",
            )
        )

    attachments = tuple(_parse_attachment(item, issues) for item in payload.attachment_metadata)
    attachment_coverage = _attachment_coverage(payload.attachment_collection, attachments, issues)

    return ParsedEmail(
        subject=payload.subject,
        text_body=payload.text_body,
        from_mailbox=from_mailbox,
        reply_to_mailbox=reply_to_mailbox,
        text_urls=tuple(text_urls),
        html_links=tuple(html_links),
        html_visible_text=html_visible_text,
        issues=tuple(issues),
        input_completeness=ParseStatus.UNKNOWN,
        attachments=attachments,
        attachment_coverage=attachment_coverage,
    )


def _parse_attachment(item: AttachmentMetadata, issues: list[ParseIssue]) -> ParsedAttachment:
    # Metadata only: names and types are untrusted strings and are kept as received.
    unavailable = [field_name for field_name in dict.fromkeys(item.unavailable_fields) if field_name in ATTACHMENT_FIELDS]
    clip = item.name_clip
    if clip is None:
        segments: tuple[str, ...] = (item.filename,)
    elif clip.at <= len(item.filename):
        segments = (item.filename[: clip.at], item.filename[clip.at :])
    else:
        # The clip position cannot be trusted, so neither can any split of the name.
        segments = ("",)
        if "filename" not in unavailable:
            unavailable.append("filename")
        _append_issue(
            issues,
            "attachment_name_clip_invalid",
            EvidenceSource.ATTACHMENTS,
            "An attachment name clip position was outside the received name.",
        )

    flags = {flag for flag, pattern in _NAME_FLAG_PATTERNS.items() if any(pattern.search(part) for part in segments)}
    if clip is not None:
        flags.update(flag for flag in clip.removed_flags if flag in KNOWN_NAME_FLAGS)
    return ParsedAttachment(
        name_segments=segments,
        content_type=item.content_type,
        size_bytes=item.size_bytes,
        name_original_length=clip.original_length if clip else None,
        removed_dot_count=clip.removed_dot_count if clip else 0,
        removed_whitespace_only=clip.removed_whitespace_only if clip else False,
        name_flags=frozenset(flags),
        content_type_clipped=item.content_type_clipped,
        unavailable_fields=tuple(unavailable),
    )


def _attachment_coverage(
    collection: AttachmentCollection | None,
    attachments: tuple[ParsedAttachment, ...],
    issues: list[ParseIssue],
) -> AttachmentCoverage:
    if collection is None:
        # V1 clients send no collection state: attachments were not collected, which is not an input problem.
        return AttachmentCoverage(listed_count=len(attachments))
    reasons = tuple(reason for reason in dict.fromkeys(collection.reasons) if reason in ATTACHMENT_REASONS)
    state = _consistent_attachment_state(collection, attachments, reasons)
    if state is None:
        _append_issue(
            issues,
            "attachment_collection_inconsistent",
            EvidenceSource.ATTACHMENTS,
            "Attachment collection state did not match the attachment list.",
        )
        state = AttachmentCollectionState.UNKNOWN
    return AttachmentCoverage(
        state=state,
        declared_state=collection.state,
        regular_count=collection.regular_count,
        listed_count=len(attachments),
        inline_count=collection.inline_count,
        omitted_count=collection.omitted_count,
        omitted_extensions=tuple(dict.fromkeys(ext.casefold() for ext in collection.omitted_extensions if ext)),
        omitted_name_flags=frozenset(flag for flag in collection.omitted_name_flags if flag in KNOWN_NAME_FLAGS),
        reasons=reasons,
    )


def _consistent_attachment_state(
    collection: AttachmentCollection,
    attachments: tuple[ParsedAttachment, ...],
    reasons: tuple[str, ...],
) -> AttachmentCollectionState | None:
    # A contradiction returns None rather than the more favourable reading.
    listed = len(attachments)
    partial = any(attachment.is_partial for attachment in attachments)
    accounted = collection.regular_count is not None and collection.regular_count == listed + collection.omitted_count
    if collection.state == AttachmentCollectionState.NONE:
        consistent = listed == 0 and collection.regular_count == 0 and collection.omitted_count == 0
    elif collection.state == AttachmentCollectionState.COLLECTED:
        consistent = listed > 0 and accounted and collection.omitted_count == 0 and not partial
    elif collection.state == AttachmentCollectionState.TRUNCATED:
        consistent = bool(reasons) and accounted and (collection.omitted_count > 0 or partial)
    elif collection.state == AttachmentCollectionState.UNAVAILABLE:
        consistent = listed == 0 and bool(reasons)
    else:
        consistent = False
    return AttachmentCollectionState(collection.state) if consistent else None


def parse_mailbox(raw_value: str, source: EvidenceSource, issues: list[ParseIssue] | None = None) -> ParsedMailbox:
    raw = raw_value.strip()
    if not raw:
        _append_issue(issues, "mailbox_missing", source, "Mailbox field is missing.")
        return ParsedMailbox(source=source, raw=raw_value, status=ParseStatus.MISSING)

    addresses = [(name.strip(), address.strip()) for name, address in getaddresses([raw]) if name.strip() or address.strip()]
    usable = [(name, address) for name, address in addresses if address]

    if len(usable) != 1:
        code = "mailbox_multiple" if len(usable) > 1 else "mailbox_malformed"
        _append_issue(issues, code, source, "Mailbox field did not contain exactly one usable address.")
        return ParsedMailbox(
            source=source,
            raw=raw_value,
            status=ParseStatus.MALFORMED,
            is_multiple=len(usable) > 1,
        )

    display_name, address = usable[0]
    normalized_address = address.strip().lower()
    local_part, domain = _split_email_address(normalized_address)
    if not local_part or not domain:
        _append_issue(issues, "mailbox_malformed", source, "Mailbox address is malformed.")
        return ParsedMailbox(source=source, raw=raw_value, status=ParseStatus.MALFORMED, display_name=display_name)

    domain_idna, domain_unicode, domain_ok = _normalize_hostname(domain)
    if not domain_ok:
        _append_issue(issues, "mailbox_domain_malformed", source, "Mailbox domain could not be normalized.")
        return ParsedMailbox(
            source=source,
            raw=raw_value,
            status=ParseStatus.MALFORMED,
            display_name=display_name,
            address=normalized_address,
            local_part=local_part,
            domain=domain,
        )

    return ParsedMailbox(
        source=source,
        raw=raw_value,
        status=ParseStatus.PRESENT,
        display_name=display_name,
        address=f"{local_part}@{domain_idna}",
        local_part=local_part,
        domain=domain_idna,
        domain_idna=domain_idna,
        domain_unicode=domain_unicode,
    )


def parse_url(raw_url: str, source: EvidenceSource, issues: list[ParseIssue] | None = None) -> ParsedUrl:
    raw = unescape(raw_url).strip()
    if len(raw) > MAX_URL_LENGTH:
        _append_issue(issues, "url_too_long", source, "URL exceeded parser length bound.")
        return ParsedUrl(
            source=source,
            raw_url=raw[:MAX_URL_LENGTH],
            status=ParseStatus.MALFORMED,
            redacted_url=raw[:MAX_URL_LENGTH],
        )

    try:
        parts = urlsplit(raw)
    except ValueError:
        _append_issue(issues, "url_malformed", source, "URL could not be parsed.")
        return ParsedUrl(source=source, raw_url=raw, status=ParseStatus.MALFORMED, redacted_url=raw)

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        _append_issue(issues, "url_unsupported_scheme", source, "URL scheme is not HTTP or HTTPS.")
        return ParsedUrl(source=source, raw_url=raw, status=ParseStatus.UNSUPPORTED, scheme=scheme, redacted_url=raw)

    if not parts.netloc or not parts.hostname:
        _append_issue(issues, "url_malformed", source, "HTTP(S) URL is missing a hostname.")
        return ParsedUrl(source=source, raw_url=raw, status=ParseStatus.MALFORMED, scheme=scheme, redacted_url=raw)

    try:
        port = parts.port
    except ValueError:
        _append_issue(issues, "url_malformed_port", source, "URL port is malformed.")
        return ParsedUrl(source=source, raw_url=raw, status=ParseStatus.MALFORMED, scheme=scheme, redacted_url=_redact_url(parts))

    hostname_idna, hostname_unicode, host_ok = _normalize_hostname(parts.hostname)
    if not host_ok:
        _append_issue(issues, "url_hostname_malformed", source, "URL hostname could not be normalized.")
        return ParsedUrl(source=source, raw_url=raw, status=ParseStatus.MALFORMED, scheme=scheme, redacted_url=_redact_url(parts))

    netloc = hostname_idna
    if port is not None:
        netloc = f"{netloc}:{port}"
    redacted_url = urlunsplit((scheme, netloc, parts.path or "", "", ""))
    canonical_url = urlunsplit((scheme, netloc, parts.path or "", parts.query or "", parts.fragment or ""))

    return ParsedUrl(
        source=source,
        raw_url=raw,
        status=ParseStatus.PRESENT,
        scheme=scheme,
        hostname=hostname_idna,
        hostname_idna=hostname_idna,
        hostname_unicode=hostname_unicode,
        port=port,
        path=parts.path or "",
        has_query=bool(parts.query),
        has_fragment=bool(parts.fragment),
        redacted_url=redacted_url,
        canonical_url=canonical_url,
    )


class _InertHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible_text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._skip_depth = 0
        self._active_href: str | None = None
        self._active_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style"}:
            self._skip_depth += 1
            return
        if tag == "a":
            attr_map = {name.lower(): value or "" for name, value in attrs}
            self._active_href = attr_map.get("href", "")
            self._active_text = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style"} and self._skip_depth:
            self._skip_depth -= 1
            return
        if tag == "a" and self._active_href is not None:
            self.links.append((self._active_href, _collapse_space(" ".join(self._active_text))))
            self._active_href = None
            self._active_text = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._active_href is not None:
            self._active_text.append(data)
        self.visible_text_parts.append(data)

    def close(self) -> None:
        if self._active_href is not None:
            self.links.append((self._active_href, _collapse_space(" ".join(self._active_text))))
            self._active_href = None
            self._active_text = []
        super().close()


def _extract_text_urls(text: str, issues: list[ParseIssue]) -> list[ParsedUrl]:
    parsed: list[ParsedUrl] = []
    urls_seen: set[tuple[str, str]] = set()
    for match in _TEXT_URL_RE.finditer(text):
        if len(parsed) >= MAX_URLS:
            issues.append(
                ParseIssue(
                    code="url_count_limit_reached",
                    source=EvidenceSource.TEXT_BODY,
                    message="Plain-text URL count exceeded parser bound.",
                )
            )
            break
        raw = match.group(0).rstrip(_TRAILING_URL_CHARS)
        parsed_url = parse_url(raw, EvidenceSource.TEXT_BODY, issues)
        if _is_duplicate(parsed_url, urls_seen, issues):
            continue
        parsed.append(parsed_url)
    return parsed


def _extract_html_links(
    raw_links: list[tuple[str, str]],
    issues: list[ParseIssue],
) -> list[ParsedHtmlLink]:
    parsed: list[ParsedHtmlLink] = []
    # Anchors are deduplicated only against other anchors, and only when both the destination and the
    # visible text match, so a URL repeated in the plain-text body cannot discard anchor evidence.
    links_seen: set[tuple[str, str]] = set()
    for href, visible_text in raw_links:
        if len(parsed) >= MAX_URLS:
            issues.append(
                ParseIssue(
                    code="url_count_limit_reached",
                    source=EvidenceSource.HTML_BODY,
                    message="HTML link count exceeded parser bound.",
                )
            )
            break
        parsed_url = parse_url(href, EvidenceSource.HTML_BODY, issues)
        if _is_duplicate(parsed_url, links_seen, issues, visible_text=visible_text):
            continue
        parsed.append(ParsedHtmlLink(href=parsed_url, visible_text=visible_text))
    return parsed


def _is_duplicate(
    parsed_url: ParsedUrl,
    urls_seen: set[tuple[str, str]],
    issues: list[ParseIssue],
    *,
    visible_text: str = "",
) -> bool:
    duplicate_key = (parsed_url.canonical_url or f"{parsed_url.status}:{parsed_url.raw_url}", visible_text)
    if duplicate_key in urls_seen:
        issues.append(
            ParseIssue(
                code="url_duplicate_omitted",
                source=parsed_url.source,
                message="Duplicate URL evidence was omitted after exact canonical matching.",
            )
        )
        return True
    urls_seen.add(duplicate_key)
    return False


def _split_email_address(address: str) -> tuple[str, str]:
    if address.count("@") != 1 or any(char.isspace() for char in address):
        return "", ""
    local_part, domain = address.rsplit("@", 1)
    if not local_part or not domain or "." not in domain:
        return "", ""
    return local_part, domain


def _normalize_hostname(hostname: str) -> tuple[str, str, bool]:
    host = hostname.strip().rstrip(".").lower()
    if not host or any(char.isspace() for char in host):
        return "", "", False
    try:
        idna = host.encode("idna").decode("ascii").lower()
        unicode_host = idna.encode("ascii").decode("idna").lower()
    except UnicodeError:
        return "", "", False
    return idna, unicode_host, True


def _redact_url(parts) -> str:
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    return urlunsplit((scheme, netloc, parts.path or "", "", ""))


def _collapse_space(value: str) -> str:
    return " ".join(value.split())


def _append_issue(
    issues: list[ParseIssue] | None,
    code: str,
    source: EvidenceSource,
    message: str,
) -> None:
    if issues is not None:
        issues.append(ParseIssue(code=code, source=source, message=message))
