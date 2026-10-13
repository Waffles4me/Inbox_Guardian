from __future__ import annotations

from dataclasses import dataclass, field
from email.utils import getaddresses
from enum import StrEnum
from html import unescape
from html.parser import HTMLParser
import re
from urllib.parse import urlsplit, urlunsplit

from .models import EmailPayload


MAX_URLS = 50
MAX_URL_LENGTH = 2_048
MAX_VISIBLE_TEXT_CHARS = 20_000


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
class ParsedEmail:
    subject: str
    from_mailbox: ParsedMailbox
    reply_to_mailbox: ParsedMailbox
    text_urls: tuple[ParsedUrl, ...]
    html_links: tuple[ParsedHtmlLink, ...]
    html_visible_text: str
    issues: tuple[ParseIssue, ...] = field(default_factory=tuple)
    input_completeness: ParseStatus = ParseStatus.UNKNOWN


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

    urls_seen: set[str] = set()
    text_urls = _extract_text_urls(payload.text_body, urls_seen, issues)
    html_links = _extract_html_links(html_parser.links, urls_seen, issues)

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

    return ParsedEmail(
        subject=payload.subject,
        from_mailbox=from_mailbox,
        reply_to_mailbox=reply_to_mailbox,
        text_urls=tuple(text_urls),
        html_links=tuple(html_links),
        html_visible_text=html_visible_text,
        issues=tuple(issues),
        input_completeness=ParseStatus.UNKNOWN,
    )


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


def _extract_text_urls(text: str, urls_seen: set[str], issues: list[ParseIssue]) -> list[ParsedUrl]:
    parsed: list[ParsedUrl] = []
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
    urls_seen: set[str],
    issues: list[ParseIssue],
) -> list[ParsedHtmlLink]:
    parsed: list[ParsedHtmlLink] = []
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
        if _is_duplicate(parsed_url, urls_seen, issues):
            continue
        parsed.append(ParsedHtmlLink(href=parsed_url, visible_text=visible_text))
    return parsed


def _is_duplicate(parsed_url: ParsedUrl, urls_seen: set[str], issues: list[ParseIssue]) -> bool:
    duplicate_key = parsed_url.canonical_url or f"{parsed_url.status}:{parsed_url.raw_url}"
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
