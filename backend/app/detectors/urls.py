from __future__ import annotations

from ipaddress import ip_address
import re
from urllib.parse import urlsplit

from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.parsing import EvidenceSource, ParsedEmail, ParsedHtmlLink, ParsedUrl, ParseStatus, parse_url


DETECTOR_ID = "url_deception"
IMPLEMENTATION_VERSION = "urls-0.1.0"

_VISIBLE_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_HOSTLIKE_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$", re.IGNORECASE)
_TRAILING_URL_CHARS = ".,;:!?)]]}"


def detect_deceptive_urls(parsed_email: ParsedEmail) -> DetectorResult:
    findings: list[DetectorFinding] = []
    limitations = [
        "URL checks inspect structure only; they do not fetch links, expand redirects, resolve DNS, or use reputation data.",
        "Legitimate marketing, tracking, support and outsourced authentication links can use different domains.",
    ]

    present_urls = list(parsed_email.text_urls)
    present_urls.extend(link.href for link in parsed_email.html_links)
    link_evidence_count = len(present_urls)

    for link in parsed_email.html_links:
        findings.extend(_find_html_link_issues(link))

    for url in present_urls:
        findings.extend(_find_url_structure_issues(url))

    deduped_findings = _dedupe_findings(findings)
    if deduped_findings:
        status = DetectorStatus.TRIGGERED
    elif _has_only_malformed_or_unsupported(present_urls):
        status = DetectorStatus.INCONCLUSIVE
        limitations = [
            "URL evidence was present but malformed or unsupported, so URL deception checks could not fully evaluate it.",
            *limitations,
        ]
    else:
        status = DetectorStatus.NOT_TRIGGERED
        limitations = [
            "No URL deception rule triggered; this is not a guarantee that the links are safe.",
            *limitations,
        ]
        if link_evidence_count == 0:
            limitations = [
                "No supported URL evidence was available in the parsed email.",
                *limitations,
            ]

    return DetectorResult(
        detector_id=DETECTOR_ID,
        status=status,
        findings=tuple(deduped_findings),
        evidence_sources=_evidence_sources(parsed_email),
        limitations=tuple(limitations),
        implementation_version=IMPLEMENTATION_VERSION,
    )


def _find_html_link_issues(link: ParsedHtmlLink) -> list[DetectorFinding]:
    findings: list[DetectorFinding] = []
    destination = link.href
    if destination.status != ParseStatus.PRESENT:
        return findings

    visible_url = _visible_url_from_text(link.visible_text)
    if not visible_url:
        return findings

    if visible_url.status != ParseStatus.PRESENT:
        return findings

    visible_host = visible_url.hostname_idna
    actual_host = destination.hostname_idna

    if _is_deceptive_prefix_host(visible_host, actual_host):
        findings.append(_deceptive_subdomain_finding(visible_host, destination))
    elif not _same_host_or_subdomain(visible_host, actual_host):
        findings.append(_display_destination_mismatch_finding(visible_host, destination))

    return findings


def _find_url_structure_issues(url: ParsedUrl) -> list[DetectorFinding]:
    if url.status != ParseStatus.PRESENT:
        return []

    findings: list[DetectorFinding] = []
    if _is_ip_host(url.hostname_idna):
        findings.append(_ip_host_finding(url))

    userinfo = _userinfo(url.raw_url)
    if userinfo and _looks_like_hostname(userinfo):
        findings.append(_userinfo_finding(userinfo, url))

    return findings


def _display_destination_mismatch_finding(visible_host: str, destination: ParsedUrl) -> DetectorFinding:
    return DetectorFinding(
        id="url_display_destination_mismatch",
        severity="medium",
        title="Displayed URL host differs from link destination",
        observation=(
            f"The link text shows {visible_host}, but the actual destination host is "
            f"{destination.hostname_idna}."
        ),
        interpretation=(
            "A displayed URL that points to a different host can mislead users. This can also occur with "
            "legitimate tracking or outsourced login infrastructure, so context matters."
        ),
        evidence_id=f"url.display_mismatch:{visible_host}->{destination.hostname_idna}",
        evidence_sources=(EvidenceSource.HTML_BODY.value,),
        contribution=0,
    )


def _deceptive_subdomain_finding(visible_host: str, destination: ParsedUrl) -> DetectorFinding:
    return DetectorFinding(
        id="url_deceptive_subdomain",
        severity="medium",
        title="Destination host embeds the displayed host as a prefix",
        observation=(
            f"The link text shows {visible_host}, but the actual destination host is "
            f"{destination.hostname_idna}."
        ),
        interpretation=(
            "The destination starts with the displayed host but continues into another domain. This structure "
            "can be used to make the true registered destination harder to notice."
        ),
        evidence_id=f"url.deceptive_subdomain:{visible_host}->{destination.hostname_idna}",
        evidence_sources=(EvidenceSource.HTML_BODY.value,),
        contribution=0,
    )


def _ip_host_finding(url: ParsedUrl) -> DetectorFinding:
    return DetectorFinding(
        id="url_ip_address_host",
        severity="low",
        title="URL uses an IP address as the host",
        observation=f"A URL destination uses the literal IP address {url.hostname_idna}.",
        interpretation=(
            "Links to IP addresses can hide the organization operating the destination. They can also be "
            "legitimate in technical notifications or internal tooling."
        ),
        evidence_id=f"url.ip_host:{url.hostname_idna}",
        evidence_sources=(url.source.value,),
        contribution=0,
    )


def _userinfo_finding(userinfo: str, url: ParsedUrl) -> DetectorFinding:
    return DetectorFinding(
        id="url_userinfo_hostname",
        severity="medium",
        title="URL userinfo resembles a hostname",
        observation=(
            f"The URL includes userinfo that looks like {userinfo}, while the actual destination host is "
            f"{url.hostname_idna}."
        ),
        interpretation=(
            "Text before '@' in a URL is not the destination host. Hostname-like userinfo can mislead users "
            "about where the link actually goes."
        ),
        evidence_id=f"url.userinfo:{userinfo}->{url.hostname_idna}",
        evidence_sources=(url.source.value,),
        contribution=0,
    )


def _visible_url_from_text(text: str) -> ParsedUrl | None:
    match = _VISIBLE_URL_RE.search(text)
    if not match:
        return None
    raw = match.group(0).rstrip(_TRAILING_URL_CHARS)
    return parse_url(raw, EvidenceSource.HTML_BODY)


def _is_deceptive_prefix_host(visible_host: str, actual_host: str) -> bool:
    return bool(
        visible_host
        and actual_host
        and actual_host.startswith(f"{visible_host}.")
        and not _same_host_or_subdomain(visible_host, actual_host)
    )


def _same_host_or_subdomain(parent_host: str, candidate_host: str) -> bool:
    if not parent_host or not candidate_host:
        return False
    parent = parent_host.strip().rstrip(".").lower()
    candidate = candidate_host.strip().rstrip(".").lower()
    return candidate == parent or candidate.endswith(f".{parent}")


def _is_ip_host(hostname: str) -> bool:
    try:
        ip_address(hostname)
    except ValueError:
        return False
    return True


def _userinfo(raw_url: str) -> str:
    try:
        parts = urlsplit(raw_url)
    except ValueError:
        return ""
    if "@" not in parts.netloc:
        return ""
    return parts.netloc.rsplit("@", 1)[0].split(":", 1)[0].lower()


def _looks_like_hostname(value: str) -> bool:
    return bool(_HOSTLIKE_RE.fullmatch(value.strip().rstrip(".").lower()))


def _has_only_malformed_or_unsupported(urls: list[ParsedUrl]) -> bool:
    return bool(urls) and all(url.status != ParseStatus.PRESENT for url in urls)


def _evidence_sources(parsed_email: ParsedEmail) -> tuple[str, ...]:
    sources: list[str] = []
    if parsed_email.text_urls:
        sources.append(EvidenceSource.TEXT_BODY.value)
    if parsed_email.html_links:
        sources.append(EvidenceSource.HTML_BODY.value)
    return tuple(sources)


def _dedupe_findings(findings: list[DetectorFinding]) -> list[DetectorFinding]:
    seen: set[str] = set()
    deduped: list[DetectorFinding] = []
    for finding in findings:
        if finding.evidence_id in seen:
            continue
        seen.add(finding.evidence_id)
        deduped.append(finding)
    return deduped
