"""Optional VirusTotal report enrichment.

This module is deliberately separate from deterministic detectors and scoring. It sends only normalized public
domains or public IP addresses to fixed VirusTotal v3 report endpoints, never URLs, paths, query strings, mailboxes,
message text, attachment metadata or files.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
import ipaddress
import json
import os
import socket
import ssl
import time
from urllib.parse import quote
import http.client

from backend.app.models import ReputationContext
from backend.app.parsing import ParsedEmail, ParsedUrl, ParseStatus


API_KEY_ENV = "VIRUSTOTAL_API_KEY"
FEATURE_FLAG_ENV = "INBOXGUARDIAN_VIRUSTOTAL_ENABLED"
VT_HOST = "www.virustotal.com"
MAX_INDICATORS = 5
MAX_RESPONSE_BYTES = 64_000
REQUEST_TIMEOUT_SECONDS = 2.0
CACHE_TTL_SECONDS = 15 * 60
MAX_CACHE_ENTRIES = 128
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_REQUESTS_PER_WINDOW = 4
STALE_REPORT_SECONDS = 90 * 24 * 60 * 60
USER_AGENT = "InboxGuardian-VirusTotal-Enrichment/0.1"
CAVEAT = "VirusTotal reputation is contextual and is not proof that the message is safe or malicious."
COMMON_SECOND_LEVEL_SUFFIXES = {
    "ac",
    "co",
    "com",
    "edu",
    "gov",
    "net",
    "org",
}

_CACHE: OrderedDict[tuple[str, str], tuple[float, ReputationContext]] = OrderedDict()
_REQUEST_TIMES: deque[float] = deque()


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str


def enrich_with_virustotal(parsed_email: ParsedEmail, *, opt_in: bool) -> tuple[ReputationContext, ...]:
    if not opt_in or not _feature_enabled():
        return ()
    api_key = os.environ.get(API_KEY_ENV, "").strip()
    if not api_key:
        return ()

    results: list[ReputationContext] = []
    for indicator in extract_public_indicators(parsed_email)[:MAX_INDICATORS]:
        results.append(_lookup_indicator(indicator, api_key))
    return tuple(results)


def extract_public_indicators(parsed_email: ParsedEmail) -> tuple[Indicator, ...]:
    indicators: list[Indicator] = []
    seen: set[tuple[str, str]] = set()
    for url in _iter_urls(parsed_email):
        indicator = _indicator_from_host(url.hostname_idna or url.hostname)
        if indicator is None:
            continue
        key = (indicator.kind, indicator.value)
        if key in seen:
            continue
        seen.add(key)
        indicators.append(indicator)
        if len(indicators) >= MAX_INDICATORS:
            break
    return tuple(indicators)


def _iter_urls(parsed_email: ParsedEmail) -> tuple[ParsedUrl, ...]:
    urls = list(parsed_email.text_urls)
    urls.extend(link.href for link in parsed_email.html_links)
    return tuple(url for url in urls if url.status == ParseStatus.PRESENT)


def _indicator_from_host(host: str) -> Indicator | None:
    normalized = host.strip().strip(".").lower()
    if not normalized or len(normalized) > 253:
        return None
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        domain = _normalize_domain(normalized)
        if domain is None:
            return None
        return Indicator("domain", domain)
    if not ip.is_global:
        return None
    return Indicator("ip_address", ip.compressed)


def _normalize_domain(host: str) -> str | None:
    if any(char in host for char in "/:@?#[]\\"):
        return None
    try:
        domain = host.encode("idna").decode("ascii").lower().strip(".")
    except UnicodeError:
        return None
    labels = domain.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return None
    if not all(_valid_domain_label(label) for label in labels):
        return None
    if labels[-1] in {"local", "localhost", "internal", "intranet", "test", "example", "invalid"}:
        return None
    return _base_public_domain(labels)


def _base_public_domain(labels: list[str]) -> str:
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in COMMON_SECOND_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _valid_domain_label(label: str) -> bool:
    return bool(label) and not label.startswith("-") and not label.endswith("-") and all(
        char.isalnum() or char == "-" for char in label
    )


def _lookup_indicator(indicator: Indicator, api_key: str) -> ReputationContext:
    key = (indicator.kind, indicator.value)
    now = _now()
    cached = _CACHE.get(key)
    if cached and now - cached[0] <= CACHE_TTL_SECONDS:
        _CACHE.move_to_end(key)
        return cached[1]

    if not _rate_limit_allows(now):
        return _unavailable(indicator, "VirusTotal lookup skipped by local rate limit.")

    try:
        payload, status = _fetch_report(indicator, api_key)
        result = _context_from_response(indicator, payload, status)
    except (OSError, TimeoutError, socket.timeout, ssl.SSLError, http.client.HTTPException, json.JSONDecodeError):
        result = _unavailable(indicator, "VirusTotal lookup failed without changing the email risk score.")

    _CACHE[key] = (now, result)
    _CACHE.move_to_end(key)
    while len(_CACHE) > MAX_CACHE_ENTRIES:
        _CACHE.popitem(last=False)
    return result


def _rate_limit_allows(now: float) -> bool:
    while _REQUEST_TIMES and now - _REQUEST_TIMES[0] > RATE_LIMIT_WINDOW_SECONDS:
        _REQUEST_TIMES.popleft()
    if len(_REQUEST_TIMES) >= MAX_REQUESTS_PER_WINDOW:
        return False
    _REQUEST_TIMES.append(now)
    return True


def _fetch_report(indicator: Indicator, api_key: str) -> tuple[dict[str, object], int]:
    path_kind = "domains" if indicator.kind == "domain" else "ip_addresses"
    path = f"/api/v3/{path_kind}/{quote(indicator.value, safe='')}"
    conn = http.client.HTTPSConnection(VT_HOST, 443, timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        conn.request(
            "GET",
            path,
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                "x-apikey": api_key,
            },
        )
        response = conn.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
    finally:
        conn.close()
    if len(body) > MAX_RESPONSE_BYTES:
        raise http.client.HTTPException("VirusTotal response exceeded size limit")
    if response.status in {401, 403, 404, 429} or 500 <= response.status <= 599:
        return {}, response.status
    if response.status != 200:
        return {}, response.status
    return json.loads(body.decode("utf-8")), response.status


def _context_from_response(indicator: Indicator, payload: dict[str, object], status_code: int) -> ReputationContext:
    if status_code in {401, 403}:
        return _unavailable(indicator, "VirusTotal authentication or permission failed.")
    if status_code == 429:
        return _unavailable(indicator, "VirusTotal quota was exhausted or rate limited.")
    if status_code == 404:
        return _unknown(indicator, "VirusTotal has no report for this public indicator.")
    if status_code != 200:
        return _unavailable(indicator, "VirusTotal report was unavailable.")

    attributes = payload.get("data", {})
    if isinstance(attributes, dict):
        attributes = attributes.get("attributes", {})
    if not isinstance(attributes, dict):
        return _unknown(indicator, "VirusTotal report did not include usable reputation statistics.")
    stats = attributes.get("last_analysis_stats", {})
    if not isinstance(stats, dict):
        return _unknown(indicator, "VirusTotal report did not include analysis statistics.")
    malicious = _safe_count(stats.get("malicious"))
    suspicious = _safe_count(stats.get("suspicious"))
    harmless = _safe_count(stats.get("harmless"))
    undetected = _safe_count(stats.get("undetected"))
    if malicious is None and suspicious is None:
        return _unknown(indicator, "VirusTotal report did not include usable malicious or suspicious counts.")
    malicious_count = malicious or 0
    suspicious_count = suspicious or 0
    stale_suffix = _stale_suffix(attributes.get("last_analysis_date"))
    if malicious_count + suspicious_count > 0:
        summary = (
            f"VirusTotal reports {malicious_count} malicious and {suspicious_count} suspicious engine results "
            f"for this public indicator.{stale_suffix}"
        )
        status = "SUSPICIOUS"
    else:
        summary = (
            "VirusTotal reports no malicious or suspicious engine results for this public indicator."
            f"{stale_suffix}"
        )
        status = "UNKNOWN"
    return ReputationContext(
        provider="virustotal",
        indicator_type=indicator.kind,  # type: ignore[arg-type]
        indicator=indicator.value,
        status=status,  # type: ignore[arg-type]
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        summary=summary,
        caveat=CAVEAT,
    )


def _safe_count(value: object) -> int | None:
    if isinstance(value, int) and value >= 0:
        return value
    return None


def _stale_suffix(value: object) -> str:
    if not isinstance(value, int) or value <= 0:
        return ""
    age_seconds = max(0, int(time.time()) - value)
    if age_seconds <= STALE_REPORT_SECONDS:
        return ""
    return " The report timestamp is older than 90 days, so treat this context as stale."


def _unknown(indicator: Indicator, summary: str) -> ReputationContext:
    return ReputationContext(
        provider="virustotal",
        indicator_type=indicator.kind,  # type: ignore[arg-type]
        indicator=indicator.value,
        status="UNKNOWN",
        summary=summary,
        caveat=CAVEAT,
    )


def _unavailable(indicator: Indicator, summary: str) -> ReputationContext:
    return ReputationContext(
        provider="virustotal",
        indicator_type=indicator.kind,  # type: ignore[arg-type]
        indicator=indicator.value,
        status="UNAVAILABLE",
        summary=summary,
        caveat=CAVEAT,
    )


def _feature_enabled() -> bool:
    return os.environ.get(FEATURE_FLAG_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _now() -> float:
    return time.monotonic()


def reset_virustotal_state_for_tests() -> None:
    _CACHE.clear()
    _REQUEST_TIMES.clear()
