import json
import socket

import pytest
from fastapi.testclient import TestClient

from backend.app import reputation
from backend.app.main import API_TOKEN_ENV, app
from backend.app.models import EmailPayload
from backend.app.parsing import parse_email_payload
from tests.evaluation.run_evaluation import evaluate_case


client = TestClient(app)
AUTH_HEADERS = {"X-InboxGuardian-Token": "test-token"}


@pytest.fixture(autouse=True)
def clean_reputation_state(monkeypatch):
    reputation.reset_virustotal_state_for_tests()
    monkeypatch.delenv(reputation.FEATURE_FLAG_ENV, raising=False)
    monkeypatch.delenv(reputation.API_KEY_ENV, raising=False)
    yield
    reputation.reset_virustotal_state_for_tests()


def payload(**email_overrides: object) -> dict[str, object]:
    email = {
        "subject": "Synthetic reputation test",
        "from": "Demo <demo@example.test>",
        "reply_to": "",
        "text_body": "Please review https://example.org/path?token=private",
        "html_body": "",
        "headers": {},
        "attachment_metadata": [],
        "attachment_collection": {"state": "NONE", "regular_count": 0},
    }
    email.update(email_overrides)
    return {"schema_version": "1.0", "email": email}


def post_analyze(monkeypatch, body: dict[str, object] | None = None):
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")
    return client.post("/analyze", json=body or payload(), headers=AUTH_HEADERS)


def enable_virustotal(monkeypatch) -> None:
    monkeypatch.setenv(reputation.FEATURE_FLAG_ENV, "true")
    monkeypatch.setenv(reputation.API_KEY_ENV, "synthetic-key")


def fake_report(malicious: int = 0, suspicious: int = 0, harmless: int = 3, last_analysis_date: int | None = None):
    attributes = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": 90,
        }
    }
    if last_analysis_date is not None:
        attributes["last_analysis_date"] = last_analysis_date
    return {
        "data": {
            "attributes": attributes
        }
    }, 200


def test_feature_disabled_makes_no_external_call(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setenv(reputation.API_KEY_ENV, "synthetic-key")
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append(indicator.value))

    result = reputation.enrich_with_virustotal(parse_email_payload(EmailPayload.model_validate(payload()["email"])), opt_in=True)

    assert result == ()
    assert calls == []


def test_no_api_key_makes_no_external_call(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setenv(reputation.FEATURE_FLAG_ENV, "true")
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append(indicator.value))

    result = reputation.enrich_with_virustotal(parse_email_payload(EmailPayload.model_validate(payload()["email"])), opt_in=True)

    assert result == ()
    assert calls == []


def test_no_request_opt_in_makes_no_external_call(monkeypatch) -> None:
    calls: list[str] = []
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append(indicator.value))

    result = reputation.enrich_with_virustotal(parse_email_payload(EmailPayload.model_validate(payload()["email"])), opt_in=False)

    assert result == ()
    assert calls == []


def test_deployed_addon_request_shape_remains_no_consent(monkeypatch) -> None:
    calls: list[str] = []
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append(indicator.value) or fake_report())

    result = post_analyze(monkeypatch, payload()).json()

    assert result["schema_version"] == "1.0"
    assert result["reputation_context"] == []
    assert result["risk_score"] == 0
    assert result["verdict"] == "NO_SIGNIFICANT_SIGNALS"
    assert calls == []


def test_public_domain_report_is_returned_separately_without_score_change(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []
    enable_virustotal(monkeypatch)

    def fake_fetch(indicator, api_key):
        calls.append((indicator.kind, indicator.value))
        return fake_report(malicious=2, suspicious=1)

    monkeypatch.setattr(reputation, "_fetch_report", fake_fetch)

    base = post_analyze(monkeypatch).json()
    enriched = post_analyze(monkeypatch, {**payload(), "enrichments": {"virustotal": True}}).json()

    assert calls == [("domain", "example.org")]
    assert (enriched["risk_score"], enriched["verdict"], enriched["findings"]) == (
        base["risk_score"],
        base["verdict"],
        base["findings"],
    )
    assert enriched["reputation_context"][0]["status"] == "SUSPICIOUS"
    assert enriched["reputation_context"][0]["malicious"] == 2
    assert "VirusTotal" in enriched["reputation_context"][0]["caveat"]


def test_public_ip_report_is_returned(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append((indicator.kind, indicator.value)) or fake_report())

    body = {**payload(text_body="Visit https://8.8.8.8/login"), "enrichments": {"virustotal": True}}
    result = post_analyze(monkeypatch, body).json()

    assert calls == [("ip_address", "8.8.8.8")]
    assert result["reputation_context"][0]["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "url",
    [
        "https://10.0.0.1/login",
        "https://127.0.0.1/login",
        "https://192.0.2.10/login",
        "https://server.local/login",
        "https://portal.internal/login",
        "https://anything.test/login",
        "https://localhost/login",
    ],
)
def test_private_reserved_and_internal_destinations_are_not_sent(monkeypatch, url: str) -> None:
    calls: list[str] = []
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append(indicator.value))

    body = {**payload(text_body=f"Visit {url}"), "enrichments": {"virustotal": True}}
    result = post_analyze(monkeypatch, body).json()

    assert result["reputation_context"] == []
    assert calls == []


def test_idn_domain_is_sent_as_punycode(monkeypatch) -> None:
    calls: list[str] = []
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append(indicator.value) or fake_report())

    body = {**payload(text_body="Visit https://bücher.de/path"), "enrichments": {"virustotal": True}}
    post_analyze(monkeypatch, body)

    assert calls == ["xn--bcher-kva.de"]


def test_query_strings_paths_and_duplicates_are_not_sent(monkeypatch) -> None:
    calls: list[str] = []
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append(indicator.value) or fake_report())

    body = {
        **payload(
            text_body="Visit https://example.org/path?token=secret",
            html_body='<a href="https://example.org/other?auth=secret">Example</a>',
        ),
        "enrichments": {"virustotal": True},
    }
    result = post_analyze(monkeypatch, body).json()

    assert calls == ["example.org"]
    assert "token" not in json.dumps(result["reputation_context"])
    assert "path" not in json.dumps(result["reputation_context"])


def test_confidential_subdomain_labels_are_not_sent(monkeypatch) -> None:
    calls: list[str] = []
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append(indicator.value) or fake_report())

    body = {
        **payload(text_body="Visit https://tenant-payroll-reset.customer.example.org/private?token=secret"),
        "enrichments": {"virustotal": True},
    }
    result = post_analyze(monkeypatch, body).json()

    assert calls == ["example.org"]
    rendered = json.dumps(result["reputation_context"])
    assert "tenant" not in rendered
    assert "payroll" not in rendered
    assert "customer" not in rendered
    assert "private" not in rendered
    assert "secret" not in rendered


def test_common_country_second_level_suffix_keeps_registered_domain(monkeypatch) -> None:
    calls: list[str] = []
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append(indicator.value) or fake_report())

    body = {
        **payload(text_body="Visit https://internal.vendor.example.co.uk/path"),
        "enrichments": {"virustotal": True},
    }
    post_analyze(monkeypatch, body)

    assert calls == ["example.co.uk"]


def test_http_429_and_quota_exhaustion_are_safe(monkeypatch) -> None:
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: ({}, 429))

    result = post_analyze(monkeypatch, {**payload(), "enrichments": {"virustotal": True}}).json()

    assert result["reputation_context"][0]["status"] == "UNAVAILABLE"
    assert "quota" in result["reputation_context"][0]["summary"].lower()


@pytest.mark.parametrize("status_code", [401, 403, 500, 503])
def test_auth_and_server_errors_are_unavailable(monkeypatch, status_code: int) -> None:
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: ({}, status_code))

    result = post_analyze(monkeypatch, {**payload(), "enrichments": {"virustotal": True}}).json()

    assert result["reputation_context"][0]["status"] == "UNAVAILABLE"
    assert result["risk_score"] == 0
    assert result["verdict"] == "NO_SIGNIFICANT_SIGNALS"


def test_local_rate_limit_does_not_multiply_requests(monkeypatch) -> None:
    calls: list[str] = []
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: calls.append(indicator.value) or fake_report())
    text = " ".join(f"https://example{index}.org/" for index in range(5))

    result = post_analyze(monkeypatch, {**payload(text_body=text), "enrichments": {"virustotal": True}}).json()

    assert len(calls) == reputation.MAX_REQUESTS_PER_WINDOW
    assert result["reputation_context"][-1]["status"] == "UNAVAILABLE"
    assert "rate limit" in result["reputation_context"][-1]["summary"].lower()


@pytest.mark.parametrize(
    "exception",
    [
        socket.timeout("synthetic timeout"),
        json.JSONDecodeError("bad json", "not-json", 0),
    ],
)
def test_timeout_and_malformed_json_are_safe(monkeypatch, exception: Exception) -> None:
    enable_virustotal(monkeypatch)

    def fake_fetch(indicator, api_key):
        raise exception

    monkeypatch.setattr(reputation, "_fetch_report", fake_fetch)

    result = post_analyze(monkeypatch, {**payload(), "enrichments": {"virustotal": True}}).json()

    assert result["reputation_context"][0]["status"] == "UNAVAILABLE"
    assert result["risk_score"] == 0
    assert result["verdict"] == "NO_SIGNIFICANT_SIGNALS"


def test_unavailable_report_is_unknown_not_clean(monkeypatch) -> None:
    enable_virustotal(monkeypatch)
    monkeypatch.setattr(reputation, "_fetch_report", lambda indicator, api_key: ({}, 404))

    result = post_analyze(monkeypatch, {**payload(), "enrichments": {"virustotal": True}}).json()

    assert result["reputation_context"][0]["status"] == "UNKNOWN"
    assert "no report" in result["reputation_context"][0]["summary"].lower()


def test_stale_zero_detection_report_remains_unknown(monkeypatch) -> None:
    enable_virustotal(monkeypatch)
    old_timestamp = 1_700_000_000
    monkeypatch.setattr(reputation.time, "time", lambda: old_timestamp + reputation.STALE_REPORT_SECONDS + 1)
    monkeypatch.setattr(
        reputation,
        "_fetch_report",
        lambda indicator, api_key: fake_report(last_analysis_date=old_timestamp),
    )

    result = post_analyze(monkeypatch, {**payload(), "enrichments": {"virustotal": True}}).json()

    assert result["reputation_context"][0]["status"] == "UNKNOWN"
    assert "stale" in result["reputation_context"][0]["summary"].lower()
    assert result["risk_score"] == 0
    assert result["verdict"] == "NO_SIGNIFICANT_SIGNALS"


def test_existing_evaluation_path_does_not_call_virustotal(monkeypatch) -> None:
    enable_virustotal(monkeypatch)

    def forbidden(*args, **kwargs):
        raise AssertionError("evaluation must not call VirusTotal")

    monkeypatch.setattr(reputation, "_fetch_report", forbidden)
    row = evaluate_case(
        {
            "id": "synthetic",
            "group": "ordinary_legitimate",
            "label": "BENIGN",
            "description": "Synthetic",
            "expected_behavior": "",
            "rationale": "",
            "families": [],
            "overlap": "",
            "email": payload()["email"],
        }
    )

    assert row["verdict"] == "NO_SIGNIFICANT_SIGNALS"
