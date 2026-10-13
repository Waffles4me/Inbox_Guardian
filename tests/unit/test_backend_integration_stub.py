import pytest
from fastapi.testclient import TestClient

from backend.app import main
from backend.app.detectors.credentials import detect_credential_phishing_context
from backend.app.engine import DetectorRunner
from backend.app.main import API_TOKEN_ENV, app


client = TestClient(app)
AUTH_HEADERS = {"X-InboxGuardian-Token": "test-token"}


def analyze_payload(**email_overrides: object) -> dict[str, object]:
    email = {
        "subject": "Synthetic setup check",
        "from": "Demo <demo@example.test>",
        "reply_to": "",
        "text_body": "This is a normal project update.",
        "html_body": "",
        "headers": {},
        "attachment_metadata": [],
    }
    email.update(email_overrides)
    return {"schema_version": "1.0", "email": email}


def post_analyze(monkeypatch: pytest.MonkeyPatch, **email_overrides: object):
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")
    return client.post(
        "/analyze",
        json=analyze_payload(**email_overrides),
        headers=AUTH_HEADERS,
    )


def response_text(body: dict[str, object]) -> str:
    return str(body)


def contribution_total(body: dict[str, object]) -> int:
    return sum(finding["contribution"] for finding in body["findings"])


def contribution_by_id(body: dict[str, object]) -> dict[str, int]:
    return {finding["id"]: finding["contribution"] for finding in body["findings"]}


def finding_ids(body: dict[str, object]) -> set[str]:
    return {finding["id"] for finding in body["findings"]}


def test_health_endpoint_remains_functional() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_accepts_valid_authentication_and_returns_real_assessment(monkeypatch) -> None:
    response = post_analyze(monkeypatch)

    body = response.json()
    assert response.status_code == 200
    assert body["schema_version"] == "1.0"
    assert body["score_type"] == "heuristic_risk_index_not_probability"
    assert body["verdict"] == "NO_SIGNIFICANT_SIGNALS"
    assert body["detector_version"] == "engine-0.1.0+scoring-0.1.0"
    assert "DEMO / NOT ANALYZED" not in response_text(body)


def test_analyze_rejects_missing_authentication(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")

    response = client.post("/analyze", json=analyze_payload())

    assert response.status_code == 401


def test_analyze_rejects_wrong_authentication(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")

    response = client.post(
        "/analyze",
        json=analyze_payload(),
        headers={"X-InboxGuardian-Token": "wrong-token"},
    )

    assert response.status_code == 401


def test_analyze_reports_unconfigured_authentication(monkeypatch) -> None:
    monkeypatch.delenv(API_TOKEN_ENV, raising=False)

    response = client.post(
        "/analyze",
        json=analyze_payload(),
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_analyze_rejects_malformed_requests(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")

    response = client.post(
        "/analyze",
        json={"schema_version": "1.0"},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 422


def test_analyze_enforces_bounded_body_size(monkeypatch) -> None:
    response = post_analyze(monkeypatch, text_body="x" * 50_001)

    assert response.status_code == 422


def test_legitimate_synthetic_email_is_not_marked_suspicious(monkeypatch) -> None:
    response = post_analyze(
        monkeypatch,
        subject="Project lunch",
        **{"from": "Team <team@example.test>"},
        text_body="Lunch is at noon in the usual room.",
        html_body="<p>Lunch is at noon in the usual room.</p>",
    )

    body = response.json()
    assert body["verdict"] == "NO_SIGNIFICANT_SIGNALS"
    assert body["risk_score"] == 0
    assert body["findings"] == []
    assert "does not guarantee" in body["recommended_action"]


def test_sender_only_indicator_returns_evidence_backed_assessment(monkeypatch) -> None:
    response = post_analyze(
        monkeypatch,
        **{"from": "accounts.example.test <notice@sender.test>"},
        text_body="Routine account notification.",
    )

    body = response.json()
    assert body["verdict"] == "SUSPICIOUS"
    assert body["risk_score"] == 20
    assert finding_ids(body) == {"sender_display_domain_mismatch"}
    assert "sender display name" in body["findings"][0]["observation"]


def test_deceptive_link_returns_url_finding(monkeypatch) -> None:
    response = post_analyze(
        monkeypatch,
        html_body='<a href="https://login.attacker.test/form">https://accounts.example.test/login</a>',
    )

    body = response.json()
    assert body["verdict"] == "SUSPICIOUS"
    assert body["risk_score"] == 30
    assert "url_display_destination_mismatch" in finding_ids(body)
    assert "avoid clicking email links" in body["recommended_action"]


def test_credential_collection_request_returns_credential_finding(monkeypatch) -> None:
    response = post_analyze(
        monkeypatch,
        text_body="Please submit your password to continue.",
    )

    body = response.json()
    assert body["verdict"] == "SUSPICIOUS"
    assert body["risk_score"] == 20
    assert "credential_secret_collection_request" in finding_ids(body)
    assert "do not submit passwords" in body["recommended_action"]


def test_multi_signal_scenario_can_return_high_risk(monkeypatch) -> None:
    response = post_analyze(
        monkeypatch,
        subject="Urgent account verification",
        **{"from": "accounts.example.test <notice@attacker.test>"},
        text_body="Urgent: enter your password within 12 hours to avoid account suspension.",
        html_body='<a href="https://login.attacker.test/form">https://accounts.example.test/login</a>',
    )

    body = response.json()
    assert body["verdict"] == "HIGH_RISK"
    assert body["risk_score"] == 75
    assert {"sender_display_domain_mismatch", "url_display_destination_mismatch"} <= finding_ids(body)
    assert "credential_secret_collection_request" in finding_ids(body)
    assert contribution_by_id(body) == {
        "sender_display_domain_mismatch": 20,
        "url_display_destination_mismatch": 30,
        "credential_secret_collection_request": 20,
        "credential_urgent_account_threat": 5,
        "credential_request_with_link": 0,
    }
    assert contribution_total(body) == 75


def test_insufficient_information_uses_placeholder_score(monkeypatch) -> None:
    response = post_analyze(monkeypatch, subject="", **{"from": ""}, text_body="", html_body="")

    body = response.json()
    assert body["verdict"] == "INCOMPLETE"
    assert body["risk_score"] == 0
    assert body["findings"] == []
    assert "placeholder" in body["limitations"][0]
    assert "could not assess" in body["recommended_action"]


def test_incomplete_preserves_positive_warning_contributions(monkeypatch) -> None:
    def fail_detector(_parsed_email):
        raise RuntimeError("synthetic sender failure")

    monkeypatch.setattr(
        "backend.app.engine.IMPLEMENTED_DETECTORS",
        (
            DetectorRunner("sender_identity", fail_detector),
            DetectorRunner("credential_context", detect_credential_phishing_context),
        ),
    )

    response = post_analyze(
        monkeypatch,
        text_body="Please submit your password to continue.",
    )

    body = response.json()
    assert body["verdict"] == "INCOMPLETE"
    assert body["risk_score"] == 0
    assert contribution_by_id(body) == {"credential_secret_collection_request": 20}
    assert "placeholder" in body["limitations"][0]
    assert "No meaningful risk score was produced" in body["limitations"][0]


def test_returned_contributions_reconcile_with_risk_score(monkeypatch) -> None:
    response = post_analyze(
        monkeypatch,
        text_body="Open https://192.0.2.10/login and submit your password.",
    )

    body = response.json()
    assert body["verdict"] == "SUSPICIOUS"
    assert contribution_total(body) == body["risk_score"]
    assert body["risk_score"] == 25


def test_findings_correspond_to_observed_email_evidence(monkeypatch) -> None:
    response = post_analyze(
        monkeypatch,
        html_body='<a href="https://evil.test/form">https://service.example.test/login</a>',
    )

    body = response.json()
    observations = " ".join(finding["observation"] for finding in body["findings"])
    assert "service.example.test" in observations
    assert "evil.test" in observations
    assert "password" not in observations.lower()


def test_planned_detectors_are_limitations_not_completed_checks(monkeypatch) -> None:
    response = post_analyze(monkeypatch)

    limitations = " ".join(response.json()["limitations"])
    assert "attachment_metadata is planned but not implemented" in limitations
    assert "financial_fraud is planned but not implemented" in limitations
    assert "nlp_phishing is planned but not implemented" in limitations


def test_unexpected_engine_failure_cannot_return_reassuring_result(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")

    def fail(_email):
        raise RuntimeError("synthetic private body should not leak")

    monkeypatch.setattr(main, "analyze_with_detectors", fail)

    response = client.post(
        "/analyze",
        json=analyze_payload(),
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 500
    assert "reliable assessment" in response.json()["detail"]
    assert "private body" not in response.text


def test_real_detector_failure_returns_incomplete_not_reassuring(monkeypatch) -> None:
    def fail_detector(_parsed_email):
        raise RuntimeError("synthetic message content omitted")

    monkeypatch.setattr(
        "backend.app.engine.IMPLEMENTED_DETECTORS",
        (DetectorRunner("sender_identity", fail_detector),),
    )

    response = post_analyze(monkeypatch)
    body = response.json()

    assert response.status_code == 200
    assert body["verdict"] == "INCOMPLETE"
    assert body["risk_score"] == 0
    assert "implemented detector did not run" in " ".join(body["limitations"])


def test_responses_are_deterministic(monkeypatch) -> None:
    first = post_analyze(monkeypatch, text_body="Please submit your password to continue.").json()
    second = post_analyze(monkeypatch, text_body="Please submit your password to continue.").json()

    assert first == second


def test_sensitive_strings_do_not_leak_to_results_or_logs(monkeypatch, capsys) -> None:
    response = post_analyze(
        monkeypatch,
        text_body=(
            "Please submit your password and OTP 123456 at "
            "http://localhost/login?token=secret-value#fragment"
        ),
    )

    body = response.json()
    combined = response_text(body)
    captured = capsys.readouterr()
    assert "123456" not in combined
    assert "token=secret-value" not in combined
    assert "#fragment" not in combined
    assert "secret-value" not in captured.out + captured.err
