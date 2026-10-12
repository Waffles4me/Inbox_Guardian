from fastapi.testclient import TestClient

from backend.app.main import API_TOKEN_ENV, app


client = TestClient(app)
AUTH_HEADERS = {"X-InboxGuardian-Token": "test-token"}


def analyze_payload(**email_overrides: object) -> dict[str, object]:
    email = {
        "subject": "Synthetic setup check",
        "from": "Demo <demo@example.test>",
        "reply_to": "",
        "text_body": "This is not a real analysis.",
        "html_body": "",
        "headers": {},
        "attachment_metadata": [],
    }
    email.update(email_overrides)
    return {"schema_version": "1.0", "email": email}


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint_returns_demo_not_analyzed_response(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")

    response = client.post(
        "/analyze",
        json=analyze_payload(),
        headers=AUTH_HEADERS,
    )

    body = response.json()
    assert response.status_code == 200
    assert body["verdict"] == "INCOMPLETE"
    assert body["risk_score"] == 0
    assert body["findings"][0]["title"] == "DEMO / NOT ANALYZED"
    assert "not implemented" in body["limitations"][0]
    assert "security assessment" in body["recommended_action"]


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


def test_analyze_rejects_invalid_input(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")

    response = client.post(
        "/analyze",
        json={"schema_version": "1.0"},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 422


def test_analyze_accepts_missing_email_fields_as_incomplete(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")

    response = client.post(
        "/analyze",
        json={"schema_version": "1.0", "email": {}},
        headers=AUTH_HEADERS,
    )

    body = response.json()
    assert response.status_code == 200
    assert body["verdict"] == "INCOMPLETE"
    assert body["findings"][0]["id"] == "demo_not_analyzed"


def test_analyze_enforces_bounded_body_size(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")

    response = client.post(
        "/analyze",
        json=analyze_payload(text_body="x" * 50_001),
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 422
