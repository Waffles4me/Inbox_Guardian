from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint_returns_stub_incomplete_response() -> None:
    response = client.post(
        "/analyze",
        json={
            "schema_version": "1.0",
            "email": {
                "subject": "Synthetic setup check",
                "from": "Demo <demo@example.test>",
                "reply_to": "",
                "text_body": "This is not a real analysis.",
                "html_body": "",
                "headers": {},
                "attachment_metadata": [],
            },
        },
    )

    body = response.json()
    assert response.status_code == 200
    assert body["verdict"] == "INCOMPLETE"
    assert body["risk_score"] == 0
    assert "not implemented" in body["limitations"][0]
