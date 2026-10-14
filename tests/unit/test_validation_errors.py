"""Validation errors must not echo what the client sent.

FastAPI's default 422 body includes the rejected input and parser messages, which can be message text or attachment
names. ``backend/app/main.py`` replaces it with locations and error types only. Every case here embeds a unique
sentinel and checks that it appears nowhere in the response.
"""

import json

import pytest
from fastapi.testclient import TestClient

from backend.app.main import API_TOKEN_ENV, MAX_VALIDATION_ERRORS, SCHEMA_FIELD_NAMES, VALIDATION_LOCATION_ROOTS, app


client = TestClient(app)
TOKEN = "test-token"
AUTH = {"X-InboxGuardian-Token": TOKEN}
SENTINEL = "IG-SENTINEL-7f3c"
BASE_EMAIL = {"from": "Example <notice@example.test>", "text_body": "Synthetic body."}


def email(**fields) -> dict:
    return {"schema_version": "1.0", "email": {**BASE_EMAIL, **fields}}


INVALID_JSON_REQUESTS = {
    "oversized-attachment-name": email(attachment_metadata=[{"filename": SENTINEL + "x" * 600 + ".pdf"}]),
    "oversized-content-type": email(attachment_metadata=[{"filename": "a.pdf", "content_type": SENTINEL + "x" * 300}]),
    "attachment-size-not-a-number": email(attachment_metadata=[{"filename": "a.pdf", "size_bytes": SENTINEL}]),
    "too-many-attachments": email(attachment_metadata=[{"filename": SENTINEL}] * 26),
    "collection-state-too-long": email(attachment_collection={"state": SENTINEL * 5}),
    "collection-extension-too-long": email(
        attachment_collection={"state": "NONE", "omitted_extensions": [SENTINEL + "-extension"]}
    ),
    "header-value-too-long": email(headers={"Subject-Copy": SENTINEL + "x" * 2_100}),
    "header-key-in-location": email(headers={SENTINEL: 5}),
    "too-many-headers": email(headers={f"X-{SENTINEL}-{index}": "v" for index in range(51)}),
    "oversized-text-body": email(text_body=SENTINEL + "x" * 50_001),
    "oversized-html-body": email(html_body=SENTINEL + "x" * 50_001),
    "subject-wrong-type": email(subject={"nested": SENTINEL}),
    "from-too-long": {"schema_version": "1.0", "email": {"from": SENTINEL + "x" * 1_000, "text_body": "Body."}},
    "wrong-schema-version": {"schema_version": SENTINEL, "email": BASE_EMAIL},
    "email-not-an-object": {"schema_version": "1.0", "email": [SENTINEL]},
    "request-not-an-object": [SENTINEL],
}
RAW_REQUESTS = {
    "malformed-json": (b'{"schema_version": "1.0", "email": {"text_body": "' + SENTINEL.encode() + b'"', "application/json"),
    "truncated-json": (b'{"email": ' + SENTINEL.encode(), "application/json"),
    "non-json-content-type": (SENTINEL.encode(), "text/plain"),
}
UNDECODABLE_BODY = b'{"email": {"text_body": "\xff\xfe' + SENTINEL.encode() + b'"}}'


@pytest.fixture(autouse=True)
def configured_token(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, TOKEN)


def post_json(payload, headers=None):
    return client.post("/analyze", json=payload, headers=headers or {})


def post_raw(body: bytes, content_type: str, headers=None):
    return client.post("/analyze", content=body, headers={"content-type": content_type, **(headers or {})})


def assert_sanitized(response) -> None:
    assert response.status_code == 422
    assert SENTINEL not in response.text
    body = response.json()
    assert set(body) == {"detail", "message"}
    assert body["detail"], "at least one error location is reported"
    for error in body["detail"]:
        assert set(error) == {"loc", "type"}
        for part in error["loc"]:
            assert isinstance(part, int) or part in SCHEMA_FIELD_NAMES or part in VALIDATION_LOCATION_ROOTS or part == "*"


@pytest.mark.parametrize("case", sorted(INVALID_JSON_REQUESTS))
def test_schema_validation_errors_do_not_echo_rejected_values(case: str) -> None:
    assert_sanitized(post_json(INVALID_JSON_REQUESTS[case], AUTH))


@pytest.mark.parametrize("case", sorted(RAW_REQUESTS))
def test_malformed_requests_do_not_echo_the_raw_body(case: str) -> None:
    body, content_type = RAW_REQUESTS[case]

    assert_sanitized(post_raw(body, content_type, AUTH))


@pytest.mark.parametrize("headers", [AUTH, {}], ids=["authenticated", "unauthenticated"])
def test_undecodable_body_gets_fastapis_fixed_400_without_echo(headers) -> None:
    # FastAPI rejects a body it cannot decode before validation and before the token check, with a fixed
    # message. This is existing behaviour outside request validation; it reveals nothing that was sent.
    response = post_raw(UNDECODABLE_BODY, "application/json", headers)

    assert response.status_code == 400
    assert response.json() == {"detail": "There was an error parsing the body"}
    assert SENTINEL not in response.text


def test_request_derived_location_parts_are_replaced() -> None:
    body = post_json(INVALID_JSON_REQUESTS["header-key-in-location"], AUTH).json()

    assert body["detail"][0]["loc"] == ["body", "email", "headers", "*"]


def test_locations_keep_schema_field_names_and_positions() -> None:
    body = post_json(INVALID_JSON_REQUESTS["attachment-size-not-a-number"], AUTH).json()

    assert body["detail"][0]["loc"] == ["body", "email", "attachment_metadata", 0, "size_bytes"]
    assert body["detail"][0]["type"] == "int_parsing"


def test_number_of_reported_errors_is_bounded() -> None:
    payload = email(attachment_metadata=[{"filename": "a.pdf", "size_bytes": SENTINEL}] * 25, subject=[SENTINEL])
    payload["email"]["attachment_collection"] = {"state": "NONE", "regular_count": SENTINEL}
    response = post_json(payload, AUTH)

    assert_sanitized(response)
    assert len(response.json()["detail"]) <= MAX_VALIDATION_ERRORS


@pytest.mark.parametrize(
    "send",
    [
        lambda headers: post_json(INVALID_JSON_REQUESTS["oversized-attachment-name"], headers),
        lambda headers: post_json(INVALID_JSON_REQUESTS["header-key-in-location"], headers),
        lambda headers: post_raw(*RAW_REQUESTS["malformed-json"], headers),
        lambda headers: post_raw(*RAW_REQUESTS["non-json-content-type"], headers),
    ],
    ids=["schema-invalid", "header-key", "malformed-json", "non-json"],
)
@pytest.mark.parametrize("token", [None, "wrong-token"], ids=["missing-token", "wrong-token"])
def test_unauthenticated_invalid_requests_get_401_without_validation_details(send, token) -> None:
    response = send({"X-InboxGuardian-Token": token} if token else {})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid backend authentication."}
    assert SENTINEL not in response.text


def test_invalid_request_without_configured_authentication_gets_503(monkeypatch) -> None:
    monkeypatch.delenv(API_TOKEN_ENV)
    response = post_raw(*RAW_REQUESTS["malformed-json"], AUTH)

    assert response.status_code == 503
    assert SENTINEL not in response.text


def test_validation_errors_are_not_logged(capsys, caplog) -> None:
    for payload in INVALID_JSON_REQUESTS.values():
        post_json(payload, AUTH)
    for body, content_type in RAW_REQUESTS.values():
        post_raw(body, content_type, AUTH)
    post_raw(UNDECODABLE_BODY, "application/json", AUTH)
    captured = capsys.readouterr()

    assert SENTINEL not in captured.out + captured.err
    assert SENTINEL not in caplog.text


def test_valid_requests_are_unaffected() -> None:
    response = post_json(email(), AUTH)

    assert response.status_code == 200
    assert json.loads(response.text)["schema_version"] == "1.0"
