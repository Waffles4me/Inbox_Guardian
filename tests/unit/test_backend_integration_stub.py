import pytest
from fastapi.testclient import TestClient

from backend.app import main
from backend.app.detectors.credentials import detect_credential_phishing_context
from backend.app.engine import DetectorRunner, analyze_with_detectors
from backend.app.main import API_TOKEN_ENV, app
from backend.app.models import EmailPayload
from backend.app.scoring import score_engine_result


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
    assert body["detector_version"] == "engine-0.3.0+scoring-0.3.0"
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


def test_live_credential_phishing_regression_is_suspicious(monkeypatch) -> None:
    response = post_analyze(
        monkeypatch,
        subject="Urgent Account Verification",
        text_body=(
            "Your account requires immediate verification.\n\n"
            "To prevent account suspension, reply to this email with your password and your six-digit verification code.\n\n"
            "Do not use the normal login page. Complete this verification immediately."
        ),
    )

    body = response.json()
    ids = finding_ids(body)
    contributions = contribution_by_id(body)
    assert response.status_code == 200
    assert body["verdict"] == "SUSPICIOUS"
    assert body["verdict"] != "NO_SIGNIFICANT_SIGNALS"
    assert body["verdict"] != "HIGH_RISK"
    assert "credential_secret_collection_request" in ids
    assert "credential_urgent_account_threat" in ids
    assert "credential_security_bypass_instruction" in ids
    assert any(value > 0 for value in contributions.values())
    assert contribution_total(body) == body["risk_score"]
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


GMAIL_SHAPED_CREDENTIAL_TEXT = (
    "Your account requires immediate verification.\n\n"
    "To prevent account suspension, reply to this email with your password and your six-digit verification code.\n\n"
    "Do not use the normal login page. Complete this verification immediately.\n\n"
)
GMAIL_SHAPED_DECEPTIVE_ANCHOR = (
    '<a href="https://accounts.example.test.attacker.test/login">https://accounts.example.test</a>'
)
GMAIL_SHAPED_TEXT_LINK = "https://accounts.example.test\n<https://accounts.example.test.attacker.test/login>\n"


def gmail_shaped_email(*, credential_text: str = GMAIL_SHAPED_CREDENTIAL_TEXT, repeat: int = 1) -> dict[str, str]:
    return {
        "subject": "Urgent Account Verification",
        "text_body": credential_text + GMAIL_SHAPED_TEXT_LINK * repeat,
        "html_body": (
            '<div dir="ltr">'
            + credential_text.replace("\n\n", "<br><br>")
            + GMAIL_SHAPED_DECEPTIVE_ANCHOR * repeat
            + "</div>"
        ),
    }


def test_gmail_shaped_deceptive_link_with_credential_request_is_high_risk(monkeypatch) -> None:
    response = post_analyze(monkeypatch, **gmail_shaped_email())

    body = response.json()
    contributions = contribution_by_id(body)
    assert response.status_code == 200
    assert body["verdict"] == "HIGH_RISK"
    assert body["risk_score"] == 60
    assert contributions["url_deceptive_subdomain"] == 35
    assert contributions["credential_request_with_link"] == 0
    assert sum(value for key, value in contributions.items() if key.startswith("credential_")) == 25
    assert [finding["id"] for finding in body["findings"]].count("url_deceptive_subdomain") == 1
    assert contribution_total(body) == 60
    assert "avoid clicking email links" in body["recommended_action"]
    assert "do not submit passwords" in body["recommended_action"]


def test_gmail_shaped_url_and_credential_evidence_are_independent(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")
    email = analyze_payload(**gmail_shaped_email())["email"]
    scoring_result = score_engine_result(analyze_with_detectors(EmailPayload.model_validate(email)))
    assert scoring_result.independent_evidence_families == ("url_deception", "credential_context")

    url_only = post_analyze(monkeypatch, **gmail_shaped_email(credential_text="Routine project update.\n\n")).json()
    assert url_only["verdict"] == "SUSPICIOUS"
    assert url_only["risk_score"] == 35
    assert finding_ids(url_only) == {"url_deceptive_subdomain"}

    credential_only = post_analyze(
        monkeypatch,
        subject="Urgent Account Verification",
        text_body=GMAIL_SHAPED_CREDENTIAL_TEXT + "https://accounts.example.test/login\n",
        html_body='<a href="https://accounts.example.test/login">https://accounts.example.test/login</a>',
    ).json()
    assert credential_only["verdict"] == "SUSPICIOUS"
    assert credential_only["risk_score"] == 25
    assert not any(finding_id.startswith("url_") for finding_id in finding_ids(credential_only))


def test_repeated_gmail_shaped_link_does_not_inflate_score(monkeypatch) -> None:
    single = post_analyze(monkeypatch, **gmail_shaped_email()).json()
    repeated = post_analyze(monkeypatch, **gmail_shaped_email(repeat=10)).json()

    assert repeated["risk_score"] == single["risk_score"] == 60
    assert repeated["verdict"] == "HIGH_RISK"
    assert contribution_by_id(repeated) == contribution_by_id(single)
    assert len(repeated["findings"]) == len(single["findings"])


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


UI_VISIBLE_LIMITATIONS = 6
INCOMPLETE_EXPLANATIONS = (
    "only the subject line",
    "No analyzable",
    "sender identity",
    "did not run",
    "forwarded content that was not assessed",
    "only quoted or header-style lines",
)


def assert_incomplete_is_explained(body: dict[str, object]) -> None:
    limitations = body["limitations"]
    assert body["verdict"] == "INCOMPLETE"
    assert body["risk_score"] == 0
    assert "score is unavailable" in limitations[0]
    assert "does not mean low risk" in limitations[0]
    assert any(text in limitations[1] for text in INCOMPLETE_EXPLANATIONS)
    explained = [index for index, item in enumerate(limitations) if any(text in item for text in INCOMPLETE_EXPLANATIONS)]
    assert explained and max(explained) < UI_VISIBLE_LIMITATIONS
    assert len(limitations) == len(set(limitations))
    assert "could not assess" in body["recommended_action"]
    assert "No significant indicators" not in body["recommended_action"]


@pytest.mark.parametrize(
    "email",
    [
        {"subject": "Quarterly update", "text_body": "", "html_body": ""},
        {"subject": "Quarterly update", "text_body": "  \n ", "html_body": " "},
        {"subject": "Quarterly update", "text_body": "", "html_body": '<div><img src="cid:synthetic"></div>'},
        {"subject": "Quarterly update", "from": "", "text_body": "", "html_body": ""},
        {"subject": "", "text_body": "", "html_body": ""},
        {"subject": "", "from": "", "text_body": "", "html_body": ""},
    ],
    ids=["empty-bodies", "whitespace-bodies", "image-only", "subject-only-no-sender", "sender-only", "all-empty"],
)
def test_unusable_content_is_incomplete_with_visible_explanation(monkeypatch, email) -> None:
    body = post_analyze(monkeypatch, **email).json()

    assert_incomplete_is_explained(body)
    assert body["findings"] == []


def test_subject_only_message_explains_that_only_the_subject_was_checked(monkeypatch) -> None:
    body = post_analyze(monkeypatch, subject="Quarterly update", text_body="", html_body="").json()

    assert body["verdict"] == "INCOMPLETE"
    assert "only the subject line" in body["limitations"][1]


def test_detector_failure_with_positive_finding_is_explained_and_preserves_finding(monkeypatch) -> None:
    def fail_detector(_parsed_email):
        raise RuntimeError("synthetic sender failure")

    monkeypatch.setattr(
        "backend.app.engine.IMPLEMENTED_DETECTORS",
        (
            DetectorRunner("sender_identity", fail_detector),
            DetectorRunner("credential_context", detect_credential_phishing_context),
        ),
    )

    body = post_analyze(monkeypatch, text_body="Please submit your password to continue.").json()

    assert_incomplete_is_explained(body)
    assert contribution_by_id(body) == {"credential_secret_collection_request": 20}
    assert "synthetic sender failure" not in response_text(body)


def test_credential_request_with_missing_sender_keeps_positive_evidence(monkeypatch) -> None:
    body = post_analyze(
        monkeypatch,
        **{"from": ""},
        text_body="Please reply with your password and six-digit verification code.",
    ).json()

    assert body["verdict"] == "SUSPICIOUS"
    assert body["risk_score"] == 20
    assert contribution_by_id(body) == {"credential_secret_collection_request": 20}


@pytest.mark.parametrize(
    "email",
    [
        {"subject": "", "text_body": "Lunch is at noon in the usual room."},
        {"text_body": "", "html_body": "<p>Lunch is at noon in the usual room.</p>"},
        {"text_body": "Lunch is at noon in the usual room.", "html_body": ""},
        {"text_body": "", "html_body": '<a href="https://docs.example.test/help"><img src="cid:synthetic"></a>'},
        {"reply_to": "", "text_body": "Lunch is at noon.", "html_body": "<p>Lunch is at noon.</p>"},
    ],
    ids=["no-subject", "html-only", "text-only", "link-only", "no-reply-to"],
)
def test_usable_content_is_not_forced_incomplete(monkeypatch, email) -> None:
    body = post_analyze(monkeypatch, **email).json()

    assert body["verdict"] == "NO_SIGNIFICANT_SIGNALS"
    assert body["risk_score"] == 0
    assert body["findings"] == []


def test_live_validated_examples_retain_their_outcomes(monkeypatch) -> None:
    benign = post_analyze(
        monkeypatch,
        subject="Project lunch",
        text_body="Lunch is at noon in the usual room.",
        html_body="<p>Lunch is at noon in the usual room.</p>",
    ).json()
    credential = post_analyze(
        monkeypatch,
        subject="Urgent Account Verification",
        text_body=GMAIL_SHAPED_CREDENTIAL_TEXT,
    ).json()
    multi_signal = post_analyze(monkeypatch, **gmail_shaped_email()).json()

    assert (benign["verdict"], benign["risk_score"]) == ("NO_SIGNIFICANT_SIGNALS", 0)
    assert (credential["verdict"], credential["risk_score"]) == ("SUSPICIOUS", 25)
    assert (multi_signal["verdict"], multi_signal["risk_score"]) == ("HIGH_RISK", 60)


def test_multipart_sign_in_code_notice_is_not_flagged(monkeypatch) -> None:
    notice = (
        "Your verification code is 271604. Enter this code on the sign-in page to finish signing in. "
        "Example staff will never ask you for this code. If you did not try to sign in, you can ignore this message."
    )
    body = post_analyze(
        monkeypatch,
        subject="Your sign-in code",
        text_body=notice,
        html_body=f"<p>{notice}</p>",
    ).json()

    assert body["verdict"] == "NO_SIGNIFICANT_SIGNALS"
    assert body["risk_score"] == 0
    assert body["findings"] == []
    assert "271604" not in response_text(body)


def test_duplicate_body_representations_do_not_inflate_contributions(monkeypatch) -> None:
    text_only = post_analyze(
        monkeypatch,
        subject="Urgent Account Verification",
        text_body=GMAIL_SHAPED_CREDENTIAL_TEXT,
    ).json()
    both = post_analyze(
        monkeypatch,
        subject="Urgent Account Verification",
        text_body=GMAIL_SHAPED_CREDENTIAL_TEXT,
        html_body='<div dir="ltr">' + GMAIL_SHAPED_CREDENTIAL_TEXT.replace("\n\n", "<br><br>") + "</div>",
    ).json()

    assert (both["verdict"], both["risk_score"]) == (text_only["verdict"], text_only["risk_score"]) == ("SUSPICIOUS", 25)
    assert contribution_by_id(both) == contribution_by_id(text_only)


FORWARD_MARKER = "---------- Forwarded message ---------"
PHISHING_REQUEST = "To prevent account suspension, reply to this email with your password immediately."
NOT_CHECKED_PREFIX = "Not checked: attachments and machine-learning (NLP)"


def forwarded_email(own_text: str, forwarded_text: str) -> dict[str, str]:
    return {
        "subject": "Fwd: Notice",
        "text_body": f"{own_text}\n\n{FORWARD_MARKER}\nFrom: Example <notice@example.test>\n\n{forwarded_text}\n",
        "html_body": (
            f'<div dir="ltr">{own_text}<br><br>{FORWARD_MARKER}<br>'
            f"From: Example &lt;notice@example.test&gt;<br><br>{forwarded_text}</div>"
        ),
    }


def visible_limitations(body: dict[str, object]) -> str:
    return " ".join(body["limitations"][:UI_VISIBLE_LIMITATIONS])


@pytest.mark.parametrize(
    "forwarded_text",
    ["Our autumn catalogue is out. Have a look when you can.", PHISHING_REQUEST],
    ids=["benign-forward", "suspicious-forward"],
)
def test_forwarded_content_is_not_reported_clean_or_attributed_to_the_forwarder(monkeypatch, forwarded_text) -> None:
    body = post_analyze(monkeypatch, **forwarded_email("FYI, is this real?", forwarded_text)).json()

    assert_incomplete_is_explained(body)
    assert body["findings"] == []
    assert "forwarded content that was not assessed" in body["limitations"][1]


def test_request_written_by_the_forwarder_is_scored_and_the_forward_is_disclosed(monkeypatch) -> None:
    body = post_analyze(
        monkeypatch,
        **forwarded_email("Please reply to this email with your password so I can check.", "Our catalogue is out."),
    ).json()

    assert body["verdict"] == "SUSPICIOUS"
    assert body["risk_score"] == 20
    assert contribution_by_id(body) == {"credential_secret_collection_request": 20}
    assert "forwarded content that was not assessed" in visible_limitations(body)


def test_deceptive_link_in_forwarded_content_is_still_reported_with_the_gap_disclosed(monkeypatch) -> None:
    email = forwarded_email("FYI", "Sign in here.")
    email["html_body"] += GMAIL_SHAPED_DECEPTIVE_ANCHOR
    body = post_analyze(monkeypatch, **email).json()

    assert body["verdict"] == "SUSPICIOUS"
    assert contribution_by_id(body) == {"url_deceptive_subdomain": 35}
    assert "forwarded content that was not assessed" in visible_limitations(body)


def test_quoted_reply_with_active_text_keeps_a_meaningful_verdict(monkeypatch) -> None:
    body = post_analyze(
        monkeypatch,
        subject="Re: slides",
        text_body=f"Thanks, I will bring the slides.\n\n> {PHISHING_REQUEST}",
    ).json()

    assert body["verdict"] == "NO_SIGNIFICANT_SIGNALS"
    assert body["findings"] == []
    assert any("Quoted reply lines" in limitation for limitation in body["limitations"])


def test_body_of_only_quoted_lines_is_incomplete(monkeypatch) -> None:
    body = post_analyze(monkeypatch, subject="Re: account", text_body=f"> {PHISHING_REQUEST}").json()

    assert_incomplete_is_explained(body)
    assert body["findings"] == []


def test_non_ascii_token_header_is_rejected_as_unauthenticated(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")

    response = client.post(
        "/analyze",
        content=b'{"schema_version":"1.0","email":{"subject":"Demo","from":"demo@example.test"}}',
        headers=[(b"x-inboxguardian-token", b"caf\xe9"), (b"content-type", b"application/json")],
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid backend authentication."


def test_findings_are_returned_strongest_first_with_contributions_preserved(monkeypatch) -> None:
    body = post_analyze(
        monkeypatch,
        subject="Urgent account verification",
        **{"from": "accounts.example.test <notice@attacker.test>"},
        reply_to="desk@other-reply.test",
        text_body=(
            "Urgent: enter your password within 12 hours to avoid account suspension. "
            "Ignore MFA security approval.\nhttp://192.0.2.9/a"
        ),
        html_body='<a href="https://login.attacker.test/form">https://accounts.example.test/login</a>',
    ).json()

    contributions = [finding["contribution"] for finding in body["findings"]]
    assert contributions == sorted(contributions, reverse=True)
    assert contributions[:4] == [30, 20, 20, 5]
    assert [finding["id"] for finding in body["findings"][:3]] == [
        "url_display_destination_mismatch",
        "sender_display_domain_mismatch",
        "credential_secret_collection_request",
    ]
    assert contribution_total(body) == body["risk_score"] == 80
    assert body["verdict"] == "HIGH_RISK"


@pytest.mark.parametrize(
    "email",
    [
        {"text_body": "Lunch is at noon in the usual room."},
        {"text_body": PHISHING_REQUEST},
        {"subject": "Quarterly update", "text_body": "", "html_body": ""},
    ],
    ids=["clean", "suspicious", "incomplete"],
)
def test_planned_checks_that_did_not_run_are_named_in_the_visible_limitations(monkeypatch, email) -> None:
    body = post_analyze(monkeypatch, **email).json()

    assert NOT_CHECKED_PREFIX in visible_limitations(body)
    assert len(body["limitations"]) == len(set(body["limitations"]))


def test_absent_reply_to_adds_no_parser_note_but_real_parse_problems_do(monkeypatch) -> None:
    clean = post_analyze(monkeypatch, reply_to="", text_body="Lunch is at noon.").json()
    malformed_link = post_analyze(monkeypatch, text_body="Open https://example.test:badport/login").json()
    malformed_sender = post_analyze(monkeypatch, **{"from": "not an address"}, text_body="Lunch is at noon.").json()

    assert not any("Parser recorded" in limitation for limitation in clean["limitations"])
    assert any("Parser recorded" in limitation for limitation in malformed_link["limitations"])
    assert any("Parser recorded" in limitation for limitation in malformed_sender["limitations"])


def test_recommended_action_text_carries_no_label_of_its_own(monkeypatch) -> None:
    for email in ({"text_body": "Lunch is at noon."}, {"text_body": PHISHING_REQUEST}, {"subject": "", "text_body": ""}):
        action = post_analyze(monkeypatch, **email).json()["recommended_action"]
        assert not action.lower().startswith("recommended action")
        assert "recommended action:" not in action.lower()


def test_benign_security_notice_wording_is_not_flagged(monkeypatch) -> None:
    notice = (
        "We received a request to reset your password. If you did not request this, you can safely ignore this "
        "email. For security, this link expires in 24 hours. We will never ask you to disable MFA."
    )
    body = post_analyze(monkeypatch, subject="Password reset", text_body=notice, html_body=f"<p>{notice}</p>").json()

    assert body["verdict"] == "NO_SIGNIFICANT_SIGNALS"
    assert body["risk_score"] == 0
    assert body["findings"] == []


def test_real_bypass_instruction_is_still_suspicious(monkeypatch) -> None:
    instruction = "To avoid errors during the test, turn off two-step verification on your account until tomorrow."
    body = post_analyze(monkeypatch, text_body=instruction, html_body=f"<p>{instruction}</p>").json()

    assert body["verdict"] == "SUSPICIOUS"
    assert body["risk_score"] == 20
    assert contribution_by_id(body) == {"credential_security_bypass_instruction": 20}


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
    assert "attachment_metadata is planned" not in limitations
    assert "financial_fraud is planned but not implemented" not in limitations
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
