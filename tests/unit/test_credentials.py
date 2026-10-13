import pytest

from backend.app.detectors.base import DetectorStatus
from backend.app.detectors.credentials import detect_credential_phishing_context
from backend.app.models import EmailPayload
from backend.app.parsing import parse_email_payload


def parsed_email(**overrides: object):
    data = {
        "subject": "Synthetic credential test",
        "from": "Example <notice@example.test>",
        "reply_to": "",
        "text_body": "",
        "html_body": "",
        "headers": {},
        "attachment_metadata": [],
    }
    data.update(overrides)
    return parse_email_payload(EmailPayload.model_validate(data))


def result(**overrides: object):
    return detect_credential_phishing_context(parsed_email(**overrides))


def finding_ids(detector_result) -> list[str]:
    return [finding.id for finding in detector_result.findings]


def test_explicit_password_submission_request_triggers() -> None:
    detector_result = result(text_body="Please submit your password to keep access to the account.")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_secret_collection_request" in finding_ids(detector_result)
    assert detector_result.findings[0].contribution == 0


def test_request_to_share_otp_or_mfa_code_triggers() -> None:
    detector_result = result(text_body="Reply with your OTP so we can verify the login.")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_secret_collection_request" in finding_ids(detector_result)


def test_reply_to_this_email_with_password_triggers() -> None:
    detector_result = result(text_body="Reply to this email with your password.")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_secret_collection_request" in finding_ids(detector_result)


def test_reply_with_verification_code_triggers() -> None:
    detector_result = result(text_body="Reply with your verification code to continue.")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_secret_collection_request" in finding_ids(detector_result)


def test_explicit_six_digit_verification_code_request_triggers() -> None:
    detector_result = result(text_body="Please provide your six-digit verification code to restore access.")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_secret_collection_request" in finding_ids(detector_result)


def test_live_false_negative_message_triggers_credential_findings() -> None:
    detector_result = result(
        subject="Urgent Account Verification",
        text_body=(
            "Your account requires immediate verification.\n\n"
            "To prevent account suspension, reply to this email with your password and your six-digit verification code.\n\n"
            "Do not use the normal login page. Complete this verification immediately."
        ),
    )

    ids = finding_ids(detector_result)
    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_secret_collection_request" in ids
    assert "credential_urgent_account_threat" in ids
    assert "credential_security_bypass_instruction" in ids


def test_urgent_account_suspension_threat_with_credential_request_triggers_context() -> None:
    detector_result = result(
        text_body="Urgent: your account will be suspended within 12 hours. Enter your password to restore access."
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_secret_collection_request" in finding_ids(detector_result)
    assert "credential_urgent_account_threat" in finding_ids(detector_result)


def test_account_verification_language_with_link_triggers() -> None:
    detector_result = result(
        html_body='<p>Verify your account to restore access.</p><a href="https://example.test/login">Verify now</a>'
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_account_verification_with_link" in finding_ids(detector_result)


def test_legitimate_password_reset_notification_does_not_trigger() -> None:
    detector_result = result(
        text_body="You requested a password reset. If this was you, use the reset link. We will never ask for your password."
    )

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()


def test_legitimate_mfa_notification_does_not_trigger() -> None:
    detector_result = result(text_body="Your MFA code was used to sign in. If this was not you, review your account.")

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()


def test_never_reply_with_password_warning_does_not_trigger_collection() -> None:
    detector_result = result(text_body="Never reply to an email with your password.")

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert "credential_secret_collection_request" not in finding_ids(detector_result)


def test_do_not_share_verification_code_warning_does_not_trigger_collection() -> None:
    detector_result = result(text_body="Do not share your six-digit verification code with anyone.")

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert "credential_secret_collection_request" not in finding_ids(detector_result)


def test_generic_account_verification_without_secret_collection_does_not_trigger() -> None:
    detector_result = result(text_body="Please verify your account details by reviewing your profile settings.")

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()


def test_generic_password_mention_without_collection_request_does_not_trigger() -> None:
    detector_result = result(text_body="Use a strong password and store it in a password manager.")

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()


def test_normal_account_security_newsletter_does_not_trigger() -> None:
    detector_result = result(
        text_body="This month we explain account security basics, phishing awareness, and safe login habits."
    )

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_urgency_without_credential_request_does_not_trigger() -> None:
    detector_result = result(text_body="Urgent maintenance starts today. Some account features may be unavailable.")

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_missing_subject_and_body_is_inconclusive() -> None:
    detector_result = result(subject="", text_body="", html_body="")

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()


def test_html_only_email_is_evaluated() -> None:
    detector_result = result(
        html_body="<p>Provide your authentication code to continue.</p>",
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert detector_result.evidence_sources == ("subject", "html_body")


def test_plain_text_only_email_is_evaluated() -> None:
    detector_result = result(text_body="Confirm your security code on the form to continue.")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "text_body" in detector_result.evidence_sources


def test_quoted_or_forwarded_phishing_language_is_ignored_when_identifiable() -> None:
    detector_result = result(
        text_body=(
            "FYI, this looks suspicious.\n\n"
            "----- Forwarded message -----\n"
            "From: attacker@example.test\n"
            "Please submit your password immediately."
        )
    )

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_case_and_punctuation_variations_are_detected() -> None:
    detector_result = result(text_body="VERIFY, your ACCOUNT now: enter your PASSWORD to continue.")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_secret_collection_request" in finding_ids(detector_result)


def test_ambiguous_incomplete_context_is_inconclusive() -> None:
    detector_result = result(text_body="Please verify your account.")

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()


def test_deterministic_output_and_stable_ids() -> None:
    first = result(text_body="Share your MFA code to avoid account suspension.")
    second = result(text_body="Share your MFA code to avoid account suspension.")

    assert first == second
    assert first.detector_id == "credential_context"
    assert first.implementation_version == "credentials-0.1.0"
    assert "credential_secret_collection_request" in finding_ids(first)
    assert all(finding.contribution == 0 for finding in first.findings)


def test_findings_reflect_observed_text() -> None:
    detector_result = result(text_body="Submit your password to restore access.")

    observation = detector_result.findings[0].observation
    assert "Submit your password" in observation
    assert "restore access" in observation


def test_sensitive_code_values_are_redacted_from_explanations() -> None:
    detector_result = result(text_body="Please share your MFA code 123456 to continue.")

    combined_observations = " ".join(finding.observation for finding in detector_result.findings)
    assert "123456" not in combined_observations
    assert "[redacted-code]" in combined_observations


def test_security_bypass_instruction_triggers() -> None:
    detector_result = result(text_body="Ignore MFA security approval and verify your account through this message.")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_security_bypass_instruction" in finding_ids(detector_result)


SIGN_IN_CODE_TEXT = (
    "Your verification code is 271604.\n\n"
    "Enter this code on the sign-in page to finish signing in. It expires in 10 minutes.\n\n"
    "Example staff will never ask you for this code. If you did not try to sign in, you can ignore this message."
)
SIGN_IN_CODE_HTML = (
    "<p>Your verification code is <b>271604</b>.</p>"
    "<p>Enter this code on the sign-in page to finish signing in. It expires in 10 minutes.</p>"
    "<p>Example staff will never ask you for this code. If you did not try to sign in, you can ignore this message.</p>"
)
BYPASS_TEXT = "To avoid errors during the test, turn off two-step verification on your account until tomorrow."
REQUEST_TEXT = "To prevent account suspension, reply to this email with your password immediately."


@pytest.mark.parametrize(
    "bodies",
    [
        {"text_body": SIGN_IN_CODE_TEXT},
        {"html_body": SIGN_IN_CODE_HTML},
        {"text_body": SIGN_IN_CODE_TEXT, "html_body": SIGN_IN_CODE_HTML},
    ],
    ids=["text-only", "html-only", "text-and-html"],
)
def test_sign_in_code_notice_has_no_bypass_finding_in_any_representation(bodies: dict[str, str]) -> None:
    detector_result = result(subject="Your sign-in code", **bodies)

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()


def test_pattern_cannot_span_plain_text_and_html_alternatives() -> None:
    detector_result = result(
        text_body="If this was not you, you can ignore this message.",
        html_body="<p>Security verification is complete.</p>",
    )

    assert "credential_security_bypass_instruction" not in finding_ids(detector_result)


@pytest.mark.parametrize(
    "bodies",
    [
        {"text_body": BYPASS_TEXT},
        {"html_body": f"<p>{BYPASS_TEXT}</p>"},
        {"text_body": BYPASS_TEXT, "html_body": f"<p>{BYPASS_TEXT}</p>"},
    ],
    ids=["text-only", "html-only", "text-and-html"],
)
def test_bypass_instruction_within_one_representation_triggers_once(bodies: dict[str, str]) -> None:
    detector_result = result(**bodies)

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert finding_ids(detector_result) == ["credential_security_bypass_instruction"]


def test_duplicate_representations_produce_the_same_findings_as_one() -> None:
    text_only = result(text_body=REQUEST_TEXT)
    both = result(text_body=REQUEST_TEXT, html_body=f"<div>{REQUEST_TEXT}</div>")

    assert finding_ids(both) == finding_ids(text_only)
    assert finding_ids(both) == [
        "credential_secret_collection_request",
        "credential_urgent_account_threat",
    ]
    assert [finding.observation for finding in both.findings] == [finding.observation for finding in text_only.findings]


def test_request_present_only_in_html_alternative_is_detected() -> None:
    detector_result = result(
        text_body="Please view this message in an HTML-capable mail client.",
        html_body=f"<p>{REQUEST_TEXT}</p>",
    )

    assert "credential_secret_collection_request" in finding_ids(detector_result)


def test_warning_followed_by_separate_malicious_request_is_detected() -> None:
    message = (
        "Remember that we will never ask for your password by phone. "
        "However, to restore your access, reply to this email with your password before midnight."
    )
    detector_result = result(text_body=message, html_body=f"<p>{message}</p>")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert "credential_secret_collection_request" in finding_ids(detector_result)
    assert "reply to this email with your password" in detector_result.findings[0].observation


def test_forwarded_content_stays_ignored_when_html_alternative_repeats_it() -> None:
    forwarded_text = (
        "FYI, is this real?\n\n"
        "---------- Forwarded message ---------\n"
        "From: Example <notice@example.test>\n\n"
        f"{REQUEST_TEXT}\n"
    )
    forwarded_html = (
        '<div dir="ltr">FYI, is this real?<br><br>---------- Forwarded message ---------<br>'
        f"From: Example &lt;notice@example.test&gt;<br><br>{REQUEST_TEXT}</div>"
    )
    text_only = result(text_body=forwarded_text)
    both = result(text_body=forwarded_text, html_body=forwarded_html)

    assert text_only.findings == ()
    assert both.findings == ()
    assert both.status == text_only.status


BYPASS_ID = "credential_security_bypass_instruction"
BENIGN_SECURITY_WORDING = [
    "You can safely ignore this email. For security, this link expires in 24 hours.",
    "Do not disable MFA on your account.",
    "IT will never ask you to bypass security checks.",
    "If you didn't request this verification code, ignore this message.",
    "If you didn't request this verification code, ignore this message. Verification codes expire after 10 minutes.",
    "Never turn off two-step verification.",
    "If this was not you, ignore this message. Security tip: never reuse passwords.",
    "We don’t recommend that you turn off security alerts.",
]
REAL_BYPASS_INSTRUCTIONS = [
    "Please disable MFA on your account so we can complete the migration.",
    "Use this link to bypass the security check and restore access.",
    "You must ignore the pending account approval and continue with the transfer.",
    "To avoid errors during the test, turn off two-step verification on your account until tomorrow.",
]
MIXED_WARNING_AND_INSTRUCTION = [
    "We will never ask for your password. However, you must disable MFA today to keep your mailbox.",
    "Never share your code, but turn off two-step verification before the upgrade.",
    "Do not disable MFA for anyone else. Now disable security verification on this account to continue.",
    "Don't worry, just disable security verification for one hour.",
    "Don't forget to disable MFA before the upgrade tonight.",
    "Do not hesitate to turn off two-step verification if the prompt appears.",
]


def body_arrangements(text: str) -> list[dict[str, str]]:
    return [{"text_body": text}, {"html_body": f"<p>{text}</p>"}, {"text_body": text, "html_body": f"<p>{text}</p>"}]


@pytest.mark.parametrize("text", BENIGN_SECURITY_WORDING)
def test_benign_security_wording_is_not_a_bypass_instruction(text: str) -> None:
    for bodies in body_arrangements(text):
        assert BYPASS_ID not in finding_ids(result(**bodies))


@pytest.mark.parametrize("text", REAL_BYPASS_INSTRUCTIONS)
def test_real_bypass_instruction_triggers_in_every_body_arrangement(text: str) -> None:
    for bodies in body_arrangements(text):
        detector_result = result(**bodies)
        assert finding_ids(detector_result).count(BYPASS_ID) == 1
        assert detector_result.status == DetectorStatus.TRIGGERED


@pytest.mark.parametrize("text", MIXED_WARNING_AND_INSTRUCTION)
def test_warning_does_not_hide_a_separate_bypass_instruction(text: str) -> None:
    for bodies in body_arrangements(text):
        assert BYPASS_ID in finding_ids(result(**bodies))


def test_bypass_observation_quotes_only_the_instruction_sentence() -> None:
    detector_result = result(
        text_body="Do not disable MFA for anyone else. Now disable security verification on this account to continue."
    )

    observation = next(finding.observation for finding in detector_result.findings if finding.id == BYPASS_ID)
    assert "Now disable security verification" in observation
    assert "anyone else" not in observation


def test_bypass_verb_and_security_term_in_different_sentences_do_not_combine() -> None:
    detector_result = result(text_body="Please ignore my last email. Security training moves to Monday.")

    assert BYPASS_ID not in finding_ids(detector_result)


def test_negated_bypass_wording_keeps_other_credential_findings() -> None:
    detector_result = result(
        text_body=(
            "Do not disable MFA on your account. "
            "To prevent account suspension, reply to this email with your password immediately."
        )
    )

    assert finding_ids(detector_result) == [
        "credential_secret_collection_request",
        "credential_urgent_account_threat",
    ]
