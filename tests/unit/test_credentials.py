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
