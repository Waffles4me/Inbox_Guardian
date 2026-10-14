from backend.app.detectors.base import DetectorStatus
from backend.app.engine import analyze_with_detectors
from backend.app.models import EmailPayload
from backend.app.scoring import score_engine_result


def payload(**overrides: object) -> EmailPayload:
    data = {
        "subject": "Synthetic financial test",
        "from": "Finance <finance@example.test>",
        "reply_to": "",
        "text_body": "Normal business update.",
        "html_body": "",
        "headers": {},
        "attachment_metadata": [],
        "attachment_collection": {"state": "NONE", "regular_count": 0},
    }
    data.update(overrides)
    return EmailPayload.model_validate(data)


def financial_result(**overrides: object):
    result = analyze_with_detectors(payload(**overrides))
    return next(detector for detector in result.detector_results if detector.detector_id == "financial_fraud")


def finding_ids(**overrides: object) -> set[str]:
    return {finding.id for finding in financial_result(**overrides).findings}


def test_payment_redirection_requires_change_and_payment_instruction() -> None:
    result = financial_result(
        text_body="Please process the invoice payment using the new bank account details for this vendor."
    )

    assert result.status == DetectorStatus.TRIGGERED
    assert finding_ids(
        text_body="Please process the invoice payment using the new bank account details for this vendor."
    ) == {"financial_payment_destination_change"}


def test_urgent_wire_requires_payment_context_plus_pressure() -> None:
    ids = finding_ids(
        text_body="Urgent: the CFO needs this wire transfer released today before close of business."
    )

    assert "financial_urgent_payment_request" in ids


def test_gift_card_redemption_code_request_triggers() -> None:
    ids = finding_ids(text_body="Buy three gift cards and reply with the redemption codes when scratched.")

    assert ids == {"financial_gift_card_code_request"}


def test_finance_verification_bypass_triggers() -> None:
    ids = finding_ids(text_body="Please process this payment without the usual finance approval callback.")

    assert "financial_verification_bypass_request" in ids


def test_financial_request_with_secrecy_triggers() -> None:
    ids = finding_ids(text_body="Please send the vendor payment today and keep this between us for now.")

    assert "financial_secret_or_channel_avoidance" in ids


def test_legitimate_supplier_bank_update_is_not_flagged() -> None:
    result = financial_result(
        text_body=(
            "The supplier bank details changed after approval. The signed bank letter is attached in the vendor "
            "portal and takes effect next month."
        )
    )

    assert result.findings == ()
    assert result.status in {DetectorStatus.NOT_TRIGGERED, DetectorStatus.INCONCLUSIVE}


def test_ordinary_invoice_reminder_is_not_proof_of_fraud() -> None:
    result = financial_result(text_body="Reminder: invoice INV-2026-004 is due next Friday under the normal terms.")

    assert result.findings == ()
    assert result.status in {DetectorStatus.NOT_TRIGGERED, DetectorStatus.INCONCLUSIVE}


def test_payroll_notification_is_not_flagged() -> None:
    result = financial_result(text_body="Payroll will be deposited on Friday as usual.")

    assert result.findings == ()


def test_negated_warning_does_not_trigger() -> None:
    result = financial_result(text_body="Do not wire funds or update bank details based only on email instructions.")

    assert result.findings == ()


def test_forwarded_financial_request_is_excluded_as_coverage_gap() -> None:
    result = financial_result(
        text_body=(
            "Please see below.\n"
            "---------- Forwarded message ---------\n"
            "Urgent: wire this payment today and keep this between us."
        )
    )

    assert result.status == DetectorStatus.INCONCLUSIVE
    assert result.findings == ()
    assert result.coverage_gaps


def test_quoted_financial_request_is_not_attributed_to_sender() -> None:
    result = financial_result(text_body="> Urgent: wire this payment today.\n> Keep this between us.")

    assert result.status == DetectorStatus.INCONCLUSIVE
    assert result.findings == ()
    assert result.coverage_gaps


def test_findings_redact_account_like_values() -> None:
    result = financial_result(
        text_body=(
            "Please process the invoice payment using the new account number ABCD-REDACT-ME today "
            "for reference PAY-1234-PRIVATE."
        )
    )

    text = " ".join(finding.observation for finding in result.findings)
    assert "ABCD-REDACT-ME" not in text
    assert "PAY-1234-PRIVATE" not in text
    assert "[redacted-account]" in text
    assert "[redacted-id]" in text


def test_financial_family_scores_with_cap_and_single_family_cannot_high_risk() -> None:
    engine_result = analyze_with_detectors(
        payload(
            text_body=(
                "Please process the invoice payment using the new bank account details today. "
                "Urgent: the CFO needs this wire transfer released today before close of business. "
                "Keep this between us until it is done."
            )
        )
    )
    scored = score_engine_result(engine_result)
    family = next(item for item in scored.family_scores if item.detector_id == "financial_fraud")

    assert (family.raw_points, family.capped_points, family.cap) == (50, 35, 35)
    assert scored.independent_evidence_families == ("financial_fraud",)
    assert scored.verdict == "SUSPICIOUS"


def test_financial_plus_independent_url_can_be_high_risk() -> None:
    engine_result = analyze_with_detectors(
        payload(
            text_body="Please process the invoice payment using the new bank account details today.",
            html_body='<a href="https://evil.example.test/pay">https://vendor.example.test/pay</a>',
        )
    )
    scored = score_engine_result(engine_result)

    assert scored.risk_score >= 60
    assert scored.independent_evidence_families == ("url_deception", "financial_fraud")
    assert scored.verdict == "HIGH_RISK"


def test_financial_rules_use_no_network(monkeypatch) -> None:
    calls: list[str] = []

    def forbidden(*args, **kwargs):
        calls.append("network")
        raise AssertionError("network should not be used")

    monkeypatch.setattr("socket.create_connection", forbidden)

    result = financial_result(text_body="Buy gift cards and reply with the codes.")

    assert result.findings
    assert calls == []
