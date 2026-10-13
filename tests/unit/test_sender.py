from backend.app.detectors.base import DetectorStatus
from backend.app.detectors.sender import detect_sender_impersonation
from backend.app.models import EmailPayload
from backend.app.parsing import parse_email_payload


def parsed_email(**overrides: object):
    data = {
        "subject": "Synthetic sender test",
        "from": "Example Support <support@example.test>",
        "reply_to": "",
        "text_body": "",
        "html_body": "",
        "headers": {},
        "attachment_metadata": [],
    }
    data.update(overrides)
    return parse_email_payload(EmailPayload.model_validate(data))


def result(**overrides: object):
    return detect_sender_impersonation(parsed_email(**overrides))


def test_triggers_low_severity_for_unrelated_reply_to_domain() -> None:
    detector_result = result(reply_to="Support Desk <case@service-desk.test>")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert len(detector_result.findings) == 1
    finding = detector_result.findings[0]
    assert finding.id == "sender_reply_to_domain_mismatch"
    assert finding.severity == "low"
    assert finding.contribution == 0
    assert "example.test" in finding.observation
    assert "service-desk.test" in finding.observation
    assert "legitimate" in finding.interpretation
    assert finding.evidence_id == "sender.reply_to_domain:example.test->service-desk.test"


def test_matching_from_and_reply_to_domains_do_not_trigger() -> None:
    detector_result = result(reply_to="Help <help@example.test>")

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_missing_reply_to_is_not_a_negative_finding() -> None:
    detector_result = result(reply_to="")

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_subdomain_differences_are_treated_as_legitimate_counterexamples() -> None:
    detector_result = result(
        **{
            "from": "Example Support <notice@mail.example.test>",
            "reply_to": "Help <case@support.example.test>",
        }
    )

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_marketing_or_delegated_reply_to_is_only_low_severity_supporting_evidence() -> None:
    detector_result = result(
        **{
            "from": "Example Newsletter <news@example.test>",
            "reply_to": "Example Newsletter <reply@marketing-platform.test>",
        }
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert detector_result.findings[0].severity == "low"
    assert detector_result.findings[0].contribution == 0
    assert "news@example.test" not in detector_result.findings[0].observation
    assert "marketing-platform.test" in detector_result.findings[0].observation


def test_display_name_does_not_need_to_match_mailbox_local_part() -> None:
    detector_result = result(**{"from": "Customer Support <noreply@example.test>"})

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_explicit_display_domain_claim_mismatch_triggers_grounded_finding() -> None:
    detector_result = result(**{"from": "example.test Security <alerts@security-example.test>"})

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert len(detector_result.findings) == 1
    finding = detector_result.findings[0]
    assert finding.id == "sender_display_domain_mismatch"
    assert finding.severity == "medium"
    assert finding.contribution == 0
    assert "example.test" in finding.observation
    assert "security-example.test" in finding.observation
    assert "reputation" not in finding.interpretation.lower()


def test_missing_from_is_inconclusive() -> None:
    detector_result = result(**{"from": ""})

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()
    assert any("From mailbox" in limitation for limitation in detector_result.limitations)


def test_malformed_from_is_inconclusive() -> None:
    detector_result = result(**{"from": "not an address"})

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()


def test_multiple_from_addresses_are_inconclusive() -> None:
    detector_result = result(**{"from": "a@example.test, b@example.test"})

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()


def test_malformed_reply_to_is_inconclusive() -> None:
    detector_result = result(reply_to="not an address")

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()
    assert any("Reply-To" in limitation for limitation in detector_result.limitations)


def test_unicode_and_punycode_domains_compare_after_idna_normalization() -> None:
    detector_result = result(
        **{
            "from": "Bücher <notice@bücher.example>",
            "reply_to": "Help <help@xn--bcher-kva.example>",
        }
    )

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_result_is_deterministic() -> None:
    first = result(reply_to="Help <help@other-example.test>")
    second = result(reply_to="Help <help@other-example.test>")

    assert first == second


def test_contract_fields_are_stable_and_unscored() -> None:
    detector_result = result(reply_to="Help <help@other-example.test>")

    assert detector_result.detector_id == "sender_identity"
    assert detector_result.implementation_version == "sender-0.1.0"
    assert detector_result.evidence_sources == ("from", "reply_to")
    assert detector_result.findings[0].evidence_sources == ("from", "reply_to")
    assert detector_result.findings[0].contribution == 0


def test_no_invented_brand_reputation_or_authentication_claims() -> None:
    detector_result = result(reply_to="Help <help@other-example.test>")
    combined_text = " ".join(
        [
            *detector_result.limitations,
            detector_result.findings[0].observation,
            detector_result.findings[0].interpretation,
        ]
    ).lower()

    assert "spf" not in combined_text
    assert "dkim" not in combined_text
    assert "dmarc" not in combined_text
    assert "reputation" not in detector_result.findings[0].observation.lower()
