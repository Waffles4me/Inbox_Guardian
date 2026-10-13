from backend.app.detectors.base import DetectorStatus
from backend.app.detectors.urls import detect_deceptive_urls
from backend.app.models import EmailPayload
from backend.app.parsing import parse_email_payload


def parsed_email(**overrides: object):
    data = {
        "subject": "Synthetic URL test",
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
    return detect_deceptive_urls(parsed_email(**overrides))


def finding_ids(detector_result) -> list[str]:
    return [finding.id for finding in detector_result.findings]


def test_displayed_domain_and_destination_mismatch_triggers() -> None:
    detector_result = result(
        html_body='<a href="https://different.example.test/login">https://accounts.example.test/login</a>'
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert finding_ids(detector_result) == ["url_display_destination_mismatch"]
    finding = detector_result.findings[0]
    assert finding.contribution == 0
    assert "accounts.example.test" in finding.observation
    assert "different.example.test" in finding.observation
    assert "legitimate tracking" in finding.interpretation


def test_matching_displayed_and_destination_domain_does_not_trigger() -> None:
    detector_result = result(
        html_body='<a href="https://accounts.example.test/login?token=secret">'
        "https://accounts.example.test/login</a>"
    )

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_hostname_comparison_is_case_insensitive_after_normalization() -> None:
    detector_result = result(
        html_body='<a href="https://ACCOUNTS.EXAMPLE.TEST/login">https://accounts.example.test/login</a>'
    )

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_deceptive_subdomain_structure_triggers_when_visible_claim_exists() -> None:
    detector_result = result(
        html_body='<a href="https://accounts.example.test.attacker.test/login">'
        "https://accounts.example.test/login</a>"
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert finding_ids(detector_result) == ["url_deceptive_subdomain"]
    assert "accounts.example.test.attacker.test" in detector_result.findings[0].observation


def test_hyphenated_lookalike_is_different_host_not_subdomain() -> None:
    detector_result = result(
        html_body='<a href="https://accounts-example.test/login">https://accounts.example.test/login</a>'
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert finding_ids(detector_result) == ["url_display_destination_mismatch"]


def test_legitimate_subdomain_relationship_does_not_trigger_mismatch() -> None:
    detector_result = result(
        html_body='<a href="https://login.example.test/login">https://example.test/login</a>'
    )

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_additional_deceptive_prefix_domain_triggers() -> None:
    detector_result = result(
        html_body='<a href="https://accounts.example.test.evil.test/login">'
        "https://accounts.example.test/login</a>"
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert finding_ids(detector_result) == ["url_deceptive_subdomain"]


def test_substring_domain_is_not_treated_as_subdomain() -> None:
    detector_result = result(
        html_body='<a href="https://otherexample.test/login">https://example.test/login</a>'
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert finding_ids(detector_result) == ["url_display_destination_mismatch"]


def test_prefix_domain_under_attacker_is_not_treated_as_owned_subdomain() -> None:
    detector_result = result(
        html_body='<a href="https://example.test.attacker.test/login">https://example.test/login</a>'
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert finding_ids(detector_result) == ["url_deceptive_subdomain"]


def test_ip_address_host_triggers_low_severity() -> None:
    detector_result = result(text_body="Review http://192.0.2.10:8080/status")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert finding_ids(detector_result) == ["url_ip_address_host"]
    assert detector_result.findings[0].severity == "low"
    assert detector_result.findings[0].contribution == 0


def test_userinfo_hostname_triggers_on_actual_destination_host() -> None:
    detector_result = result(text_body="Open https://accounts.example.test@attacker.test/login")

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert finding_ids(detector_result) == ["url_userinfo_hostname"]
    assert "accounts.example.test" in detector_result.findings[0].observation
    assert "attacker.test" in detector_result.findings[0].observation


def test_normal_https_link_does_not_trigger() -> None:
    detector_result = result(text_body="Read https://docs.example.test/help?section=login")

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_legitimate_tracking_link_with_non_url_text_does_not_trigger() -> None:
    detector_result = result(
        html_body='<a href="https://click.marketing-platform.test/track?id=abc">Read the newsletter</a>'
    )

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_legitimate_redirect_style_url_is_not_flagged_without_claimed_host() -> None:
    detector_result = result(
        text_body="Continue at https://redirect.example.test/?url=https%3A%2F%2Fservice.example.test"
    )

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_missing_url_returns_not_triggered_with_limitation() -> None:
    detector_result = result(text_body="No links here.", html_body="<p>No links here.</p>")

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()
    assert any("No supported URL evidence" in limitation for limitation in detector_result.limitations)


def test_missing_html_body_with_plain_text_url_still_evaluates() -> None:
    detector_result = result(text_body="Visit https://example.test/login", html_body="")

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.evidence_sources == ("text_body",)


def test_malformed_url_evidence_is_inconclusive() -> None:
    detector_result = result(text_body="Open https://example.test:badport/login")

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()


def test_unsupported_scheme_evidence_is_inconclusive() -> None:
    detector_result = result(html_body='<a href="mailto:help@example.test">Email support</a>')

    assert detector_result.status == DetectorStatus.INCONCLUSIVE
    assert detector_result.findings == ()
    assert detector_result.evidence_sources == ("html_body",)


def test_unicode_and_idna_hosts_normalize_before_matching() -> None:
    detector_result = result(
        html_body='<a href="https://xn--bcher-kva.example/login">https://bücher.example/login</a>'
    )

    assert detector_result.status == DetectorStatus.NOT_TRIGGERED
    assert detector_result.findings == ()


def test_duplicate_url_evidence_produces_one_finding() -> None:
    detector_result = result(
        text_body="http://192.0.2.10/a http://192.0.2.10/a",
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    assert finding_ids(detector_result) == ["url_ip_address_host"]


def test_sensitive_query_parameter_is_not_exposed_in_observation() -> None:
    detector_result = result(
        html_body='<a href="https://different.example.test/login?token=secret">'
        "https://accounts.example.test/login?token=secret</a>"
    )

    assert detector_result.status == DetectorStatus.TRIGGERED
    observation = detector_result.findings[0].observation
    assert "token=secret" not in observation
    assert "different.example.test" in observation


def test_deterministic_finding_ids_status_and_contract_fields() -> None:
    first = result(text_body="Open https://accounts.example.test@attacker.test/login")
    second = result(text_body="Open https://accounts.example.test@attacker.test/login")

    assert first == second
    assert first.detector_id == "url_deception"
    assert first.status == DetectorStatus.TRIGGERED
    assert first.implementation_version == "urls-0.1.0"
    assert first.findings[0].id == "url_userinfo_hostname"
    assert first.findings[0].evidence_sources == ("text_body",)
    assert first.findings[0].contribution == 0
