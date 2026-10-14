from backend.app import engine
from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.engine import analyze_with_detectors
from backend.app.models import EmailPayload


def payload(**overrides: object) -> EmailPayload:
    data = {
        "subject": "Synthetic engine test",
        "from": "Example <notice@example.test>",
        "reply_to": "",
        "text_body": "",
        "html_body": "",
        "headers": {},
        "attachment_metadata": [],
    }
    data.update(overrides)
    return EmailPayload.model_validate(data)


def detector_map(result) -> dict[str, DetectorResult]:
    return {detector.detector_id: detector for detector in result.detector_results}


def finding_ids(result) -> list[str]:
    return [finding.id for finding in result.findings]


def test_all_implemented_detectors_run_for_valid_email() -> None:
    result = analyze_with_detectors(payload(text_body="Normal update with no links."))

    statuses = detector_map(result)
    assert list(statuses) == [
        "sender_identity",
        "url_deception",
        "credential_context",
        "attachment_metadata",
        "financial_fraud",
        "nlp_phishing",
    ]
    assert statuses["sender_identity"].status == DetectorStatus.NOT_TRIGGERED
    assert statuses["url_deception"].status == DetectorStatus.NOT_TRIGGERED
    assert statuses["credential_context"].status == DetectorStatus.NOT_TRIGGERED


def test_parser_is_invoked_once_per_analysis(monkeypatch) -> None:
    calls = 0
    original_parse = engine.parse_email_payload

    def counted_parse(email_payload):
        nonlocal calls
        calls += 1
        return original_parse(email_payload)

    monkeypatch.setattr(engine, "parse_email_payload", counted_parse)

    analyze_with_detectors(payload(text_body="Visit https://192.0.2.10/login and submit your password."))

    assert calls == 1


def test_findings_from_multiple_detectors_are_preserved() -> None:
    result = analyze_with_detectors(
        payload(
            **{"from": "accounts.example.test <alerts@attacker.test>"},
            text_body="Please submit your password to continue.",
            html_body=(
                '<a href="https://login.attacker.test/form">'
                "https://accounts.example.test/login</a>"
            ),
        )
    )

    ids = finding_ids(result)
    assert "sender_display_domain_mismatch" in ids
    assert "url_display_destination_mismatch" in ids
    assert "credential_secret_collection_request" in ids


def test_email_triggering_no_rules_preserves_completed_statuses() -> None:
    result = analyze_with_detectors(payload(text_body="Team lunch is at noon.", html_body="<p>Team lunch is at noon.</p>"))
    statuses = detector_map(result)

    assert result.findings == ()
    assert statuses["sender_identity"].status == DetectorStatus.NOT_TRIGGERED
    assert statuses["url_deception"].status == DetectorStatus.NOT_TRIGGERED
    assert statuses["credential_context"].status == DetectorStatus.NOT_TRIGGERED
    assert all(finding.contribution == 0 for finding in result.findings)


def test_missing_sender_data_does_not_prevent_available_checks() -> None:
    result = analyze_with_detectors(
        payload(
            **{"from": ""},
            text_body="Please enter your password to continue.",
            html_body='<a href="https://192.0.2.10/login">Sign in</a>',
        )
    )
    statuses = detector_map(result)

    assert statuses["sender_identity"].status == DetectorStatus.INCONCLUSIVE
    assert statuses["url_deception"].status == DetectorStatus.TRIGGERED
    assert statuses["credential_context"].status == DetectorStatus.TRIGGERED


def test_empty_input_is_not_falsely_reassuring() -> None:
    result = analyze_with_detectors(payload(subject="", text_body="", html_body="", **{"from": ""}))
    statuses = detector_map(result)

    assert statuses["sender_identity"].status == DetectorStatus.INCONCLUSIVE
    assert statuses["credential_context"].status == DetectorStatus.INCONCLUSIVE
    # No attachment information is not evidence of no attachments.
    assert statuses["attachment_metadata"].status == DetectorStatus.INCONCLUSIVE
    assert statuses["financial_fraud"].status == DetectorStatus.NOT_RUN
    assert "No security check was performed" in " ".join(result.limitations)


def test_malformed_evidence_does_not_become_clean_finding() -> None:
    result = analyze_with_detectors(payload(text_body="Open https://example.test:badport/login"))
    statuses = detector_map(result)

    assert statuses["url_deception"].status == DetectorStatus.INCONCLUSIVE
    assert statuses["url_deception"].findings == ()


def test_synthetic_email_can_trigger_multiple_independent_detectors() -> None:
    result = analyze_with_detectors(
        payload(
            **{"from": "service.example.test <notice@attacker.test>"},
            reply_to="Support <help@reply-attacker.test>",
            text_body="Urgent: enter your password within 12 hours to avoid account suspension.",
            html_body='<a href="https://192.0.2.10/login">Login</a>',
        )
    )

    statuses = detector_map(result)
    assert statuses["sender_identity"].status == DetectorStatus.TRIGGERED
    assert statuses["url_deception"].status == DetectorStatus.TRIGGERED
    assert statuses["credential_context"].status == DetectorStatus.TRIGGERED


def test_evidence_source_identities_remain_available_for_deduplication() -> None:
    result = analyze_with_detectors(
        payload(
            text_body="Please submit your password at https://192.0.2.10/login",
            html_body='<a href="https://192.0.2.10/login">Login</a>',
        )
    )

    assert "text_body" in result.evidence_sources
    assert result.findings
    assert all(finding.evidence_id for finding in result.findings)
    assert all(isinstance(finding.evidence_sources, tuple) for finding in result.findings)


def test_results_and_detector_ordering_are_deterministic() -> None:
    email = payload(text_body="Share your MFA code to avoid account suspension.")

    first = analyze_with_detectors(email)
    second = analyze_with_detectors(email)

    assert first == second
    assert [result.detector_id for result in first.detector_results] == [
        "sender_identity",
        "url_deception",
        "credential_context",
        "attachment_metadata",
        "financial_fraud",
        "nlp_phishing",
    ]


def test_engine_assigns_no_scores_or_verdicts() -> None:
    result = analyze_with_detectors(payload(text_body="Please submit your password."))

    assert not hasattr(result, "risk_score")
    assert not hasattr(result, "verdict")
    assert all(finding.contribution == 0 for finding in result.findings)


def test_unexpected_detector_failure_is_not_treated_as_clean(monkeypatch) -> None:
    def failing_detector(parsed_email):
        raise RuntimeError("synthetic failure with message content omitted")

    monkeypatch.setattr(
        engine,
        "IMPLEMENTED_DETECTORS",
        (engine.DetectorRunner("sender_identity", failing_detector),),
    )

    result = analyze_with_detectors(payload(text_body="Normal text."))
    sender_result = detector_map(result)["sender_identity"]

    assert sender_result.status == DetectorStatus.NOT_RUN
    assert sender_result.findings == ()
    assert "must not be treated as clean" in " ".join(sender_result.limitations)


def test_engine_does_not_use_network_fetching_or_html_execution(monkeypatch) -> None:
    calls: list[str] = []

    def inert_detector(parsed_email):
        calls.append("detector_ran")
        return DetectorResult(
            detector_id="synthetic_detector",
            status=DetectorStatus.TRIGGERED,
            findings=(
                DetectorFinding(
                    id="synthetic_finding",
                    severity="low",
                    title="Synthetic finding",
                    observation="Synthetic observation",
                    interpretation="Synthetic interpretation",
                    evidence_id="synthetic.evidence",
                    evidence_sources=("html_body",),
                    contribution=0,
                ),
            ),
        )

    monkeypatch.setattr(engine, "IMPLEMENTED_DETECTORS", (engine.DetectorRunner("synthetic_detector", inert_detector),))

    result = analyze_with_detectors(
        payload(
            html_body=(
                '<script>throw new Error("should not execute")</script>'
                '<img src="https://example.test/tracker.png">'
                '<a href="https://example.test/login">Login</a>'
            )
        )
    )

    assert calls == ["detector_ran"]
    assert finding_ids(result) == ["synthetic_finding"]
