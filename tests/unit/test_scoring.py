from copy import deepcopy

import pytest

from backend.app.detectors.base import DetectorFinding, DetectorResult, DetectorStatus
from backend.app.engine import EngineResult
from backend.app.models import EmailPayload
from backend.app.parsing import parse_email_payload
from backend.app import scoring
from backend.app.scoring import score_engine_result


def payload(**overrides: object) -> EmailPayload:
    data = {
        "subject": "Synthetic scoring test",
        "from": "Example <notice@example.test>",
        "reply_to": "",
        "text_body": "Ordinary message content.",
        "html_body": "",
        "headers": {},
        "attachment_metadata": [],
    }
    data.update(overrides)
    return EmailPayload.model_validate(data)


def finding(finding_id: str, evidence_id: str | None = None, sources: tuple[str, ...] = ("text_body",)) -> DetectorFinding:
    return DetectorFinding(
        id=finding_id,
        severity="medium",
        title=f"Synthetic {finding_id}",
        observation="Synthetic observation with no private content.",
        interpretation="Synthetic interpretation.",
        evidence_id=evidence_id or f"evidence:{finding_id}",
        evidence_sources=sources,
        contribution=0,
    )


def detector(detector_id: str, *findings: DetectorFinding, status: DetectorStatus | None = None) -> DetectorResult:
    if status is None:
        status = DetectorStatus.TRIGGERED if findings else DetectorStatus.NOT_TRIGGERED
    return DetectorResult(
        detector_id=detector_id,
        status=status,
        findings=tuple(findings),
        evidence_sources=tuple(dict.fromkeys(source for item in findings for source in item.evidence_sources)),
        limitations=(),
        implementation_version="synthetic-test",
    )


def planned(detector_id: str) -> DetectorResult:
    return DetectorResult(
        detector_id=detector_id,
        status=DetectorStatus.NOT_RUN,
        limitations=("planned detector not implemented",),
        implementation_version="not-implemented",
    )


def engine_result(
    *detectors: DetectorResult,
    email: EmailPayload | None = None,
    limitations: tuple[str, ...] = (),
) -> EngineResult:
    by_id = {item.detector_id: item for item in detectors}
    ordered = [
        by_id.get("sender_identity", detector("sender_identity")),
        by_id.get("url_deception", detector("url_deception")),
        by_id.get("credential_context", detector("credential_context")),
        # A request without attachment collection leaves the attachment check inconclusive.
        by_id.get("attachment_metadata", detector("attachment_metadata", status=DetectorStatus.INCONCLUSIVE)),
        planned("financial_fraud"),
        planned("nlp_phishing"),
    ]
    parsed = parse_email_payload(email or payload())
    return EngineResult(
        parsed_email=parsed,
        detector_results=tuple(ordered),
        findings=tuple(finding for item in ordered for finding in item.findings),
        evidence_sources=tuple(dict.fromkeys(source for item in ordered for source in item.evidence_sources)),
        limitations=limitations,
        parse_issues=parsed.issues,
    )


def score_for(*detectors: DetectorResult, email: EmailPayload | None = None):
    return score_engine_result(engine_result(*detectors, email=email))


def test_no_findings_with_sufficient_coverage_scores_zero() -> None:
    result = score_for()

    assert result.risk_score == 0
    assert result.verdict == "NO_SIGNIFICANT_SIGNALS"


def test_sender_reply_to_mismatch_scores_five() -> None:
    result = score_for(detector("sender_identity", finding("sender_reply_to_domain_mismatch")))

    assert result.risk_score == 5
    assert result.verdict == "NO_SIGNIFICANT_SIGNALS"


def test_sender_display_domain_mismatch_scores_twenty() -> None:
    result = score_for(detector("sender_identity", finding("sender_display_domain_mismatch")))

    assert result.risk_score == 20
    assert result.verdict == "SUSPICIOUS"


def test_deceptive_url_mismatch_scores_thirty() -> None:
    result = score_for(detector("url_deception", finding("url_display_destination_mismatch")))

    assert result.risk_score == 30
    assert result.verdict == "SUSPICIOUS"


def test_deceptive_subdomain_scores_thirty_five() -> None:
    result = score_for(detector("url_deception", finding("url_deceptive_subdomain")))

    assert result.risk_score == 35


def test_literal_ip_host_scores_five() -> None:
    result = score_for(detector("url_deception", finding("url_ip_address_host")))

    assert result.risk_score == 5


def test_explicit_credential_collection_scores_twenty() -> None:
    result = score_for(detector("credential_context", finding("credential_secret_collection_request")))

    assert result.risk_score == 20
    assert result.verdict == "SUSPICIOUS"


def test_contextual_credential_with_link_scores_zero() -> None:
    result = score_for(detector("credential_context", finding("credential_request_with_link")))

    assert result.risk_score == 0
    assert result.scored_findings[0].effective_contribution == 0


def test_multiple_independent_families_sum_correctly() -> None:
    result = score_for(
        detector("sender_identity", finding("sender_display_domain_mismatch")),
        detector("url_deception", finding("url_deceptive_subdomain")),
        detector("credential_context", finding("credential_secret_collection_request")),
    )

    assert result.risk_score == 75
    assert result.verdict == "HIGH_RISK"


def test_category_caps_limit_family_contribution() -> None:
    result = score_for(
        detector(
            "credential_context",
            finding("credential_secret_collection_request"),
            finding("credential_security_bypass_instruction"),
            finding("credential_urgent_account_threat"),
        )
    )

    assert result.family_scores[2].raw_points == 50
    assert result.family_scores[2].capped_points == 25
    assert result.risk_score == 25


def test_maximum_current_total_is_eighty_five() -> None:
    result = score_for(
        detector(
            "sender_identity",
            finding("sender_display_domain_mismatch"),
            finding("sender_reply_to_domain_mismatch"),
        ),
        detector(
            "url_deception",
            finding("url_deceptive_subdomain", "url.deceptive_subdomain:a.test->b.test"),
            finding("url_userinfo_hostname", "url.userinfo:a.test->b.test"),
        ),
        detector(
            "credential_context",
            finding("credential_secret_collection_request"),
            finding("credential_security_bypass_instruction"),
            finding("credential_urgent_account_threat"),
        ),
    )

    assert [family.capped_points for family in result.family_scores] == [20, 40, 25, 0]
    assert result.risk_score == 85


def test_duplicate_evidence_ids_are_not_counted_twice() -> None:
    duplicate = "sender.display_domain:example.test->attacker.test"
    result = score_for(
        detector(
            "sender_identity",
            finding("sender_display_domain_mismatch", duplicate),
            finding("sender_display_domain_mismatch", duplicate),
        )
    )

    assert result.risk_score == 20
    assert [item.effective_contribution for item in result.scored_findings] == [20, 0]


def test_multiple_rules_for_same_deceptive_link_keep_strongest() -> None:
    result = score_for(
        detector(
            "url_deception",
            finding("url_display_destination_mismatch", "url.display_mismatch:accounts.example.test->evil.test"),
            finding("url_deceptive_subdomain", "url.deceptive_subdomain:accounts.example.test->evil.test"),
        )
    )

    assert result.risk_score == 35
    assert [item.effective_contribution for item in result.scored_findings] == [0, 35]


def test_credential_with_link_context_does_not_duplicate_url_evidence() -> None:
    result = score_for(
        detector("url_deception", finding("url_display_destination_mismatch")),
        detector(
            "credential_context",
            finding("credential_secret_collection_request"),
            finding("credential_request_with_link"),
        ),
    )

    assert result.risk_score == 50
    assert result.correlation_bonus == 0
    assert [item.effective_contribution for item in result.scored_findings] == [30, 20, 0]


def test_distinct_evidence_from_multiple_families_is_retained() -> None:
    result = score_for(
        detector("sender_identity", finding("sender_display_domain_mismatch")),
        detector("url_deception", finding("url_userinfo_hostname")),
    )

    assert result.risk_score == 50
    assert result.independent_evidence_families == ("sender_identity", "url_deception")


def test_zero_correlation_bonus_is_applied() -> None:
    result = score_for(
        detector("sender_identity", finding("sender_display_domain_mismatch")),
        detector("url_deception", finding("url_display_destination_mismatch")),
    )

    assert result.correlation_bonus == 0
    assert result.risk_score == 50


def test_effective_contributions_reconcile_with_final_score() -> None:
    result = score_for(
        detector(
            "url_deception",
            finding("url_deceptive_subdomain", "url.deceptive_subdomain:a.test->b.test"),
            finding("url_userinfo_hostname", "url.userinfo:a.test->b.test"),
        )
    )

    assert sum(item.effective_contribution for item in result.scored_findings) == result.risk_score


def test_input_engine_findings_remain_unchanged_after_scoring() -> None:
    source = engine_result(detector("credential_context", finding("credential_secret_collection_request")))
    original = deepcopy(source)

    score_engine_result(source)

    assert source == original
    assert source.findings[0].contribution == 0


def test_score_19_boundary_is_no_significant_signals(monkeypatch) -> None:
    monkeypatch.setitem(scoring.FINDING_WEIGHTS, "synthetic_nineteen", 19)
    monkeypatch.setitem(scoring.FAMILY_CAPS, "sender_identity", 20)
    result = score_for(detector("sender_identity", finding("synthetic_nineteen")))

    assert result.risk_score == 19
    assert result.verdict == "NO_SIGNIFICANT_SIGNALS"


def test_score_20_boundary_is_suspicious() -> None:
    result = score_for(detector("sender_identity", finding("sender_display_domain_mismatch")))

    assert result.risk_score == 20
    assert result.verdict == "SUSPICIOUS"


def test_score_59_boundary_is_suspicious(monkeypatch) -> None:
    monkeypatch.setitem(scoring.FINDING_WEIGHTS, "synthetic_59", 59)
    monkeypatch.setitem(scoring.FAMILY_CAPS, "sender_identity", 100)
    result = score_for(detector("sender_identity", finding("synthetic_59")))

    assert result.risk_score == 59
    assert result.verdict == "SUSPICIOUS"


def test_score_60_with_two_independent_families_is_high_risk() -> None:
    result = score_for(
        detector("sender_identity", finding("sender_display_domain_mismatch")),
        detector(
            "url_deception",
            finding("url_deceptive_subdomain", "url.deceptive_subdomain:a.test->b.test"),
            finding("url_userinfo_hostname", "url.userinfo:a.test->b.test"),
        ),
    )

    assert result.risk_score == 60
    assert result.verdict == "HIGH_RISK"


def test_score_at_least_60_without_independence_is_suspicious(monkeypatch) -> None:
    monkeypatch.setitem(scoring.FAMILY_CAPS, "sender_identity", 100)
    result = score_for(
        detector(
            "sender_identity",
            finding("sender_display_domain_mismatch", "sender.display_domain:a->b"),
            finding("sender_display_domain_mismatch", "sender.display_domain:c->d"),
            finding("sender_display_domain_mismatch", "sender.display_domain:e->f"),
        )
    )

    assert result.risk_score == 60
    assert result.independent_evidence_families == ("sender_identity",)
    assert result.verdict == "SUSPICIOUS"


def test_missing_essential_sender_and_content_is_incomplete() -> None:
    result = score_for(email=payload(subject="", text_body="", html_body="", **{"from": ""}))

    assert result.verdict == "INCOMPLETE"
    assert result.coverage.reasons


def test_missing_reply_to_alone_does_not_force_incomplete() -> None:
    result = score_for(email=payload(reply_to=""))

    assert result.verdict == "NO_SIGNIFICANT_SIGNALS"


def test_missing_html_or_urls_alone_does_not_force_incomplete() -> None:
    result = score_for(email=payload(html_body="", text_body="Plain text content with no links."))

    assert result.verdict == "NO_SIGNIFICANT_SIGNALS"


@pytest.mark.parametrize(
    "bodies",
    [
        {"text_body": "", "html_body": ""},
        {"text_body": "  \n\t ", "html_body": " \n "},
        {"text_body": "", "html_body": '<div><img src="cid:synthetic"></div>'},
        {"text_body": "", "html_body": '<a href="mailto:help@example.test"></a>'},
    ],
    ids=["empty", "whitespace-only", "image-only", "unsupported-link-only"],
)
def test_subject_without_usable_body_is_incomplete(bodies: dict[str, str]) -> None:
    result = score_for(email=payload(**bodies))

    assert result.risk_score == 0
    assert result.verdict == "INCOMPLETE"
    assert result.coverage.sufficient_for_no_significant_signals is False
    assert len(result.coverage.reasons) == 1
    assert "only the subject line" in result.coverage.reasons[0]


@pytest.mark.parametrize(
    "fields",
    [
        {"subject": "", "text_body": "Ordinary message content."},
        {"text_body": "", "html_body": "<p>Ordinary message content.</p>"},
        {"text_body": "Ordinary message content.", "html_body": ""},
        {"text_body": "", "html_body": '<a href="https://docs.example.test/help"><img src="cid:synthetic"></a>'},
        {"text_body": "https://docs.example.test/help", "html_body": ""},
    ],
    ids=["no-subject", "html-only", "text-only", "html-link-only", "text-link-only"],
)
def test_usable_body_or_supported_link_keeps_meaningful_verdict(fields: dict[str, str]) -> None:
    result = score_for(email=payload(**fields))

    assert result.verdict == "NO_SIGNIFICANT_SIGNALS"
    assert result.coverage.reasons == ()


def test_inconclusive_detectors_on_usable_content_do_not_force_incomplete() -> None:
    result = score_for(
        detector("url_deception", status=DetectorStatus.INCONCLUSIVE),
        detector("credential_context", status=DetectorStatus.INCONCLUSIVE),
    )

    assert result.verdict == "NO_SIGNIFICANT_SIGNALS"


def test_subject_only_positive_finding_at_threshold_remains_suspicious() -> None:
    result = score_for(
        detector("credential_context", finding("credential_secret_collection_request", sources=("subject",))),
        email=payload(text_body="", html_body=""),
    )

    assert result.risk_score == 20
    assert result.verdict == "SUSPICIOUS"
    assert result.coverage.reasons == ()


def test_subject_only_low_finding_is_incomplete_with_finding_preserved() -> None:
    result = score_for(
        detector("sender_identity", finding("sender_reply_to_domain_mismatch", sources=("from", "reply_to"))),
        email=payload(text_body="", html_body=""),
    )

    assert result.verdict == "INCOMPLETE"
    assert [(item.finding.id, item.effective_contribution) for item in result.scored_findings] == [
        ("sender_reply_to_domain_mismatch", 5)
    ]
    assert "only the subject line" in result.coverage.reasons[0]


def test_missing_sender_with_low_score_explains_incomplete() -> None:
    result = score_for(
        detector("sender_identity", status=DetectorStatus.INCONCLUSIVE),
        detector("url_deception", finding("url_ip_address_host")),
        email=payload(text_body="Status page http://192.0.2.10/a", **{"from": ""}),
    )

    assert result.risk_score == 5
    assert result.verdict == "INCOMPLETE"
    assert any("sender identity" in reason for reason in result.coverage.reasons)


def gap_detector(*findings: DetectorFinding) -> DetectorResult:
    return DetectorResult(
        detector_id="credential_context",
        status=DetectorStatus.TRIGGERED if findings else DetectorStatus.INCONCLUSIVE,
        findings=tuple(findings),
        implementation_version="synthetic-test",
        coverage_gaps=("Synthetic forwarded content was not assessed.",),
    )


def test_detector_coverage_gap_without_sufficient_evidence_is_incomplete() -> None:
    result = score_for(gap_detector())

    assert result.risk_score == 0
    assert result.verdict == "INCOMPLETE"
    assert result.coverage.reasons == ("Synthetic forwarded content was not assessed.",)


def test_detector_coverage_gap_keeps_low_findings_but_stays_incomplete() -> None:
    result = score_for(
        gap_detector(),
        detector("sender_identity", finding("sender_reply_to_domain_mismatch", sources=("from", "reply_to"))),
    )

    assert result.verdict == "INCOMPLETE"
    assert [(item.finding.id, item.effective_contribution) for item in result.scored_findings] == [
        ("sender_reply_to_domain_mismatch", 5)
    ]


def test_detector_coverage_gap_does_not_override_positive_evidence() -> None:
    from_active_text = score_for(gap_detector(finding("credential_secret_collection_request")))
    from_other_family = score_for(gap_detector(), detector("url_deception", finding("url_deceptive_subdomain")))

    assert (from_active_text.verdict, from_active_text.risk_score) == ("SUSPICIOUS", 20)
    assert (from_other_family.verdict, from_other_family.risk_score) == ("SUSPICIOUS", 35)
    assert from_active_text.coverage.reasons == ()
    assert from_other_family.coverage.reasons == ()


def test_unimplemented_families_are_limitations_not_clean_evidence() -> None:
    result = score_for()

    assert result.risk_score == 0
    assert any("financial_fraud" in limitation for limitation in result.limitations)
    assert not any("attachment_metadata is planned" in limitation for limitation in result.limitations)
    assert result.verdict == "NO_SIGNIFICANT_SIGNALS"


def test_unexpected_detector_failure_returns_incomplete_not_clean() -> None:
    result = score_for(
        detector(
            "url_deception",
            status=DetectorStatus.NOT_RUN,
        )
    )

    assert result.verdict == "INCOMPLETE"
    assert result.risk_score == 0


def test_legitimate_password_reset_is_not_high_risk() -> None:
    result = score_for(
        detector("credential_context", status=DetectorStatus.INCONCLUSIVE),
        email=payload(text_body="You requested a password reset. We will never ask for your password."),
    )

    assert result.verdict in {"NO_SIGNIFICANT_SIGNALS", "INCOMPLETE"}


def test_delegated_sender_example_is_not_high_risk() -> None:
    result = score_for(detector("sender_identity", finding("sender_reply_to_domain_mismatch")))

    assert result.risk_score == 5
    assert result.verdict != "HIGH_RISK"


def test_unknown_finding_ids_are_not_given_invented_weights() -> None:
    result = score_for(detector("url_deception", finding("unknown_future_rule")))

    assert result.risk_score == 0
    assert result.scored_findings[0].approved_weight == 0
    assert "unknown finding" in result.scored_findings[0].accounting_note.lower()


def test_inconsistent_detector_output_is_incomplete() -> None:
    result = score_for(
        detector(
            "sender_identity",
            finding("sender_display_domain_mismatch"),
            status=DetectorStatus.NOT_TRIGGERED,
        )
    )

    assert result.verdict == "INCOMPLETE"
    assert result.risk_score == 20


def test_scored_finding_ordering_is_deterministic() -> None:
    first = score_for(
        detector("sender_identity", finding("sender_display_domain_mismatch")),
        detector("url_deception", finding("url_display_destination_mismatch")),
    )
    second = score_for(
        detector("sender_identity", finding("sender_display_domain_mismatch")),
        detector("url_deception", finding("url_display_destination_mismatch")),
    )

    assert [item.finding.id for item in first.scored_findings] == [item.finding.id for item in second.scored_findings]


def test_scoring_accounting_does_not_add_sensitive_values_to_explanations() -> None:
    result = score_for(
        detector(
            "url_deception",
            finding("url_display_destination_mismatch", "url.display_mismatch:example.test->evil.test?token=secret"),
        )
    )

    generated_text = " ".join(
        [item.accounting_note for item in result.scored_findings] + list(result.limitations)
    )
    assert "token=secret" not in generated_text


def test_scoring_uses_no_network_or_external_services(monkeypatch) -> None:
    calls: list[str] = []

    def forbidden(*args, **kwargs):
        calls.append("network")
        raise AssertionError("network should not be used")

    monkeypatch.setattr("socket.create_connection", forbidden)

    result = score_for(detector("url_deception", finding("url_display_destination_mismatch")))

    assert result.risk_score == 30
    assert calls == []
