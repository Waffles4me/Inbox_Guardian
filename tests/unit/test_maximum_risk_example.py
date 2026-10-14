"""Maximum-risk demonstration: the highest score Method C v1 can produce, reached with the current rules.

Method C sums each family's capped points and clamps the total to 100. The five family caps add up to 155
(20 + 40 + 25 + 35 + 35), so 100 is attainable with headroom. These tests pin the synthetic fixture in
``tests/fixtures/examples/maximum_risk.json`` to that result without changing any weight, cap or threshold.
"""

import ipaddress
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.engine import analyze_with_detectors
from backend.app.main import API_TOKEN_ENV, app
from backend.app.models import EmailPayload
from backend.app.scoring import FAMILY_CAPS, score_engine_result


FIXTURE = json.loads(Path("tests/fixtures/examples/maximum_risk.json").read_text(encoding="utf-8"))
ALL_FAMILIES = ("sender_identity", "url_deception", "credential_context", "attachment_metadata", "financial_fraud")


def score(email: dict):
    return score_engine_result(analyze_with_detectors(EmailPayload(**email)))


def capped_points(result) -> dict[str, int]:
    return {family.detector_id: family.capped_points for family in result.family_scores}


def credited(result) -> dict[str, int]:
    """Effective contribution per finding ID, summed, for findings that actually added points."""
    totals: dict[str, int] = {}
    for item in result.scored_findings:
        if item.effective_contribution > 0:
            totals[item.finding.id] = totals.get(item.finding.id, 0) + item.effective_contribution
    return totals


def test_family_caps_make_100_attainable() -> None:
    assert sum(FAMILY_CAPS.values()) == 155


def test_five_family_fixture_reaches_100_with_every_family_at_its_cap() -> None:
    result = score(FIXTURE["five_family_maximum"])

    assert result.risk_score == 100
    assert result.verdict == "HIGH_RISK"
    assert capped_points(result) == FAMILY_CAPS
    assert result.independent_evidence_families == ALL_FAMILIES
    assert credited(result) == {
        "sender_display_domain_mismatch": 20,
        "url_deceptive_subdomain": 35,
        "url_display_destination_mismatch": 5,
        "credential_secret_collection_request": 20,
        "credential_urgent_account_threat": 5,
        "attachment_deceptive_double_extension": 30,
        "attachment_executable_extension": 5,
        "financial_gift_card_code_request": 35,
    }


def test_gmail_reproducible_fixture_reaches_100_without_sender_or_executable_attachments() -> None:
    email = FIXTURE["gmail_reproducible"]
    result = score(email)

    assert result.risk_score == 100
    assert result.verdict == "HIGH_RISK"
    assert capped_points(result) == {
        "sender_identity": 0,
        "url_deception": 40,
        "credential_context": 25,
        "attachment_metadata": 10,
        "financial_fraud": 35,
    }
    assert result.independent_evidence_families == ("url_deception", "credential_context", "financial_fraud")

    # Without the harmless HTML attachment the three capped families still sum to exactly 100.
    without_attachment = dict(email, attachment_metadata=[], attachment_collection=dict(
        email["attachment_collection"], state="NONE", regular_count=0))
    bare = score(without_attachment)
    assert bare.risk_score == 100 and bare.verdict == "HIGH_RISK"


@pytest.mark.parametrize("name", ["five_family_maximum", "gmail_reproducible"])
def test_api_response_reports_100_without_external_enrichment(monkeypatch, name: str) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")
    response = TestClient(app).post(
        "/analyze",
        json={"schema_version": "1.0", "email": FIXTURE[name]},
        headers={"X-InboxGuardian-Token": "test-token"},
    )
    body = response.json()

    assert response.status_code == 200
    assert (body["risk_score"], body["verdict"]) == (100, "HIGH_RISK")
    assert body["detector_version"] == "engine-0.3.0+scoring-0.3.0"
    assert body["reputation_context"] == []
    assert sum(finding["contribution"] for finding in body["findings"]) >= 100


def test_fixture_uses_only_reserved_hosts() -> None:
    text = json.dumps(FIXTURE)
    for host in re.findall(r"@([A-Za-z0-9.-]+)|https?://([A-Za-z0-9.-]+)", text):
        name = host[0] or host[1]
        try:
            assert ipaddress.ip_address(name) in ipaddress.ip_network("192.0.2.0/24")
        except ValueError:
            assert name.endswith((".test", ".example")), name


def test_examples_scenario_10_single_sentence_payment_bypass_scores_25() -> None:
    result = score({
        "subject": "Updated payment instructions",
        "from": "Accounts <ap@vendor.example>",
        "text_body": "Send the invoice payment to our new bank account today and skip the usual callback verification.",
        "html_body": "",
        "attachment_metadata": [],
        "attachment_collection": {"state": "NONE", "regular_count": 0, "inline_count": 0, "omitted_count": 0,
                                  "omitted_extensions": [], "omitted_name_flags": [], "reasons": []},
    })

    assert (result.risk_score, result.verdict) == (25, "SUSPICIOUS")
    assert credited(result) == {"financial_verification_bypass_request": 25}
