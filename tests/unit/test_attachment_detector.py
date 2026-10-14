"""WBS 2.5 Stage 2: the attachment metadata detector, its scoring and its coverage states.

All names are synthetic. A name is metadata only: nothing here reads, opens or downloads attachment content.
"""

import json

import pytest
from fastapi.testclient import TestClient

from backend.app import scoring
from backend.app.detectors import attachments
from backend.app.detectors.attachments import RULE_CODES, detect_suspicious_attachments
from backend.app.detectors.base import DetectorStatus
from backend.app.engine import analyze_with_detectors
from backend.app.main import API_TOKEN_ENV, app
from backend.app.models import EmailPayload
from backend.app.parsing import parse_email_payload
from backend.app.scoring import score_engine_result


client = TestClient(app)
BASE_EMAIL = {
    "subject": "Synthetic attachment test",
    "from": "Accounts <accounts@supplier.example.test>",
    "text_body": "Hello, the document we discussed is attached. Regards, the accounts team.",
}
ATTACHMENT_FINDING_IDS = set(RULE_CODES)


def item(name: str = "agenda.pdf", **overrides) -> dict:
    data = {"filename": name, "content_type": "application/octet-stream", "size_bytes": 2048, "unavailable_fields": []}
    data.update(overrides)
    return data


def collected(*names: str) -> dict:
    return {"attachment_metadata": [item(name) for name in names], "attachment_collection": collection("COLLECTED", len(names))}


def collection(state: str, regular_count: int | None = 0, **overrides) -> dict:
    data = {
        "state": state,
        "regular_count": regular_count,
        "inline_count": 0,
        "omitted_count": 0,
        "omitted_extensions": [],
        "omitted_name_flags": [],
        "reasons": [],
    }
    data.update(overrides)
    return data


def clipped(head: str, tail: str, original_length: int = 400, **overrides) -> dict:
    return item(head + tail, name_clip={"at": len(head), "original_length": original_length, **overrides})


def payload(**email) -> EmailPayload:
    return EmailPayload.model_validate({**BASE_EMAIL, **email})


def detect(**email):
    return detect_suspicious_attachments(parse_email_payload(payload(**email)))


def finding_ids(result) -> list[str]:
    return [finding.id for finding in result.findings]


def score(**email):
    return score_engine_result(analyze_with_detectors(payload(**email)))


def attachment_family(result):
    return next(family for family in result.family_scores if family.detector_id == "attachment_metadata")


def credited(result) -> dict[str, int]:
    return {
        scored.finding.id: scored.effective_contribution
        for scored in result.scored_findings
        if scored.detector_id == "attachment_metadata" and scored.effective_contribution
    }


def analyze_api(monkeypatch, **email) -> dict:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")
    response = client.post(
        "/analyze",
        json={"schema_version": "1.0", "email": {**BASE_EMAIL, **email}},
        headers={"X-InboxGuardian-Token": "test-token"},
    )
    assert response.status_code == 200
    return response.json()


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("invoice.exe", ["attachment_executable_extension"]),
        ("INVOICE.EXE", ["attachment_executable_extension"]),
        ("setup.msi", ["attachment_executable_extension"]),
        ("run.ps1", ["attachment_script_extension"]),
        ("update.vbs", ["attachment_script_extension"]),
        ("start.cmd", ["attachment_script_extension"]),
        ("Scan_0012.lnk", ["attachment_script_extension"]),
        ("invoice.pdf.exe", ["attachment_deceptive_double_extension", "attachment_executable_extension"]),
        ("report.docx.scr", ["attachment_deceptive_double_extension", "attachment_executable_extension"]),
        ("photo.jpg.js", ["attachment_deceptive_double_extension", "attachment_script_extension"]),
        # Padding between the decoy and the real extension does not hide the pattern.
        ("invoice.pdf          .exe", ["attachment_deceptive_double_extension", "attachment_executable_extension"]),
        # Windows drops trailing dots and spaces, so the real extension is .exe.
        ("invoice.exe. .", ["attachment_executable_extension"]),
        ("statement.html", ["attachment_active_content_type"]),
        ("logo.svg", ["attachment_active_content_type"]),
        ("meeting-notes.one", ["attachment_active_content_type"]),
        ("memo.docm", ["attachment_macro_enabled_office"]),
        ("budget.xlsm", ["attachment_macro_enabled_office"]),
        ("deck.pptm", ["attachment_macro_enabled_office"]),
    ],
)
def test_listed_extensions_trigger_their_rule(name: str, expected: list[str]) -> None:
    result = detect(**collected(name))

    assert result.status == DetectorStatus.TRIGGERED
    assert finding_ids(result) == expected


def test_bidi_override_in_a_name_is_reported_with_the_real_extension() -> None:
    # Displays as "scanrcs.pdf"; the real extension is .scr.
    result = detect(**collected("scan‮fdp.scr"))

    assert finding_ids(result) == ["attachment_executable_extension", "attachment_bidi_control_name"]


@pytest.mark.parametrize("control", ["‪", "‫", "‬", "‭", "⁦", "⁧", "⁨", "⁩"])
def test_every_bidi_embedding_and_isolate_control_counts(control: str) -> None:
    assert finding_ids(detect(**collected(f"report{control}.pdf"))) == ["attachment_bidi_control_name"]


@pytest.mark.parametrize("hidden", ["​", "⁠", "﻿"])
def test_zero_width_characters_with_no_filename_use_are_reported(hidden: str) -> None:
    assert finding_ids(detect(**collected(f"pay{hidden}roll.pdf"))) == ["attachment_invisible_character_name"]


def test_zero_width_joiner_next_to_latin_text_is_reported() -> None:
    assert finding_ids(detect(**collected("in‍voice.pdf"))) == ["attachment_invisible_character_name"]


@pytest.mark.parametrize(
    "name",
    [
        "report.pdf",
        "proposal.docx",
        "notes.txt",
        "photo.jpg",
        "scan.png",
        "photos.zip",
        "backup.7z",
        "budget.xlsx",
        "legacy-template.doc",
        "דוח רבעוני.pdf",  # Hebrew
        "חשבונית‏ 2026.pdf",  # Hebrew with a right-to-left mark
        "فایل‌ها.pdf",  # Persian with a zero-width non-joiner
        "family\U0001f468‍\U0001f469.jpg",  # emoji joined with a zero-width joiner
        "site.url",  # internet shortcut: its target is inside the file, which is not read
        "data.xyz123",
        "no-extension",
        ".exe-notes.txt",
        "exe",
    ],
)
def test_ordinary_names_do_not_trigger(name: str) -> None:
    result = detect(**collected(name))

    assert result.status == DetectorStatus.NOT_TRIGGERED
    assert result.findings == ()


def test_mime_type_alone_is_never_scored() -> None:
    result = detect(
        attachment_metadata=[item("invoice.pdf", content_type="application/x-msdownload")],
        attachment_collection=collection("COLLECTED", 1),
    )

    assert result.status == DetectorStatus.NOT_TRIGGERED


def test_size_is_never_scored() -> None:
    for size in (0, 1, 50_000_000):
        assert detect(
            attachment_metadata=[item("report.pdf", size_bytes=size)], attachment_collection=collection("COLLECTED", 1)
        ).findings == ()


def test_control_characters_alone_are_not_scored() -> None:
    assert detect(**collected("report\u0007.pdf")).findings == ()


def test_invalid_unicode_in_a_name_is_rejected_without_echoing_it(monkeypatch) -> None:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")
    raw = (
        '{"schema_version": "1.0", "email": {"from": "a@example.test", "text_body": "x", '
        '"attachment_metadata": [{"filename": "ig-private\\ud800.exe"}]}}'
    )
    response = client.post(
        "/analyze",
        content=raw.encode("utf-8"),
        headers={"X-InboxGuardian-Token": "test-token", "Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert "ig-private" not in response.text


def test_every_rule_has_a_weight_and_a_rule_code() -> None:
    assert ATTACHMENT_FINDING_IDS <= set(scoring.FINDING_WEIGHTS)
    assert sorted(RULE_CODES.values()) == [f"ATT-0{number}" for number in range(1, 8)]
    assert not attachments.EXECUTABLE_EXTENSIONS & attachments.SCRIPT_EXTENSIONS
    extension_lists = (
        attachments.RUNNABLE_EXTENSIONS,
        attachments.ACTIVE_CONTENT_EXTENSIONS,
        attachments.MACRO_OFFICE_EXTENSIONS,
        attachments.DECOY_EXTENSIONS,
    )
    for index, first in enumerate(extension_lists):
        for second in extension_lists[index + 1 :]:
            assert not first & second


# ---------------------------------------------------------------------------
# Evidence and privacy
# ---------------------------------------------------------------------------

PRIVATE_NAMES = [
    "ig-private-salary.pdf.exe",
    "ig-private-board‮fdp.scr",
    "ig-private-pay​roll.xlsm",
    "ig-private-portal.html",
    "ig-private-סודי.ps1",
]


def test_findings_never_quote_a_filename_or_hidden_character(monkeypatch) -> None:
    body = analyze_api(
        monkeypatch,
        attachment_metadata=[item(name, content_type="application/x-ig-private-type") for name in PRIVATE_NAMES],
        attachment_collection=collection("COLLECTED", len(PRIVATE_NAMES)),
    )

    text = json.dumps(body, ensure_ascii=False)
    assert "ig-private" not in text
    assert "x-ig-private-type" not in text
    for hidden in ("‮", "​", "ס"):
        assert hidden not in text
    assert {finding["id"] for finding in body["findings"]} >= {
        "attachment_deceptive_double_extension",
        "attachment_bidi_control_name",
    }


def test_findings_are_explainable_and_do_not_claim_malware() -> None:
    names = ["invoice.pdf.exe", "run.ps1", "a‮b.pdf", "pay​roll.pdf", "page.html", "model.xlsm", "go.lnk"]
    result = detect(**collected(*names))

    assert set(finding_ids(result)) == ATTACHMENT_FINDING_IDS
    for finding in result.findings:
        assert finding.title and finding.observation and finding.interpretation
        assert finding.severity in {"low", "medium"}
        assert finding.evidence_sources == ("attachments",)
        assert finding.contribution == 0  # assigned by the scorer
        assert "not inspected" in finding.interpretation or "was not checked" in finding.interpretation
        lowered = f"{finding.observation} {finding.interpretation}".lower()
        assert "contains malware" not in lowered
        assert "is malicious" not in lowered
    double = next(finding for finding in result.findings if finding.id == "attachment_deceptive_double_extension")
    assert "(.pdf.exe)" in double.observation
    assert "attachment 1 in Gmail's list" in double.observation


# ---------------------------------------------------------------------------
# Coverage states
# ---------------------------------------------------------------------------


def test_none_is_not_triggered_but_a_legacy_request_is_inconclusive() -> None:
    none = detect(attachment_metadata=[], attachment_collection=collection("NONE"))
    legacy = detect()

    assert none.status == DetectorStatus.NOT_TRIGGERED
    assert legacy.status == DetectorStatus.INCONCLUSIVE
    assert "No attachment collection state was sent" in legacy.limitations[0]


def test_legacy_names_are_not_trusted_without_a_collection_state() -> None:
    result = detect(attachment_metadata=[item("invoice.exe")])

    assert result.status == DetectorStatus.INCONCLUSIVE
    assert result.findings == ()


def test_unavailable_is_inconclusive() -> None:
    result = detect(attachment_collection=collection("UNAVAILABLE", None, reasons=["collection_error"]))

    assert result.status == DetectorStatus.INCONCLUSIVE
    assert "could not be collected" in result.limitations[0]


def test_inconsistent_state_is_inconclusive_and_its_names_are_not_used() -> None:
    result = detect(attachment_metadata=[item("invoice.exe")], attachment_collection=collection("NONE"))

    assert result.status == DetectorStatus.INCONCLUSIVE
    assert result.findings == ()
    assert "inconsistent" in result.limitations[0]


def test_truncated_with_a_reliable_finding_is_triggered_and_discloses_the_gap() -> None:
    result = detect(
        attachment_metadata=[item("invoice.exe"), item("", unavailable_fields=["filename"])],
        attachment_collection=collection("TRUNCATED", 2, reasons=["field_unavailable"]),
    )

    assert result.status == DetectorStatus.TRIGGERED
    assert finding_ids(result) == ["attachment_executable_extension"]
    assert any("1 attachment names were unavailable" in line for line in result.limitations)


def test_truncated_without_a_reliable_finding_is_inconclusive() -> None:
    result = detect(
        attachment_metadata=[item("", unavailable_fields=["filename"])],
        attachment_collection=collection("TRUNCATED", 1, reasons=["field_unavailable"]),
    )

    assert result.status == DetectorStatus.INCONCLUSIVE
    assert result.findings == ()


def test_missing_type_and_size_do_not_stop_the_name_check() -> None:
    result = detect(
        attachment_metadata=[item("run.ps1", content_type="", size_bytes=None, unavailable_fields=["content_type", "size_bytes"])],
        attachment_collection=collection("TRUNCATED", 1, reasons=["field_unavailable"]),
    )

    assert result.status == DetectorStatus.TRIGGERED
    assert finding_ids(result) == ["attachment_script_extension"]


def test_exactly_twenty_five_transmitted_attachments_are_all_checked() -> None:
    names = [f"page-{index}.pdf" for index in range(24)] + ["setup.exe"]
    result = detect(**collected(*names))

    assert result.status == DetectorStatus.TRIGGERED
    assert [finding.evidence_id for finding in result.findings] == ["attachment:25"]


def test_more_than_twenty_five_listed_uses_the_omitted_extension_summary() -> None:
    names = [f"page-{index}.pdf" for index in range(25)]
    result = detect(
        attachment_metadata=[item(name) for name in names],
        attachment_collection=collection(
            "TRUNCATED", 30, omitted_count=5, omitted_extensions=["PDF", "exe", "js"], reasons=["count_limit"]
        ),
    )

    assert result.status == DetectorStatus.TRIGGERED
    assert finding_ids(result) == ["attachment_executable_extension", "attachment_script_extension"]
    assert {finding.evidence_id for finding in result.findings} == {"attachment:omitted"}
    assert "not sent individually" in result.findings[0].observation
    assert any("5 attachments were not sent individually" in line for line in result.limitations)


@pytest.mark.parametrize("malformed", [".exe", "exe ", "ex", "e​xe", "exe.pdf"])
def test_malformed_omitted_extensions_are_not_evidence(malformed: str) -> None:
    result = detect(
        attachment_metadata=[item("page.pdf")],
        attachment_collection=collection(
            "TRUNCATED", 2, omitted_count=1, omitted_extensions=[malformed], reasons=["count_limit"]
        ),
    )

    assert result.status == DetectorStatus.INCONCLUSIVE
    assert result.findings == ()


def test_omitted_flags_score_bidi_controls_but_not_ambiguous_zero_width() -> None:
    def omitted(flags: list[str]):
        return detect(
            attachment_metadata=[item("page.pdf")],
            attachment_collection=collection(
                "TRUNCATED", 2, omitted_count=1, omitted_name_flags=flags, reasons=["count_limit"]
            ),
        )

    assert finding_ids(omitted(["BIDI_CONTROL"])) == ["attachment_bidi_control_name"]
    assert omitted(["ZERO_WIDTH", "MULTIPLE_DOTS", "CONTROL_CHAR"]).findings == ()


def test_names_not_read_are_disclosed() -> None:
    result = detect(
        attachment_metadata=[item("page.pdf")],
        attachment_collection=collection("TRUNCATED", 3, omitted_count=2, reasons=["time_limit", "names_not_read"]),
    )

    assert result.status == DetectorStatus.INCONCLUSIVE
    assert any("could not be read at all" in line for line in result.limitations)


def test_a_double_extension_is_never_read_across_a_clip() -> None:
    # The kept head ends in ".pdf" and the kept tail is ".exe": they were not adjacent in the original name.
    result = detect(
        attachment_metadata=[clipped("statement.pdf", ".exe")],
        attachment_collection=collection("TRUNCATED", 1, reasons=["field_limit"]),
    )

    assert finding_ids(result) == ["attachment_executable_extension"]
    assert any("double extension that spans the shortened part" in line for line in result.limitations)


def test_whitespace_only_clip_still_does_not_join_head_and_tail() -> None:
    result = detect(
        attachment_metadata=[clipped("invoice.pdf" + " " * 53, " " * 10 + ".exe", removed_whitespace_only=True)],
        attachment_collection=collection("TRUNCATED", 1, reasons=["field_limit"]),
    )

    assert finding_ids(result) == ["attachment_executable_extension"]


def test_a_double_extension_wholly_inside_the_kept_tail_is_reported() -> None:
    result = detect(
        attachment_metadata=[clipped("A" * 64, "-quarterly-report.pdf.exe")],
        attachment_collection=collection("TRUNCATED", 1, reasons=["field_limit"]),
    )

    assert finding_ids(result) == ["attachment_deceptive_double_extension", "attachment_executable_extension"]


def test_a_clipped_name_keeps_a_verified_final_extension() -> None:
    result = detect(
        attachment_metadata=[clipped("B" * 64, "C" * 20 + ".xlsm")],
        attachment_collection=collection("TRUNCATED", 1, reasons=["field_limit"]),
    )

    assert finding_ids(result) == ["attachment_macro_enabled_office"]


@pytest.mark.parametrize(
    ("head", "tail", "original_length"),
    [
        ("invoice.exe", "    ", 400),  # a tail of spaces is dropped by Windows; the real extension is unknown
        ("invoice", ".exe", 11),  # the claimed original length leaves nothing removed
    ],
    ids=["whitespace-tail", "incoherent-length"],
)
def test_an_unreliable_clip_is_not_evaluated(head: str, tail: str, original_length: int) -> None:
    result = detect(
        attachment_metadata=[clipped(head, tail, original_length)],
        attachment_collection=collection("TRUNCATED", 1, reasons=["field_limit"]),
    )

    assert result.status == DetectorStatus.INCONCLUSIVE
    assert result.findings == ()


def test_bidi_control_in_a_clipped_out_middle_still_counts() -> None:
    result = detect(
        attachment_metadata=[clipped("D" * 64, "E" * 20 + ".pdf", removed_flags=["BIDI_CONTROL"])],
        attachment_collection=collection("TRUNCATED", 1, reasons=["field_limit"]),
    )

    assert finding_ids(result) == ["attachment_bidi_control_name"]


def test_zero_width_in_a_clipped_out_middle_is_disclosed_not_scored() -> None:
    result = detect(
        attachment_metadata=[clipped("F" * 64, "G" * 20 + ".pdf", removed_flags=["ZERO_WIDTH"])],
        attachment_collection=collection("TRUNCATED", 1, reasons=["field_limit"]),
    )

    assert result.findings == ()
    assert any("zero-width characters in a shortened-out part" in line for line in result.limitations)


def test_internal_failure_is_not_run_and_never_leaks_the_name(monkeypatch) -> None:
    def explode(attachment):
        raise RuntimeError("ig-private-name.exe")

    monkeypatch.setattr(attachments, "_read_name", explode)
    email = collected("ig-private-name.exe")
    engine_result = analyze_with_detectors(payload(**email))
    status = {result.detector_id: result for result in engine_result.detector_results}["attachment_metadata"]

    assert status.status == DetectorStatus.NOT_RUN
    assert "Internal failure type: RuntimeError." in status.limitations
    assert score_engine_result(engine_result).verdict == "INCOMPLETE"
    body = analyze_api(monkeypatch, **email)
    assert "ig-private-name" not in json.dumps(body)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def test_single_strong_finding_scores_its_weight() -> None:
    result = score(**collected("invoice.exe"))

    assert result.risk_score == 25
    assert result.verdict == "SUSPICIOUS"
    assert result.independent_evidence_families == ("attachment_metadata",)


def test_single_weak_finding_stays_below_the_suspicious_threshold() -> None:
    # Known V1 policy limitation: a weak finding is shown, but the verdict stays NO_SIGNIFICANT_SIGNALS.
    result = score(**collected("statement.html"))

    assert result.risk_score == 10
    assert result.verdict == "NO_SIGNIFICANT_SIGNALS"
    assert credited(result) == {"attachment_active_content_type": 10}
    assert result.independent_evidence_families == ()


def test_low_score_limitation_is_visible_in_the_response(monkeypatch) -> None:
    body = analyze_api(monkeypatch, **collected("budget.xlsm"))

    assert body["verdict"] == "NO_SIGNIFICANT_SIGNALS"
    assert body["risk_score"] == 10
    assert [(finding["id"], finding["contribution"]) for finding in body["findings"]] == [
        ("attachment_macro_enabled_office", 10)
    ]
    assert "do not open attachments" in body["recommended_action"]


def test_overlapping_rules_on_one_file_credit_only_the_strongest() -> None:
    result = score(**collected("invoice.pdf.exe"))

    assert result.risk_score == 30
    assert credited(result) == {"attachment_deceptive_double_extension": 30}
    suppressed = next(item for item in result.scored_findings if item.finding.id == "attachment_executable_extension")
    assert suppressed.effective_contribution == 0
    assert suppressed.accounting_note == "Suppressed because stronger finding covers the same evidence."


def test_bidi_and_executable_on_one_file_credit_only_the_strongest() -> None:
    assert score(**collected("scan‮fdp.scr")).risk_score == 25


def test_two_distinct_files_add_up_to_the_family_cap() -> None:
    result = score(**collected("invoice.exe", "run.ps1"))

    family = attachment_family(result)
    assert (family.raw_points, family.capped_points, family.cap) == (45, 35, 35)
    assert credited(result) == {"attachment_executable_extension": 25, "attachment_script_extension": 10}
    partial = next(item for item in result.scored_findings if item.finding.id == "attachment_script_extension")
    assert partial.accounting_note == "Partially reduced by detector-family cap."
    assert any("attachment_metadata contribution was capped from 45 to 35" in line for line in result.limitations)


def test_family_cap_is_thirty_five_however_many_files() -> None:
    result = score(**collected("a.pdf.exe", "b.docx.scr", "c.js", "d.vbs", "e.html", "f.xlsm"))

    assert result.risk_score == 35
    assert attachment_family(result).capped_points == 35
    # Every credited point belongs to a visible finding.
    assert sum(item.effective_contribution for item in result.scored_findings if item.counted) == 35


def test_cap_allocation_is_deterministic() -> None:
    names = ("c.js", "a.exe", "b.pdf.scr")
    first = score(**collected(*names))
    second = score(**collected(*names))

    assert [(item.finding.id, item.finding.evidence_id, item.effective_contribution) for item in first.scored_findings] == [
        (item.finding.id, item.finding.evidence_id, item.effective_contribution) for item in second.scored_findings
    ]
    assert {(item.finding.evidence_id, item.effective_contribution) for item in first.scored_findings if item.effective_contribution} == {
        ("attachment:3", 30),
        ("attachment:2", 5),
    }


def test_duplicate_metadata_entries_are_not_double_credited() -> None:
    result = score(**collected("invoice.exe", "invoice.exe", "invoice.exe"))

    assert result.risk_score == 25
    assert len(result.scored_findings) == 1
    engine_result = analyze_with_detectors(payload(**collected("invoice.exe", "invoice.exe")))
    detector = {item.detector_id: item for item in engine_result.detector_results}["attachment_metadata"]
    assert any("repeated an earlier entry exactly" in line for line in detector.limitations)


def test_same_name_with_different_sizes_counts_as_two_files() -> None:
    result = score(
        attachment_metadata=[item("invoice.exe", size_bytes=10), item("invoice.exe", size_bytes=20)],
        attachment_collection=collection("COLLECTED", 2),
    )

    assert result.risk_score == 35


def test_many_attachment_findings_are_still_one_independent_family() -> None:
    result = score(**collected("a.exe", "b.ps1", "c‮fdp.scr"))

    assert result.independent_evidence_families == ("attachment_metadata",)


DECEPTIVE_LINK_HTML = (
    '<p>Your statement is ready.</p><p><a href="https://coastlinebank-statements-view.test/open">'
    "https://online.coastlinebank.test/statements</a></p>"
)


def test_attachment_plus_separate_url_family_can_be_high_risk() -> None:
    result = score(html_body=DECEPTIVE_LINK_HTML, **collected("statement.pdf.exe"))

    assert result.independent_evidence_families == ("url_deception", "attachment_metadata")
    assert result.risk_score == 60
    assert result.verdict == "HIGH_RISK"


def test_attachment_plus_sender_family_scores_both() -> None:
    result = score(**{**collected("statement.pdf.scr"), "from": "accounts.coastlinebank.test <notice@mailer-hub.test>"})

    assert result.independent_evidence_families == ("sender_identity", "attachment_metadata")
    assert result.risk_score == 50
    assert result.verdict == "SUSPICIOUS"


def test_high_risk_still_needs_two_independent_families() -> None:
    # Weak attachment rules are not independent evidence, so 30 of them plus a 30-point link stay SUSPICIOUS.
    result = score(html_body=DECEPTIVE_LINK_HTML, **collected("a.html", "b.svg", "c.xlsm"))

    assert result.risk_score == 60
    assert result.independent_evidence_families == ("url_deception",)
    assert result.verdict == "SUSPICIOUS"


def test_existing_families_keep_their_weights_and_caps() -> None:
    assert {family: scoring.FAMILY_CAPS[family] for family in ("sender_identity", "url_deception", "credential_context")} == {
        "sender_identity": 20,
        "url_deception": 40,
        "credential_context": 25,
    }
    assert scoring.FAMILY_CAPS["attachment_metadata"] == 35
    assert scoring.CORRELATION_BONUS == 0
    assert scoring.SUSPICIOUS_THRESHOLD == 20


@pytest.mark.parametrize(
    "email",
    [
        {},
        {"attachment_metadata": [], "attachment_collection": collection("NONE")},
        {"attachment_collection": collection("UNAVAILABLE", None, reasons=["collection_error"])},
        {"attachment_metadata": [item("invoice.exe")], "attachment_collection": collection("NONE")},
        {
            "attachment_metadata": [item("", unavailable_fields=["filename"])],
            "attachment_collection": collection("TRUNCATED", 1, reasons=["field_unavailable"]),
        },
        collected("report.pdf", "notes.txt"),
    ],
    ids=["legacy", "none", "unavailable", "inconsistent", "truncated-unreadable", "collected-ordinary"],
)
def test_zero_point_outcomes_never_change_the_legacy_score_or_verdict(email: dict) -> None:
    legacy = score()
    result = score(**email)

    assert (result.risk_score, result.verdict, result.coverage.reasons) == (
        legacy.risk_score,
        legacy.verdict,
        legacy.coverage.reasons,
    )
    assert credited(result) == {}


def test_inconclusive_attachment_check_never_makes_a_clean_message_incomplete() -> None:
    result = score(attachment_collection=collection("UNAVAILABLE", None, reasons=["collection_error"]))

    assert result.verdict == "NO_SIGNIFICANT_SIGNALS"
