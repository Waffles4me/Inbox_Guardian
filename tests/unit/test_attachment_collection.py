"""WBS 2.5 Stage 1: attachment metadata collection contract.

Attachment metadata is parsed and reported, but no attachment check exists yet: the attachment family stays a
planned NOT_RUN detector and nothing here may change a score or verdict.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app.detectors.base import DetectorStatus
from backend.app.engine import analyze_with_detectors
from backend.app.main import API_TOKEN_ENV, app
from backend.app.models import AnalyzeRequest, EmailPayload
from backend.app.parsing import AttachmentCollectionState, EvidenceSource, parse_email_payload
from backend.app.scoring import score_engine_result


client = TestClient(app)
CASES = json.loads(Path("tests/fixtures/evaluation/cases.json").read_text(encoding="utf-8"))["cases"]
BASE_EMAIL = {
    "subject": "Synthetic attachment test",
    "from": "Example <notice@example.test>",
    "text_body": "Please find the agenda attached.",
}
PRIVATE_NAME = "ig-private-salary-review.pdf"
NAMES_ONLY = "Only attachment names were checked; attachment content was not inspected."


def item(name: str = "ig-agenda.pdf", **overrides) -> dict:
    data = {"filename": name, "content_type": "application/pdf", "size_bytes": 1024, "unavailable_fields": []}
    data.update(overrides)
    return data


def collection(state: str, **overrides) -> dict:
    data = {
        "state": state,
        "regular_count": 0,
        "inline_count": 0,
        "omitted_count": 0,
        "omitted_extensions": [],
        "omitted_name_flags": [],
        "reasons": [],
    }
    data.update(overrides)
    return data


def parse(items: list[dict] | None = None, attachment_collection: dict | None = None, **email):
    data = {**BASE_EMAIL, **email, "attachment_metadata": items or []}
    if attachment_collection is not None:
        data["attachment_collection"] = attachment_collection
    return parse_email_payload(EmailPayload.model_validate(data))


def analyze(monkeypatch, items: list[dict] | None = None, attachment_collection: dict | None = None, **email) -> dict:
    monkeypatch.setenv(API_TOKEN_ENV, "test-token")
    data = {**BASE_EMAIL, **email, "attachment_metadata": items or []}
    if attachment_collection is not None:
        data["attachment_collection"] = attachment_collection
    response = client.post(
        "/analyze",
        json={"schema_version": "1.0", "email": data},
        headers={"X-InboxGuardian-Token": "test-token"},
    )
    assert response.status_code == 200
    return response.json()


def attachment_issues(parsed) -> list[str]:
    return [issue.code for issue in parsed.issues if issue.source == EvidenceSource.ATTACHMENTS]


CONSISTENT = {
    "none": ([], collection("NONE")),
    "collected": ([item(), item("ig-notes.txt", content_type="text/plain")], collection("COLLECTED", regular_count=2)),
    "truncated-count": (
        [item()],
        collection("TRUNCATED", regular_count=3, omitted_count=2, omitted_extensions=["TXT", "txt", "html"],
                   reasons=["count_limit"]),
    ),
    "truncated-clip": (
        [item("ig-head" + "ig-tail.pdf", name_clip={"at": 7, "original_length": 400})],
        collection("TRUNCATED", regular_count=1, reasons=["field_limit"]),
    ),
    "truncated-field": (
        [item(content_type="", unavailable_fields=["content_type"])],
        collection("TRUNCATED", regular_count=1, reasons=["field_unavailable"]),
    ),
    "unavailable": ([], collection("UNAVAILABLE", regular_count=None, inline_count=None, reasons=["collection_error"])),
}
EXPECTED_STATE = {
    "none": AttachmentCollectionState.NONE,
    "collected": AttachmentCollectionState.COLLECTED,
    "truncated-count": AttachmentCollectionState.TRUNCATED,
    "truncated-clip": AttachmentCollectionState.TRUNCATED,
    "truncated-field": AttachmentCollectionState.TRUNCATED,
    "unavailable": AttachmentCollectionState.UNAVAILABLE,
}


def test_legacy_request_without_collection_state_is_unknown_and_adds_no_issue() -> None:
    parsed = parse()

    assert parsed.attachment_coverage.state == AttachmentCollectionState.UNKNOWN
    assert parsed.attachment_coverage.declared_state is None
    assert attachment_issues(parsed) == []


def test_legacy_list_without_collection_state_is_parsed_but_never_reported_as_collected() -> None:
    parsed = parse([item()])

    assert parsed.attachment_coverage.state == AttachmentCollectionState.UNKNOWN
    assert parsed.attachment_coverage.listed_count == 1
    assert parsed.attachments[0].name_segments == ("ig-agenda.pdf",)


@pytest.mark.parametrize("case", sorted(CONSISTENT))
def test_consistent_collection_states_are_accepted(case: str) -> None:
    items, declared = CONSISTENT[case]
    parsed = parse(items, declared)

    assert parsed.attachment_coverage.state == EXPECTED_STATE[case]
    assert attachment_issues(parsed) == []


def test_omitted_extensions_are_casefolded_and_deduplicated() -> None:
    items, declared = CONSISTENT["truncated-count"]

    assert parse(items, declared).attachment_coverage.omitted_extensions == ("txt", "html")


@pytest.mark.parametrize(
    ("items", "declared"),
    [
        ([item()], collection("NONE")),
        ([], collection("NONE", regular_count=None)),
        ([], collection("NONE", regular_count=2)),
        ([], collection("COLLECTED", regular_count=0)),
        ([item()], collection("COLLECTED", regular_count=2)),
        ([item()], collection("COLLECTED", regular_count=None)),
        ([item(name_clip={"at": 3, "original_length": 300})], collection("COLLECTED", regular_count=1)),
        ([item()], collection("COLLECTED", regular_count=2, omitted_count=1, reasons=["count_limit"])),
        ([item()], collection("TRUNCATED", regular_count=1, reasons=["count_limit"])),
        ([item()], collection("TRUNCATED", regular_count=3, omitted_count=2)),
        ([item()], collection("TRUNCATED", regular_count=3, omitted_count=2, reasons=["not_a_reason"])),
        ([item()], collection("UNAVAILABLE", reasons=["collection_error"])),
        ([], collection("UNAVAILABLE")),
        ([], collection("collected")),
        ([], collection("SAFE")),
    ],
    ids=[
        "none-with-items", "none-without-count", "none-with-count", "collected-empty", "collected-count-mismatch",
        "collected-without-count", "collected-with-clip", "collected-with-omissions", "truncated-nothing-lost",
        "truncated-without-reason", "truncated-unknown-reason-only", "unavailable-with-items",
        "unavailable-without-reason", "lowercase-state", "unrecognised-state",
    ],
)
def test_contradictory_collection_metadata_becomes_unknown_with_an_issue(items, declared) -> None:
    parsed = parse(items, declared)

    assert parsed.attachment_coverage.state == AttachmentCollectionState.UNKNOWN
    assert parsed.attachment_coverage.declared_state == declared["state"]
    assert attachment_issues(parsed) == ["attachment_collection_inconsistent"]
    assert parsed.attachment_coverage.listed_count == len(items)


def test_unknown_reason_and_flag_codes_are_dropped() -> None:
    parsed = parse(
        [item()],
        collection("TRUNCATED", regular_count=2, omitted_count=1, reasons=["count_limit", "made_up"],
                   omitted_name_flags=["BIDI_CONTROL", "MADE_UP"]),
    )

    assert parsed.attachment_coverage.reasons == ("count_limit",)
    assert parsed.attachment_coverage.omitted_name_flags == frozenset({"BIDI_CONTROL"})


def test_clipped_name_is_kept_as_separate_segments_with_removed_part_flags() -> None:
    head, tail = "ig-head-", "ig-tail.pdf"
    parsed = parse(
        [item(head + tail, name_clip={"at": len(head), "original_length": 400, "removed_dot_count": 2,
                                      "removed_flags": ["BIDI_CONTROL", "NOT_A_FLAG"]})],
        collection("TRUNCATED", regular_count=1, reasons=["field_limit"]),
    )
    attachment = parsed.attachments[0]

    assert attachment.name_segments == (head, tail)
    assert attachment.name_clipped and attachment.is_partial
    assert attachment.name_original_length == 400
    assert attachment.removed_dot_count == 2
    assert attachment.name_flags == frozenset({"BIDI_CONTROL"})


def test_invalid_clip_position_makes_the_name_unavailable_instead_of_guessing_a_split() -> None:
    parsed = parse(
        [item("short.pdf", name_clip={"at": 64, "original_length": 400})],
        collection("TRUNCATED", regular_count=1, reasons=["field_limit"]),
    )
    attachment = parsed.attachments[0]

    assert attachment.name_segments == ("",)
    assert "filename" in attachment.unavailable_fields
    assert "attachment_name_clip_invalid" in attachment_issues(parsed)


def test_hidden_characters_in_a_received_name_are_flagged() -> None:
    names = {
        "BIDI_CONTROL": "ig-report" + chr(0x202E) + "txt.pdf",
        "ZERO_WIDTH": "ig" + chr(0x200B) + "agenda.pdf",
        "CONTROL_CHAR": "ig" + chr(0x07) + "agenda.pdf",
    }
    parsed = parse([item(name) for name in names.values()],
                   collection("COLLECTED", regular_count=len(names)))

    assert [attachment.name_flags for attachment in parsed.attachments] == [frozenset({flag}) for flag in names]


def test_hebrew_and_direction_marks_are_not_flagged_as_controls() -> None:
    hebrew = "ig-" + "".join(chr(code) for code in (0x05D3, 0x05D5, 0x05D7)) + ".pdf"
    marked = chr(0x200F) + "ig-mark.pdf"
    parsed = parse([item(hebrew), item(marked)], collection("COLLECTED", regular_count=2))

    assert [attachment.name_flags for attachment in parsed.attachments] == [frozenset(), frozenset()]


@pytest.mark.parametrize(
    "overrides",
    [
        {"attachment_metadata": [item()] * 26},
        {"attachment_metadata": [item("x" * 513)]},
        {"attachment_metadata": [item(content_type="x" * 256)]},
        {"attachment_metadata": [item(size_bytes=-1)]},
        {"attachment_collection": collection("COLLECTED", reasons=["x"] * 9)},
        {"attachment_collection": collection("C" * 33)},
        {"attachment_collection": collection("COLLECTED", omitted_extensions=["x" * 17])},
        {"attachment_collection": collection("COLLECTED", regular_count=-1)},
    ],
    ids=["26-items", "long-name", "long-type", "negative-size", "too-many-reasons", "long-state", "long-extension",
         "negative-count"],
)
def test_out_of_bound_attachment_fields_are_rejected(overrides) -> None:
    with pytest.raises(ValidationError):
        AnalyzeRequest.model_validate({"schema_version": "1.0", "email": {**BASE_EMAIL, **overrides}})


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("none", "Attachments: Gmail listed none. Inline images and linked Drive files are not counted."),
        ("collected", f"Attachments: Gmail listed 2. {NAMES_ONLY}"),
        ("truncated-count", f"Attachments: Gmail listed 3 and details for 1 were received; the others were not "
                            f"assessed individually. {NAMES_ONLY}"),
        ("unavailable", "Attachments: attachment information could not be collected from Gmail, so attachments were "
                        "not assessed."),
    ],
)
def test_collection_state_is_reported_after_the_not_checked_line(monkeypatch, case: str, expected: str) -> None:
    items, declared = CONSISTENT[case]
    limitations = analyze(monkeypatch, items, declared)["limitations"]

    not_checked = next(index for index, line in enumerate(limitations) if line.startswith("Not checked:"))
    # Attachment information was sent, so attachments are no longer listed as not checked.
    assert "attachments" not in limitations[not_checked]
    assert limitations[not_checked + 1] == expected


def test_inconsistent_collection_is_reported_without_claiming_attachments_were_checked(monkeypatch) -> None:
    limitations = analyze(monkeypatch, [item()], collection("NONE"))["limitations"]

    assert "Attachments: the attachment information received was inconsistent, so attachments were not assessed." in limitations
    assert not any("names were checked" in line for line in limitations)


def test_legacy_request_gets_no_attachment_status_line(monkeypatch) -> None:
    limitations = analyze(monkeypatch)["limitations"]

    assert not any(line.startswith("Attachments:") for line in limitations)
    not_checked = next(line for line in limitations if line.startswith("Not checked: attachments"))
    assert "This request included no attachment information" in not_checked


def test_attachment_names_and_types_never_reach_the_response(monkeypatch) -> None:
    body = analyze(
        monkeypatch,
        [item(PRIVATE_NAME, content_type="application/x-ig-private-type")],
        collection("COLLECTED", regular_count=1),
    )

    text = json.dumps(body)
    assert PRIVATE_NAME not in text
    assert "ig-private" not in text
    assert "x-ig-private-type" not in text


def legacy_and_variants(case: dict) -> list[dict]:
    email = dict(case["email"])
    email.pop("attachment_collection", None)
    variants = [dict(email)]
    for items, declared in CONSISTENT.values():
        # Only names the attachment rules never score, so any change would come from the collection state.
        declared = {**declared, "omitted_extensions": [ext for ext in declared["omitted_extensions"] if ext != "html"]}
        variants.append({**email, "attachment_metadata": items, "attachment_collection": declared})
    variants.append({**email, "attachment_metadata": [item()], "attachment_collection": collection("NONE")})
    return variants


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_collection_state_with_unscored_names_never_changes_score_verdict_or_findings(case: dict) -> None:
    outcomes = []
    for email in legacy_and_variants(case):
        engine_result = analyze_with_detectors(EmailPayload.model_validate(email))
        scoring = score_engine_result(engine_result)
        statuses = {result.detector_id: result.status for result in engine_result.detector_results}
        assert statuses["attachment_metadata"] != DetectorStatus.TRIGGERED
        outcomes.append(
            (
                scoring.risk_score,
                scoring.verdict,
                tuple((scored.finding.id, scored.effective_contribution) for scored in scoring.scored_findings),
                scoring.coverage.reasons,
            )
        )

    assert len(set(outcomes)) == 1


def test_no_attachments_does_not_turn_an_incomplete_assessment_into_a_verdict(monkeypatch) -> None:
    body = analyze(monkeypatch, [], collection("NONE"), text_body="")

    assert body["verdict"] == "INCOMPLETE"
