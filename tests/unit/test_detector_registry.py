"""The detector registry and the shared text-context helpers.

The engine, the scorer and the public response mapping each refer to detector families by ID. These tests keep
them in step, and pin the behaviour of the helpers that wording-based detectors share.
"""

import re

from backend.app import engine, main, scoring
from backend.app.detectors import text_context
from backend.app.detectors.base import DetectorFinding
from backend.app.models import EmailPayload
from backend.app.parsing import parse_email_payload


FORWARD_MARKER = "---------- Forwarded message ---------"


def parsed(**email):
    return parse_email_payload(EmailPayload.model_validate({"from": "A <a@example.test>", **email}))


def test_every_detector_the_engine_runs_is_scored_in_the_same_order() -> None:
    assert tuple(runner.detector_id for runner in engine.IMPLEMENTED_DETECTORS) == scoring.SCORED_FAMILY_ORDER


def test_planned_families_are_shared_by_engine_scorer_and_response() -> None:
    assert scoring.PLANNED_FAMILIES == frozenset(engine.PLANNED_DETECTOR_IDS)
    assert set(main.PLANNED_CHECK_NAMES) == set(engine.PLANNED_DETECTOR_IDS)
    assert not set(scoring.IMPLEMENTED_FAMILIES) & scoring.PLANNED_FAMILIES


def test_every_weighted_finding_belongs_to_a_scored_family() -> None:
    prefixes = {
        "sender_identity": "sender_",
        "url_deception": "url_",
        "credential_context": "credential_",
        "attachment_metadata": "attachment_",
    }

    assert set(prefixes) == set(scoring.IMPLEMENTED_FAMILIES)
    assert all(any(finding_id.startswith(prefix) for prefix in prefixes.values()) for finding_id in scoring.FINDING_WEIGHTS)


def test_split_active_text_drops_forwarded_and_quoted_content() -> None:
    assert text_context.split_active_text(f"Hello\n> quoted\n{FORWARD_MARKER}\nForwarded body") == ("Hello", True, True)
    assert text_context.split_active_text("From: someone\n> \nOwn line") == ("Own line", False, True)
    assert text_context.split_active_text(">\n> ") == ("", False, False)


def test_active_text_keeps_subject_and_bodies_as_separate_contexts() -> None:
    active = text_context.active_text(parsed(subject="  Urgent  ", text_body="Plain body.", html_body="<p>Html body.</p>"))

    assert active.subject == "Urgent"
    assert active.active_bodies == ("Plain body.", "Html body.")
    assert active.contexts == ("Urgent", "Plain body.", "Html body.")
    assert active.active_body == "Plain body. Html body."


def test_active_text_ignores_the_html_copy_of_forwarded_content() -> None:
    active = text_context.active_text(
        parsed(text_body=f"FYI\n{FORWARD_MARKER}\nSend your password", html_body="<p>FYI Send your password</p>")
    )

    assert active.forwarded_excluded
    assert active.active_bodies == ("FYI",)


def test_identical_contexts_are_kept_once() -> None:
    assert text_context.active_text(parsed(subject="Same", text_body="Same")).contexts == ("Same",)


def test_matches_are_reported_as_the_enclosing_sentence() -> None:
    text = "First sentence. Please confirm your account now! Last one"
    pattern = re.compile(r"confirm your account")

    assert text_context.find_match(pattern, text) == "Please confirm your account now"
    assert text_context.find_match(re.compile("absent"), text) == ""
    assert text_context.first_in_contexts(lambda value: value if "b" in value else "", ["a", "bc", "bd"]) == "bc"


def test_safe_snippet_redacts_codes_and_url_queries_and_is_bounded() -> None:
    snippet = text_context.safe_snippet("Use code 482913 at https://login.example.test/path?token=secret#frag  now")

    assert snippet == "Use code [redacted-code] at https://login.example.test/path now"
    assert len(text_context.safe_snippet("x" * 500)) == 160


def test_dedupe_findings_keeps_the_first_finding_per_evidence_id() -> None:
    def finding(finding_id: str, evidence_id: str) -> DetectorFinding:
        return DetectorFinding(finding_id, "low", "t", "o", "i", evidence_id, ("text_body",))

    first, duplicate, other = finding("a", "e1"), finding("b", "e1"), finding("c", "e2")

    assert text_context.dedupe_findings([first, duplicate, other]) == [first, other]


def test_evidence_sources_name_only_the_inputs_that_were_used() -> None:
    email = parsed(subject="S", text_body="Body https://docs.example.test", html_body="<a href='https://x.example.test'>x</a>")

    assert text_context.evidence_sources(email, "S", "Body") == (
        "subject", "text_body", "html_body", "text_urls", "html_links"
    )
    assert text_context.evidence_sources(email, "", "") == ("text_urls", "html_links")
