from backend.app.models import EmailPayload
from backend.app.parsing import (
    MAX_URLS,
    MAX_URL_LENGTH,
    EvidenceSource,
    ParseStatus,
    parse_email_payload,
    parse_mailbox,
    parse_url,
)


def payload(**overrides: object) -> EmailPayload:
    data = {
        "subject": "Synthetic parser test",
        "from": "Security Team <Notice@Example.Test>",
        "reply_to": "",
        "text_body": "",
        "html_body": "",
        "headers": {},
        "attachment_metadata": [],
    }
    data.update(overrides)
    return EmailPayload.model_validate(data)


def issue_codes(parsed) -> set[str]:
    return {issue.code for issue in parsed.issues}


def test_parses_valid_mailbox_with_display_name_and_normalized_domain() -> None:
    mailbox = parse_mailbox("Security Team <Notice@Example.Test>", EvidenceSource.FROM)

    assert mailbox.status == ParseStatus.PRESENT
    assert mailbox.display_name == "Security Team"
    assert mailbox.address == "notice@example.test"
    assert mailbox.local_part == "notice"
    assert mailbox.domain == "example.test"
    assert mailbox.domain_unicode == "example.test"


def test_mailbox_missing_malformed_and_multiple_are_explicit() -> None:
    missing = parse_mailbox("", EvidenceSource.REPLY_TO)
    malformed = parse_mailbox("not an address", EvidenceSource.FROM)
    multiple = parse_mailbox("a@example.test, b@example.test", EvidenceSource.FROM)

    assert missing.status == ParseStatus.MISSING
    assert malformed.status == ParseStatus.MALFORMED
    assert multiple.status == ParseStatus.MALFORMED
    assert multiple.is_multiple is True


def test_mailbox_normalizes_unicode_domain_to_idna_and_unicode_forms() -> None:
    mailbox = parse_mailbox("Demo <user@bücher.example>", EvidenceSource.FROM)

    assert mailbox.status == ParseStatus.PRESENT
    assert mailbox.domain_idna == "xn--bcher-kva.example"
    assert mailbox.domain_unicode == "bücher.example"


def test_parse_email_payload_reports_missing_reply_to_without_security_conclusion() -> None:
    parsed = parse_email_payload(payload(reply_to=""))

    assert parsed.reply_to_mailbox.status == ParseStatus.MISSING
    assert "mailbox_missing" in issue_codes(parsed)
    assert parsed.input_completeness == ParseStatus.UNKNOWN


def test_extracts_plain_text_urls_and_redacts_query_from_display_form() -> None:
    parsed = parse_email_payload(
        payload(text_body="Open https://login.example.test/reset?token=secret#frag now.")
    )

    assert len(parsed.text_urls) == 1
    url = parsed.text_urls[0]
    assert url.status == ParseStatus.PRESENT
    assert url.hostname == "login.example.test"
    assert url.has_query is True
    assert url.has_fragment is True
    assert url.redacted_url == "https://login.example.test/reset"
    assert "token=secret" not in url.redacted_url


def test_extracts_html_anchor_href_and_visible_text_with_entities() -> None:
    parsed = parse_email_payload(
        payload(
            html_body='<p>Pay &amp; review <a href="https://example.test/path?code=secret">'
            "Example &amp; Portal</a></p>"
        )
    )

    assert parsed.html_visible_text == "Pay & review Example & Portal"
    assert len(parsed.html_links) == 1
    assert parsed.html_links[0].visible_text == "Example & Portal"
    assert parsed.html_links[0].href.hostname == "example.test"
    assert parsed.html_links[0].href.redacted_url == "https://example.test/path"


def test_malformed_html_is_handled_gracefully() -> None:
    parsed = parse_email_payload(
        payload(html_body='<div><a href="https://example.test/login">Login')
    )

    assert parsed.html_visible_text == "Login"
    assert len(parsed.html_links) == 1
    assert parsed.html_links[0].href.redacted_url == "https://example.test/login"


def test_unsupported_url_scheme_is_retained_as_link_evidence() -> None:
    parsed = parse_email_payload(payload(html_body='<a href="mailto:help@example.test">Email us</a>'))

    assert len(parsed.html_links) == 1
    assert parsed.html_links[0].href.status == ParseStatus.UNSUPPORTED
    assert parsed.html_links[0].href.scheme == "mailto"
    assert "url_unsupported_scheme" in issue_codes(parsed)


def test_ip_address_url_is_supported_without_reputation_claim() -> None:
    parsed = parse_email_payload(payload(text_body="Visit http://192.0.2.10:8080/a"))

    url = parsed.text_urls[0]
    assert url.status == ParseStatus.PRESENT
    assert url.hostname == "192.0.2.10"
    assert url.port == 8080
    assert url.redacted_url == "http://192.0.2.10:8080/a"


def test_url_parser_handles_unicode_and_punycode_hosts() -> None:
    unicode_url = parse_url("https://bücher.example/path", EvidenceSource.TEXT_BODY)
    punycode_url = parse_url("https://xn--bcher-kva.example/path", EvidenceSource.TEXT_BODY)

    assert unicode_url.status == ParseStatus.PRESENT
    assert unicode_url.hostname_idna == "xn--bcher-kva.example"
    assert unicode_url.hostname_unicode == "bücher.example"
    assert punycode_url.hostname_idna == "xn--bcher-kva.example"
    assert punycode_url.hostname_unicode == "bücher.example"


def test_duplicate_urls_are_omitted_only_after_exact_canonical_match() -> None:
    parsed = parse_email_payload(
        payload(
            text_body=(
                "https://example.test/a https://example.test/a "
                "https://example.test/b https://example.test/a?x=1"
            )
        )
    )

    assert [url.canonical_url for url in parsed.text_urls] == [
        "https://example.test/a",
        "https://example.test/b",
        "https://example.test/a?x=1",
    ]
    assert "url_duplicate_omitted" in issue_codes(parsed)


def test_html_anchor_is_preserved_when_destination_also_appears_in_text_body() -> None:
    parsed = parse_email_payload(
        payload(
            text_body=(
                "Review your account:\n"
                "https://accounts.example.test\n"
                "<https://accounts.example.test.attacker.test/login>\n"
            ),
            html_body='<a href="https://accounts.example.test.attacker.test/login">https://accounts.example.test</a>',
        )
    )

    assert [url.hostname for url in parsed.text_urls] == [
        "accounts.example.test",
        "accounts.example.test.attacker.test",
    ]
    assert len(parsed.html_links) == 1
    assert parsed.html_links[0].href.status == ParseStatus.PRESENT
    assert parsed.html_links[0].href.hostname == "accounts.example.test.attacker.test"
    assert parsed.html_links[0].visible_text == "https://accounts.example.test"
    assert "url_duplicate_omitted" not in issue_codes(parsed)


def test_html_anchors_with_same_destination_and_different_text_are_both_preserved() -> None:
    generic = '<a href="https://accounts.example.test.attacker.test/login">Sign in</a>'
    claimed = '<a href="https://accounts.example.test.attacker.test/login">https://accounts.example.test</a>'

    first_order = parse_email_payload(payload(html_body=generic + claimed))
    second_order = parse_email_payload(payload(html_body=claimed + generic))

    assert [link.visible_text for link in first_order.html_links] == ["Sign in", "https://accounts.example.test"]
    assert [link.visible_text for link in second_order.html_links] == ["https://accounts.example.test", "Sign in"]
    assert "url_duplicate_omitted" not in issue_codes(first_order)
    assert "url_duplicate_omitted" not in issue_codes(second_order)


def test_identical_html_anchors_are_still_deduplicated() -> None:
    anchor = '<a href="https://example.test/login">Sign   in</a>'
    same_after_normalization = '<a href="HTTPS://EXAMPLE.TEST/login"> Sign in </a>'
    parsed = parse_email_payload(payload(html_body=anchor + same_after_normalization + anchor))

    assert len(parsed.html_links) == 1
    assert parsed.html_links[0].visible_text == "Sign in"
    assert "url_duplicate_omitted" in issue_codes(parsed)


def test_html_link_count_bound_is_enforced_deterministically() -> None:
    body = "".join(
        f'<a href="https://example.test/{index}">Link {index}</a>' for index in range(MAX_URLS + 5)
    )
    text = " ".join(f"https://example.test/{index}" for index in range(MAX_URLS + 5))
    parsed = parse_email_payload(payload(text_body=text, html_body=body))

    assert len(parsed.text_urls) == MAX_URLS
    assert len(parsed.html_links) == MAX_URLS
    assert parsed.html_links[-1].href.path == f"/{MAX_URLS - 1}"
    assert "url_count_limit_reached" in issue_codes(parsed)


def test_url_length_bound_marks_overlong_url_malformed() -> None:
    parsed = parse_email_payload(payload(text_body="https://example.test/" + "a" * MAX_URL_LENGTH))

    assert parsed.text_urls[0].status == ParseStatus.MALFORMED
    assert "url_too_long" in issue_codes(parsed)


def test_url_count_bound_is_enforced_deterministically() -> None:
    body = " ".join(f"https://example.test/{index}" for index in range(MAX_URLS + 5))
    parsed = parse_email_payload(payload(text_body=body))

    assert len(parsed.text_urls) == MAX_URLS
    assert parsed.text_urls[-1].path == f"/{MAX_URLS - 1}"
    assert "url_count_limit_reached" in issue_codes(parsed)


def test_hostile_html_remains_inert_and_script_text_is_ignored() -> None:
    parsed = parse_email_payload(
        payload(
            html_body=(
                '<script>fetch("https://evil.example.test")</script>'
                '<style>.x{background:url("https://asset.example.test")}</style>'
                '<a href="https://example.test">Visible</a>'
            )
        )
    )

    assert "fetch" not in parsed.html_visible_text
    assert "asset.example.test" not in parsed.html_visible_text
    assert parsed.html_visible_text == "Visible"
    assert len(parsed.html_links) == 1
    assert parsed.html_links[0].href.hostname == "example.test"


def test_parser_does_not_claim_complete_original_message_when_no_truncation_flag_exists() -> None:
    parsed = parse_email_payload(payload(text_body="short body", html_body="<p>short body</p>"))

    assert parsed.input_completeness == ParseStatus.UNKNOWN
    assert "truncated" not in issue_codes(parsed)
