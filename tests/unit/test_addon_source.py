import json
import subprocess
from pathlib import Path


ADDON_SOURCE = Path("addon/Code.js").read_text(encoding="utf-8")
ADDON_MANIFEST = json.loads(Path("addon/appsscript.json").read_text(encoding="utf-8"))


def run_addon_redaction(value: str) -> str:
    script = f"""
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync('addon/Code.js', 'utf8');
const context = {{}};
vm.createContext(context);
vm.runInContext(source, context);
process.stdout.write(context.redactSensitiveText_({json.dumps(value)}));
"""
    return subprocess.run(
        ["node", "-e", script],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def test_addon_uses_current_message_access_token() -> None:
    assert "GmailApp.setCurrentMessageAccessToken" in ADDON_SOURCE
    assert "messageId" in ADDON_SOURCE


def test_addon_calls_backend_with_error_handling_and_auth_header() -> None:
    assert "UrlFetchApp.fetch" in ADDON_SOURCE
    assert "X-InboxGuardian-Token" in ADDON_SOURCE
    assert "muteHttpExceptions" in ADDON_SOURCE


def test_addon_has_error_states_without_demo_result_text() -> None:
    assert "DEMO / NOT ANALYZED" not in ADDON_SOURCE
    assert "Backend unavailable" in ADDON_SOURCE
    assert "Unexpected backend response" in ADDON_SOURCE


def test_addon_renders_real_verdict_and_heuristic_score_labels() -> None:
    assert "verdictLabel_" in ADDON_SOURCE
    assert "label: 'High risk'" in ADDON_SOURCE
    assert "label: 'Suspicious'" in ADDON_SOURCE
    assert "label: 'No significant suspicious signals found'" in ADDON_SOURCE
    assert "label: 'Assessment incomplete'" in ADDON_SOURCE
    assert "Heuristic risk index, not a probability of phishing" in ADDON_SOURCE
    assert "/100 heuristic risk index" in ADDON_SOURCE
    assert "label: 'Safe'" not in ADDON_SOURCE


def test_addon_treats_incomplete_placeholder_score_as_unavailable() -> None:
    assert "showScore: false" in ADDON_SOURCE
    assert "meaningfulScore_" in ADDON_SOURCE
    assert "Risk score unavailable" in ADDON_SOURCE
    assert "risk_score: 0" not in ADDON_SOURCE


def test_addon_limits_findings_and_preserves_backend_findings() -> None:
    assert "MAX_PRIMARY_FINDINGS = 3" in ADDON_SOURCE
    assert "MAX_RENDERED_FINDINGS = 12" in ADDON_SOURCE
    assert "MAX_FINDING_SUMMARY_CHARS = 700" in ADDON_SOURCE
    assert "result.findings.slice(0, MAX_RENDERED_FINDINGS)" in ADDON_SOURCE
    assert "truncate_(observation, MAX_FINDING_SUMMARY_CHARS)" in ADDON_SOURCE
    assert "truncate_(interpretation, MAX_FINDING_SUMMARY_CHARS - observation.length)" in ADDON_SOURCE
    assert "findingSummaryHtml_" in ADDON_SOURCE
    assert "to risk index" in ADDON_SOURCE
    assert ".sort(" not in ADDON_SOURCE


def test_addon_displays_limitations_and_recommended_action() -> None:
    assert "MAX_DETAIL_LIMITATIONS = 40" in ADDON_SOURCE
    assert "MAX_LIMITATION_CHARS = 300" in ADDON_SOURCE
    assert "splitLimitations_(result.limitations)" in ADDON_SOURCE
    assert ".setHeader('Analysis coverage')" in ADDON_SOURCE
    assert ".setHeader('Additional details')" in ADDON_SOURCE
    assert ".setHeader('Recommended action')" in ADDON_SOURCE
    assert "<b>Recommended action:</b>" not in ADDON_SOURCE


def test_addon_displays_optional_reputation_context_separately() -> None:
    assert "reputationSection_(result)" in ADDON_SOURCE
    assert ".setHeader('Reputation context')" in ADDON_SOURCE
    assert "does not change the risk score or verdict" in ADDON_SOURCE
    assert "result.reputation_context !== undefined && !Array.isArray(result.reputation_context)" in ADDON_SOURCE
    assert "reputation_context || []" in ADDON_SOURCE
    assert "MAX_REPUTATION_CONTEXT = 5" in ADDON_SOURCE


def test_addon_requires_separate_virustotal_consent_action() -> None:
    assert "function checkPublicLinkReputation(e)" in ADDON_SOURCE
    assert "callBackend_(email, { virustotal: true })" in ADDON_SOURCE
    assert "payload.enrichments = { virustotal: true }" in ADDON_SOURCE
    assert "Check public link reputation with VirusTotal" in ADDON_SOURCE
    assert "Message text, full URLs, paths, query strings and attachments are not sent" in ADDON_SOURCE
    assert "function analyzeEmail(e)" in ADDON_SOURCE
    assert "result = callBackend_(email);" in function_body("analyzeEmail")
    assert "virustotal: true" not in function_body("analyzeEmail")


def test_addon_escapes_backend_provided_text() -> None:
    assert "escapeHtml_(findingTitle_(finding))" in ADDON_SOURCE
    assert "escapeHtml_(parts.observation)" in ADDON_SOURCE
    assert "escapeHtml_(parts.interpretation)" in ADDON_SOURCE
    assert "return CardService.newDecoratedText()" in ADDON_SOURCE
    assert ".setText(escapeHtml_(safeString_(text)))" in ADDON_SOURCE
    assert "html: '<b>' + escapeHtml_(action) + '</b>'" in ADDON_SOURCE
    assert "html: escapeHtml_(note)" in ADDON_SOURCE
    assert "escapeHtml_(line)" in ADDON_SOURCE
    assert "escapeHtml_(errorMessage)" in ADDON_SOURCE
    assert "escapeHtml_(value)" in ADDON_SOURCE
    assert "redactSensitiveText_" in ADDON_SOURCE
    assert "[redacted-code]" in ADDON_SOURCE
    assert "(?:\\?[^\\s\"'<>#]*)?" in ADDON_SOURCE


def test_addon_redaction_preserves_harmless_numbers_and_redacts_sensitive_contexts() -> None:
    redacted = run_addon_redaction(
        "Invoice 2026 reference 123456. OTP code 654321. "
        "Link https://example.test/path?token=secret#frag"
    )

    assert "Invoice 2026 reference 123456" in redacted
    assert "OTP code [redacted-code]" in redacted
    assert "https://example.test/path" in redacted
    assert "token=secret" not in redacted
    assert "#frag" not in redacted


def test_addon_validates_expected_backend_response_shape() -> None:
    assert "result.schema_version !== '1.0'" in ADDON_SOURCE
    assert "typeof result.risk_score !== 'number'" in ADDON_SOURCE
    assert "typeof result.score_type !== 'string'" in ADDON_SOURCE
    assert "typeof result.recommended_action !== 'string'" in ADDON_SOURCE


def test_manifest_declares_gmail_contextual_trigger_and_minimal_scopes() -> None:
    assert ADDON_MANIFEST["addOns"]["gmail"]["contextualTriggers"][0]["onTriggerFunction"] == "onGmailMessageOpen"
    assert set(ADDON_MANIFEST["oauthScopes"]) == {
        "https://www.googleapis.com/auth/gmail.addons.execute",
        "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
        "https://www.googleapis.com/auth/script.external_request",
    }


ADDON_CODE = "\n".join(line.split("//", 1)[0] if line.lstrip().startswith("//") else line
                       for line in ADDON_SOURCE.splitlines())


def function_body(name: str) -> str:
    """The code of one top-level function, without its declaration line and full-line comments."""
    start = ADDON_CODE.index(f"\nfunction {name}(")
    end = ADDON_CODE.find("\nfunction ", start + 1)
    body = ADDON_CODE[start : end if end != -1 else len(ADDON_CODE)]
    return body.split("\n", 2)[2]


def test_addon_never_calls_attachment_content_methods() -> None:
    for forbidden in ("getBytes", "copyBlob", "getDataAsString", "getAs(", "getHash", "getRawContent", "getAllBlobs"):
        assert forbidden not in ADDON_CODE


def test_addon_reads_attachments_only_when_analyze_email_runs() -> None:
    readers = {"collectAttachmentMetadata_", "countInlineImages_"}
    functions = [line.split("(", 1)[0].removeprefix("function ") for line in ADDON_SOURCE.splitlines()
                 if line.startswith("function ")]

    assert {name for name in functions if ".getAttachments(" in function_body(name)} == readers
    assert {name for name in functions if "collectAttachmentMetadata_(e)" in function_body(name)} == {
        "collectAttachmentsSafely_"
    }
    assert {name for name in functions if "collectAttachmentsSafely_(e)" in function_body(name)} == {
        "analyzeEmail",
        "checkPublicLinkReputation",
    }
    for name in ("onGmailMessageOpen", "getCurrentEmail_"):
        assert "collectAttachment" not in function_body(name)


def test_addon_attachment_collection_logs_nothing() -> None:
    for name in ("collectAttachmentsSafely_", "unavailableAttachments_", "collectAttachmentMetadata_",
                 "countInlineImages_", "describeAttachment_", "readAttachmentField_", "clipAttachmentName_"):
        body = function_body(name)
        assert "console." not in body and "Logger." not in body


def test_addon_source_contains_no_invisible_or_direction_control_characters() -> None:
    hidden = [
        hex(ord(character)) for character in ADDON_SOURCE
        if (ord(character) < 0x20 and character not in "\n\r\t")
        or 0x7F <= ord(character) <= 0x9F
        or 0x200B <= ord(character) <= 0x200F
        or 0x202A <= ord(character) <= 0x202E
        or 0x2060 <= ord(character) <= 0x2069
        or ord(character) == 0xFEFF
    ]
    assert hidden == []


def test_addon_attachment_limits_match_the_backend_model() -> None:
    from backend.app.models import AttachmentMetadata, EmailPayload

    list_limit = next(item.max_length for item in EmailPayload.model_fields["attachment_metadata"].metadata
                      if hasattr(item, "max_length"))
    name_limit = next(item.max_length for item in AttachmentMetadata.model_fields["filename"].metadata
                      if hasattr(item, "max_length"))
    type_limit = next(item.max_length for item in AttachmentMetadata.model_fields["content_type"].metadata
                      if hasattr(item, "max_length"))

    assert "var MAX_ATTACHMENTS_SENT = 25;" in ADDON_SOURCE and list_limit == 25
    assert "var MAX_ATTACHMENT_NAME_CODE_POINTS = 255;" in ADDON_SOURCE and name_limit >= 255
    assert "var MAX_ATTACHMENT_TYPE_CODE_POINTS = 255;" in ADDON_SOURCE and type_limit >= 255
    assert "var MAX_ATTACHMENTS_READ = 100;" in ADDON_SOURCE
    assert "var MAX_ATTACHMENT_COLLECTION_MS = 5000;" in ADDON_SOURCE


def test_addon_adds_no_links_remote_images_or_extra_network_calls() -> None:
    assert ADDON_SOURCE.count("UrlFetchApp.fetch") == 1
    for forbidden in ("setOpenLink", "newOpenLink", "setIconUrl", "setImageUrl", "newImage(", "<a href", "http://"):
        assert forbidden not in ADDON_SOURCE
    assert "https://" not in ADDON_SOURCE
    assert "setMaterialIcon" in ADDON_SOURCE
