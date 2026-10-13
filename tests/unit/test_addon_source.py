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
    assert "truncate_(parts.join(' '), MAX_FINDING_SUMMARY_CHARS)" in ADDON_SOURCE
    assert "findingSummary_" in ADDON_SOURCE
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


def test_addon_escapes_backend_provided_text() -> None:
    assert "escapeHtml_(findingTitle_(finding))" in ADDON_SOURCE
    assert "escapeHtml_(findingSummary_(finding))" in ADDON_SOURCE
    assert "return CardService.newDecoratedText()" in ADDON_SOURCE
    assert ".setText(escapeHtml_(safeString_(text)))" in ADDON_SOURCE
    assert "html: escapeHtml_(action)" in ADDON_SOURCE
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


def test_addon_adds_no_links_remote_images_or_extra_network_calls() -> None:
    assert ADDON_SOURCE.count("UrlFetchApp.fetch") == 1
    for forbidden in ("setOpenLink", "newOpenLink", "setIconUrl", "setImageUrl", "newImage(", "<a href", "http://"):
        assert forbidden not in ADDON_SOURCE
    assert "https://" not in ADDON_SOURCE
    assert "setMaterialIcon" in ADDON_SOURCE
