import json
from pathlib import Path


ADDON_SOURCE = Path("addon/Code.js").read_text(encoding="utf-8")
ADDON_MANIFEST = json.loads(Path("addon/appsscript.json").read_text(encoding="utf-8"))


def test_addon_uses_current_message_access_token() -> None:
    assert "GmailApp.setCurrentMessageAccessToken" in ADDON_SOURCE
    assert "messageId" in ADDON_SOURCE


def test_addon_calls_backend_with_error_handling_and_auth_header() -> None:
    assert "UrlFetchApp.fetch" in ADDON_SOURCE
    assert "X-InboxGuardian-Token" in ADDON_SOURCE
    assert "muteHttpExceptions" in ADDON_SOURCE


def test_addon_has_error_and_demo_states() -> None:
    assert "DEMO / NOT ANALYZED" in ADDON_SOURCE
    assert "Backend unavailable" in ADDON_SOURCE
    assert "Unexpected backend response" in ADDON_SOURCE


def test_addon_does_not_present_demo_as_real_security_score() -> None:
    assert "No security score has been produced" in ADDON_SOURCE
    assert "Demo connection result" in ADDON_SOURCE


def test_manifest_declares_gmail_contextual_trigger_and_minimal_scopes() -> None:
    assert ADDON_MANIFEST["addOns"]["gmail"]["contextualTriggers"][0]["onTriggerFunction"] == "onGmailMessageOpen"
    assert set(ADDON_MANIFEST["oauthScopes"]) == {
        "https://www.googleapis.com/auth/gmail.addons.execute",
        "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
        "https://www.googleapis.com/auth/script.external_request",
    }
