# Gmail Integration Runbook

This runbook prepares and verifies the Gmail vertical slice:

```text
Opened Gmail message -> Gmail Add-on -> FastAPI backend -> real result card
```

The Apps Script source renders real backend assessments as a modular dashboard using the existing `/analyze` response schema. The 2026-10-13 version was synchronized to the existing Apps Script project and manually verified in Gmail. Later add-on changes need a reviewed `clasp push` and a Gmail check against a backend reporting the matching analysis version (Additional details, "Analysis version").

## Current Local State

- Apps Script source lives in `addon/`.
- Local `.clasp.json` exists and points to script ID.
- `.clasp.json` is ignored and must not be committed.
- `addon/appsscript.json` declares a Gmail contextual trigger and minimal current-message/external-request scopes.
- `addon/Code.js` reads the opened message subject/sender/body using the current-message access token, then calls the backend with a token stored in Script Properties.

## Backend Setup

Create a local token for the demo session. Use a fresh random value and do not commit it.

```powershell
$env:INBOXGUARDIAN_API_TOKEN = "<local-demo-token>"
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Authenticated analyze check:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/analyze `
  -Headers @{ "X-InboxGuardian-Token" = $env:INBOXGUARDIAN_API_TOKEN } `
  -ContentType "application/json" `
  -Body '{"schema_version":"1.0","email":{"subject":"Demo","from":"demo@example.test","text_body":"Lunch is at noon."}}'
```

This should return `NO_SIGNIFICANT_SIGNALS` with `risk_score` `0`.

## HTTPS Exposure For Apps Script

Apps Script cannot call `localhost`. For a short-lived demo, use a temporary HTTPS tunnel or hosted HTTPS endpoint that supports forwarding to local port `8000`.

Recommended temporary options:

- Cloudflare Tunnel
- ngrok

Security requirements:

- Use HTTPS.
- Keep the `/analyze` endpoint protected with `X-InboxGuardian-Token`.
- Do not put the token in source code or Git.
- Stop the tunnel after testing.

Apps Script `UrlFetchApp` does not expose a per-request timeout option. The add-on handles non-2xx responses, authentication failures, malformed JSON, and unavailable backend responses without displaying sensitive details.

## Apps Script Configuration

Run these only after reviewing the local changes. Before pushing, pull the remote source into a separate scratch folder and compare it, so unexpected remote edits are not overwritten. Do not use `--force`.

```powershell
cd addon
clasp status
clasp push
```

Set Script Properties in the Apps Script editor:

| Property | Value |
|---|---|
| `INBOXGUARDIAN_BACKEND_URL` | Your temporary HTTPS base URL, without `/analyze` |
| `INBOXGUARDIAN_API_TOKEN` | Same token as `INBOXGUARDIAN_API_TOKEN` in the backend environment |

Do not store these values in Git.

## Manual Gmail Add-on Verification

1. Confirm `addon/.clasp.json` points to the expected script ID.
2. Push the local add-on files only after reviewing them.
3. In Apps Script, confirm the manifest contains the Gmail add-on configuration.
4. Configure/test the add-on in the Apps Script editor using the unpublished/test deployment flow.
5. Open Gmail with the same account.
6. Open a safe synthetic test email.
7. Open InboxGuardian from the Gmail side panel.
8. Confirm the card shows the subject and sender.
9. Click **Analyze Email**.
10. Confirm the result card shows these sections: **Assessment** (verdict, and a risk index with a bar, or `Risk score unavailable` when incomplete), **Key findings**, **Recommended action**, **Analysis coverage** and a collapsed **Additional details**.
11. If the result does not match what the current code should produce, restart the backend. A FastAPI process started before a code change keeps serving the old behaviour.

## Expected Failure States

- Missing Script Properties: card reports backend settings are missing.
- Wrong token: card reports backend authentication failed.
- Backend/tunnel down: card shows an `Analysis unavailable` section saying the backend is unavailable, with no verdict or risk score.
- Invalid backend JSON: card reports unexpected backend response.

Manual checks recorded on 2026-10-13 (desktop web Gmail, synthetic messages): benign `0`, credential phishing `25`, multi-signal `60`, empty-body and forwarded `INCOMPLETE`, expandable sections, icons and colours, non-clickable hostnames, and backend unavailable. Dark theme, the mobile app and screen readers were not checked. Evidence is listed in `WBS.md` 2.13 and 3.6.
