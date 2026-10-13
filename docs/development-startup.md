# Development Startup Guide

This guide resumes the current local development setup without recreating the project.

Current flow:

```text
Gmail Add-on -> ngrok HTTPS -> 127.0.0.1:8000 -> FastAPI
```

The backend now returns real parser -> detector engine -> Method C scorer results. The Gmail CardService UI has not yet been adapted and may still contain demo-specific wording.

## Prerequisites

- Run commands from the repository root unless a step says otherwise.
- Keep `INBOXGUARDIAN_API_TOKEN` out of Git and terminal screenshots.
- Keep `INBOXGUARDIAN_BACKEND_URL` and `INBOXGUARDIAN_API_TOKEN` in Apps Script Properties only.
- Do not regenerate tokens or change Apps Script Properties without an explicit review step.

## Activate Python

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"
```

If the virtual environment is missing:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"
py -m pip install -e ".[dev]"
```

## Start FastAPI

Set the demo token in the current PowerShell session. Use the existing token value; do not paste it into source files.

```powershell
$env:INBOXGUARDIAN_API_TOKEN = "<existing-local-demo-token>"
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Leave this terminal running.

## Start ngrok

Open a second PowerShell terminal and use an explicit IPv4 upstream:

```powershell
ngrok http http://127.0.0.1:8000
```

Copy the HTTPS forwarding URL shown by ngrok, for example:

```text
https://example.ngrok-free.app
```

Do not include `/analyze` in the Apps Script backend URL property.

## Verify Health Checks

Local health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Public HTTPS health check, replacing the URL with the current ngrok URL:

```powershell
Invoke-RestMethod https://example.ngrok-free.app/health
```

Expected result:

```json
{
  "status": "ok",
  "service": "inboxguardian-backend"
}
```

## Verify Backend Authentication Safely

Unauthenticated requests should fail:

```powershell
Invoke-WebRequest `
  -Method Post `
  -Uri http://127.0.0.1:8000/analyze `
  -ContentType "application/json" `
  -Body '{"schema_version":"1.0","email":{"subject":"Demo","from":"demo@example.test"}}' `
  -SkipHttpErrorCheck
```

Expected status: `401 Unauthorized`.

Authenticated local check:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/analyze `
  -Headers @{ "X-InboxGuardian-Token" = $env:INBOXGUARDIAN_API_TOKEN } `
  -ContentType "application/json" `
  -Body '{"schema_version":"1.0","email":{"subject":"Demo","from":"demo@example.test"}}'
```

Expected result: a schema `1.0` response with `score_type` set to `heuristic_risk_index_not_probability`. For this minimal example, the verdict may be `NO_SIGNIFICANT_SIGNALS` if enough basic evidence is present or `INCOMPLETE` if the payload is too sparse.

## Confirm Apps Script Properties

In the Apps Script editor for the existing project:

1. Open Project Settings.
2. Open Script Properties.
3. Confirm `INBOXGUARDIAN_BACKEND_URL` equals the current ngrok HTTPS base URL.
4. Confirm `INBOXGUARDIAN_API_TOKEN` is configured.
5. Do not reveal or copy the token into Git, docs, screenshots, or chat.

Existing project:

```text
https://script.google.com/home/projects/1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs/edit
```

## Open the Existing Gmail Add-on

1. Open Gmail with the authorized test account.
2. Open a safe synthetic test email.
3. Open InboxGuardian from the Gmail side panel.
4. Confirm the card shows the selected email subject and sender.
5. Click **Analyze Email**.
6. Confirm the backend call completes. The current Gmail result card may still use demo wording until the CardService UI is updated in the next milestone.

This is a manual integration check. It is not covered by automated tests.

## Stop Development Processes

Do this manually when finished:

1. In the FastAPI terminal, press `Ctrl+C`.
2. In the ngrok terminal, press `Ctrl+C`.
3. Close only the terminals you no longer need.

Do not leave ngrok running after the demo unless you are actively testing.

## Troubleshooting

### ngrok connects but FastAPI does not receive requests

- Confirm FastAPI is bound to `127.0.0.1` on port `8000`.
- Confirm ngrok was started with `http://127.0.0.1:8000`, not `localhost:8000`.
- Re-run both `/health` checks.

### Gmail reports backend unavailable

- Confirm the ngrok HTTPS URL is current.
- Confirm Apps Script `INBOXGUARDIAN_BACKEND_URL` matches the current ngrok HTTPS base URL.
- Confirm `/health` works through ngrok from PowerShell.

### Gmail reports authentication failed

- Confirm the local `INBOXGUARDIAN_API_TOKEN` environment variable is set.
- Confirm Apps Script `INBOXGUARDIAN_API_TOKEN` is set to the same value.
- Do not print or commit the token while checking.

### `/analyze` returns 503

The backend process does not have `INBOXGUARDIAN_API_TOKEN` configured. Set the environment variable and restart FastAPI.

### `clasp status` fails

- Confirm `addon/.clasp.json` exists locally and is not committed.
- Confirm `clasp login` has been completed for the correct Google account.
- Confirm the Apps Script API is enabled at `https://script.google.com/home/usersettings`.

## Startup Automation Recommendation

Do not add an automatic all-in-one startup script yet. The manual two-terminal flow is safer for the current single-user prototype because it avoids printing tokens, hiding ngrok state, or changing Apps Script Properties automatically.

A future helper script can be added if it:

- Reads the token from the current environment or a local ignored `.env` file.
- Never prints secrets.
- Starts FastAPI only.
- Leaves ngrok and Apps Script Property updates as explicit manual steps.
