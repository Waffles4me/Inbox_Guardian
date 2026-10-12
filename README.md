# InboxGuardian

InboxGuardian is a 48-hour Upwind Security home-assignment project: a Gmail Add-on that analyzes the currently opened email on demand and asks a separate Python backend for an explainable heuristic risk result.

The assignment requires a Google Workspace Gmail Add-on, a backend service the add-on can call, a clear maliciousness score/verdict/reasoning shown to the user, a public source repository, and a live demonstration against a real Gmail account. The full assignment brief is intentionally not published in this repository.

Current status: initial local setup only. A basic Apps Script project exists and was manually verified by the project owner, but it is not yet configured as a Gmail Add-on. There is no deployed backend, Gmail-to-backend integration, or threat detection engine yet.

## Scope

- Gmail Add-on for an opened message, not inbox-wide monitoring.
- Separate Python/FastAPI backend.
- Option B: deterministic, explainable multi-signal analysis using sender identity, URL deception, and credential-phishing context signals once detection is implemented.
- Explainable 0-100 heuristic risk index, verdict, evidence, limitations, and recommended action.
- No LLM analysis, malware execution, URL fetching, auto-quarantine, or background scanning in the MVP.

## Repository Layout

```text
.
├── addon/                  # Future Apps Script source/manifest notes
├── backend/app/            # FastAPI app and request/response models
├── docs/                   # Setup, security, and assignment notes
├── tests/                  # Unit/integration tests and safe fixtures
├── PROJECT_OBJECTIVE.md
├── WBS.md
├── pyproject.toml
├── .env.example
└── .gitignore
```

## Local Backend Setup

Python is expected to be run with the Windows launcher:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"
py -m pip install -e ".[dev]"
uvicorn backend.app.main:app --reload
```

If pip or pytest has trouble with the non-ASCII workspace path, run commands with `PYTHONUTF8=1` and keep temporary/cache directories out of Git as configured in `.gitignore`.

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Test command:

```powershell
py -m pytest
```

The current `/analyze` endpoint requires `X-InboxGuardian-Token` and returns a clearly labelled `DEMO / NOT ANALYZED` response only. It does not perform threat detection.

For local testing, set the backend token outside Git:

```powershell
$env:INBOXGUARDIAN_API_TOKEN = "replace-with-local-demo-token"
```

Authenticated analyze check:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/analyze `
  -Headers @{ "X-InboxGuardian-Token" = $env:INBOXGUARDIAN_API_TOKEN } `
  -ContentType "application/json" `
  -Body '{"schema_version":"1.0","email":{"subject":"Demo","from":"demo@example.test"}}'
```

## API Contract

`POST /analyze`

Required header:

```text
X-InboxGuardian-Token: <shared demo token>
```

Minimal request:

```json
{
  "schema_version": "1.0",
  "email": {
    "subject": "Demo",
    "from": "sender@example.test",
    "reply_to": "",
    "text_body": "",
    "html_body": "",
    "headers": {},
    "attachment_metadata": []
  }
}
```

Current response is intentionally incomplete:

```json
{
  "schema_version": "1.0",
  "risk_score": 0,
  "score_type": "heuristic_risk_index_not_probability",
  "verdict": "INCOMPLETE",
  "findings": [
    {
      "id": "demo_not_analyzed",
      "severity": "info",
      "title": "DEMO / NOT ANALYZED"
    }
  ],
  "limitations": ["Threat detection is not implemented yet."],
  "recommended_action": "Do not use this demo response as a security assessment.",
  "detector_version": "stub-0.1.0"
}
```

## Manual Google Apps Script Steps Still Required

An Apps Script project has been created and basic execution was verified manually by the project owner:

- Project ID: `1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs`
- Project URL: https://script.google.com/home/projects/1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs/edit

Local source now contains a Gmail contextual trigger and CardService UI. Still required:

1. Review and push the local `addon/` files to the existing Apps Script project with `clasp`.
2. Verify the Gmail contextual trigger and requested scopes in the Apps Script editor.
3. Configure a secure HTTPS backend URL reachable from Google servers; `localhost` will not work for live Apps Script.
4. Store backend auth material in Apps Script properties or another non-committed secret store.
5. Install/test the add-on in a real consenting Gmail account using synthetic emails.

## Apps Script Local Sync

Recommended local synchronization is Google's `clasp` CLI. It is not installed yet in this environment.

Manual setup:

```powershell
# Install Node.js/npm first, then:
npm install -g @google/clasp
clasp login
```

Also enable the Apps Script API at https://script.google.com/home/usersettings.

After authentication, connect the local `addon/` directory to the existing project ID and pull before pushing:

```powershell
cd addon
clasp clone 1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs .
clasp pull
```

Do not commit `.clasp.json` or Google auth tokens.

Manual integration details are in [docs/gmail-integration-runbook.md](docs/gmail-integration-runbook.md). Do not run `clasp push`, deploy, or authorize new scopes without an explicit review step.

## GitHub

Remote repository: https://github.com/Waffles4me/Inbox_Guardian

`origin` is configured locally. The first push succeeded on branch `master`.

Confidentiality rule: `UPWIND_HOME_ASSIGNMENT.md` must remain local and must never be committed or pushed. The public README summarizes the assignment requirements without reproducing the assignment document.

Useful official docs:

- https://developers.google.com/workspace/add-ons/gmail
- https://developers.google.com/workspace/add-ons/gmail/extending-message-ui
- https://developers.google.com/apps-script/reference/url-fetch/url-fetch-app

## Open Decisions Before Gmail Integration

- Backend hosting or tunnel provider for an HTTPS URL reachable by Apps Script.
- Add-on-to-backend authentication strategy and secret rotation.
- Exact Gmail current-message scopes and event/message access pattern.
- Request size limits and redaction policy for logs/errors.
- Final versioned `/analyze` contract and scoring semantics.
- Whether authentication metadata can be trusted from available Gmail/Add-on data.

## Validation Status

Initial validation is limited to local tooling and backend skeleton checks. Current tests pass for the backend skeleton. Do not claim Gmail integration, deployment, or detection accuracy until those flows are implemented and tested.
