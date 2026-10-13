# InboxGuardian

InboxGuardian is a 48-hour Upwind Security home-assignment project: a Gmail Add-on that analyzes the currently opened email on demand and asks a separate Python backend for an explainable heuristic risk result.

The assignment requires a Google Workspace Gmail Add-on, a backend service the add-on can call, a clear maliciousness score/verdict/reasoning shown to the user, a public source repository, and a live demonstration against a real Gmail account. The full assignment brief is intentionally not published in this repository.

Current status: Gmail-to-backend integration proof of concept is complete. The unpublished Gmail Add-on has been synchronized with Apps Script, installed/authorized in a real Gmail account, and verified to call the local FastAPI backend through ngrok HTTPS. WBS 2.1 safe parsing/normalization, WBS 2.2 sender detection, WBS 2.3 deceptive URL detection, WBS 2.4 credential-context detection, internal detector orchestration, Method C v1 scoring, and backend `/analyze` response mapping are implemented with synthetic tests. The Gmail CardService UI still contains demo-specific wording and has not yet been adapted to present real scores.

## Scope

- Gmail Add-on for an opened message, not inbox-wide monitoring.
- Separate Python/FastAPI backend.
- Option B: explainable multi-signal analysis. Six detector families are approved as planned scope: sender identity, URL deception, credential-phishing context, suspicious attachment metadata, payment redirection / financial fraud, and separately evaluated NLP phishing classification.
- Method C v1 internal scoring is implemented: evidence deduplication, per-family caps, fixed heuristic weights, approved thresholds, coverage handling, and zero correlation bonus.
- Explainable 0-100 heuristic risk index, verdict, evidence, limitations, and recommended action.
- No LLM analysis, malware execution, URL fetching, auto-quarantine, or background scanning in the MVP.
- Implemented detector findings and scored results are connected to backend `/analyze`; the Gmail UI still needs a separate CardService update before claiming end-to-end real-score display.

## Repository Layout

```text
.
├── addon/                  # Apps Script Gmail Add-on source and manifest
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

The current `/analyze` endpoint requires `X-InboxGuardian-Token`, runs the parser, implemented detectors and Method C v1 scorer, and returns a bounded heuristic result. The score is not a probability. For `INCOMPLETE`, `risk_score` is a required-schema placeholder and limitations state that no meaningful score was produced.

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

Example low-observed-risk response:

```json
{
  "schema_version": "1.0",
  "risk_score": 0,
  "score_type": "heuristic_risk_index_not_probability",
  "verdict": "NO_SIGNIFICANT_SIGNALS",
  "findings": [],
  "limitations": [
    "attachment_metadata is planned but not implemented; it contributed 0 points.",
    "financial_fraud is planned but not implemented; it contributed 0 points.",
    "nlp_phishing is planned but not implemented; it contributed 0 points."
  ],
  "recommended_action": "No significant indicators were observed by the checks that ran. This does not guarantee the message is safe; continue using normal caution with links, attachments, and unusual requests.",
  "detector_version": "engine-0.1.0+scoring-0.1.0"
}
```

## Gmail Add-on Integration Status

An Apps Script project has been created and basic execution was verified manually by the project owner:

- Project ID: `1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs`
- Project URL: https://script.google.com/home/projects/1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs/edit

Verified on 2026-10-12:

- Local source was synchronized to Apps Script with `clasp`.
- Script Properties were configured for backend URL and token.
- The unpublished add-on was installed and authorized in a real Gmail account.
- Gmail displayed the selected email subject and sender.
- Clicking **Analyze Email** reached FastAPI through ngrok and displayed the expected `DEMO / NOT ANALYZED` response.

Backend update on 2026-10-13:

- `/analyze` now returns real parser -> engine -> scorer results in the existing response schema.
- The existing Gmail UI source was intentionally not changed; it may still show demo-specific labels until the next CardService milestone.

Still required:

1. Make startup/shutdown repeatable for backend and ngrok.
2. Keep backend auth material in environment variables and Apps Script Properties only.
3. Replace the Gmail result card's demo wording with real score, verdict, evidence and limitation display.

## Apps Script Local Sync

Local synchronization uses Google's `clasp` CLI.

Manual setup on a new machine:

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

Daily local startup and shutdown steps are in [docs/development-startup.md](docs/development-startup.md). Use that guide to restart FastAPI and ngrok without changing the existing Apps Script project.

## GitHub

Remote repository: https://github.com/Waffles4me/Inbox_Guardian

`origin` is configured locally. The first push succeeded on branch `master`.

Confidentiality rule: `UPWIND_HOME_ASSIGNMENT.md` must remain local and must never be committed or pushed. The public README summarizes the assignment requirements without reproducing the assignment document.

Useful official docs:

- https://developers.google.com/workspace/add-ons/gmail
- https://developers.google.com/workspace/add-ons/gmail/extending-message-ui
- https://developers.google.com/apps-script/reference/url-fetch/url-fetch-app

## Open Decisions After Integration Proof

- Whether to add a small local startup helper after the manual startup flow remains stable.
- Add-on-to-backend authentication rotation/replacement if the project grows beyond a single-user prototype.
- Sensitive logging/redaction rules for future detector output.
- Gmail CardService presentation of the backend's real scored response.
- Whether authentication metadata can be trusted from available Gmail/Add-on data.

## Validation Status

Integration proof of concept has been manually verified through Gmail, Apps Script, ngrok HTTPS, and FastAPI. Automated tests cover the backend/add-on source contract, internal parser, internal detectors, internal detector orchestration, internal scoring, and backend response mapping. Do not claim detection accuracy until fixture evaluation and Gmail real-result presentation are implemented.
