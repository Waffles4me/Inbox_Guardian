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

The current `/analyze` endpoint returns a clearly labelled stub response only. It does not perform threat detection.

## Manual Google Apps Script Steps Still Required

An Apps Script project has been created and basic execution was verified manually by the project owner:

- Project ID: `1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs`
- Project URL: https://script.google.com/home/projects/1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs/edit

Still required:

1. Configure it as a Google Workspace Gmail Add-on using CardService.
2. Add a Gmail contextual trigger for opened messages.
3. Choose and verify least-privilege scopes for current-message access and `UrlFetchApp`.
4. Configure a secure HTTPS backend URL reachable from Google servers; `localhost` will not work for live Apps Script.
5. Store backend auth material in Apps Script properties or another non-committed secret store.
6. Install/test the add-on in a real consenting Gmail account using synthetic emails.

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

## GitHub

Remote repository: https://github.com/Waffles4me/Inbox_Guardian

`origin` is configured locally. First push is pending verification of publish-safe contents and GitHub push permissions.

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

Initial validation is limited to local tooling and backend skeleton checks. Do not claim Gmail integration, deployment, or detection accuracy until those flows are implemented and tested.
