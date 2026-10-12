# InboxGuardian — Project Objective & Agent Operating Guide

> **Status:** PLANNING / NOT IMPLEMENTED  
> **Last updated:** 2026-10-12  
> **Assignment:** Upwind Security — Security Analyst Home Assignment  
> **Delivery constraint:** 48-hour focused development window, with a working live Gmail demonstration as the primary milestone.  
> **Read this file first.** Then read `WBS.md`. Both must remain synchronized.

## 1. Project in one minute

**InboxGuardian** is a user-friendly, explainable **Gmail Add-on** that analyzes the *currently opened email* on demand and displays a **0–100 heuristic risk score, understandable verdict, concrete evidence, and recommended safe action**. A separate **Python backend** parses the email, runs independent security checks, correlates findings, and returns a structured result. The goal is a convincing, reliable, securely implemented interview demonstration—not an enterprise mail gateway.

### Research question

> **How effectively can a lightweight, explainable multi-signal detection system identify suspicious and potentially malicious emails within Gmail, while minimizing false positives and clearly communicating the evidence and uncertainty behind each verdict?**

This question motivates the project; a 48-hour prototype cannot establish general real-world detection accuracy. Any empirical claims must be limited to the actual test dataset.

## 2. Source-of-truth hierarchy and assignment alignment

1. **Upwind's supplied assignment** (`UPWIND_HOME_ASSIGNMENT.md`) is authoritative for external requirements.
2. **This document** defines agreed project scope, implementation constraints, decisions, and session status.
3. **`WBS.md`** defines ordered implementation work and acceptance gates.
4. Code and tests show what is actually implemented. Where code diverges from this guide, **report the discrepancy**; do not silently rewrite requirements to fit code.
5. The local project directory is the development source of truth. GitHub is the remote version-controlled repository once synchronization is verified.

The assignment explicitly requires:
- A **Gmail Add-on**, built with **Google Workspace APIs**, that works on an **opened email**; the add-on is the product users see first.
- A **backend service** that the add-on calls.
- A **maliciousness score, clear verdict, and explanation** shown in the add-on.
- A **public Git repository** containing complete add-on/backend source and a professional root `README.md` with setup, architecture, rationale, and evaluation/limitations.
- Deployment to a **real Gmail account** and a **live demonstration** on the developer's own laptop.
- Explicit attention to product choices, design, code quality, untrusted input, sensitive data, and trade-offs.

Not mandated by Upwind: continuous background monitoring, Chrome extensions, push notifications, machine learning, LLMs, malware sandboxing, production rollout, or arbitrary feature count. **Do not build them in the MVP.**

## 3. GitHub Publishing and Confidentiality Rules

These rules are mandatory for every current and future coding agent, including Codex, Claude, or any other AI agent working on this repository:

1. **NEVER commit or push `UPWIND_HOME_ASSIGNMENT.md` to GitHub.** This is a permanent, non-negotiable rule.
2. The assignment document must remain available locally so coding agents can read and reference it.
3. The file must be explicitly excluded through `.gitignore`.
4. Before every Git commit and push, verify that the assignment file is not staged or tracked.
5. If the file is already tracked, remove it from Git tracking without deleting the local copy.
6. If the file was previously committed, report this immediately and do not assume `.gitignore` removes it from Git history.
7. Review all files for credentials, secrets, tokens, private email content, and confidential information before publishing.
8. `PROJECT_OBJECTIVE.md`, `WBS.md`, source code, tests, and `README.md` may be published after reviewing them for sensitive information.
9. The public `README.md` should briefly summarize the project's goals and Upwind's mandatory technical requirements, without reproducing the full assignment document.
10. The assignment remains authoritative for project requirements, even though it is excluded from the public repository.

## 4. Product principles (ordered)

1. **Simple for the user:** open Gmail → select InboxGuardian → choose **Analyze this email** → read a score/verdict and short reasons. Show a clear loading/error/incomplete state. Minimize steps and jargon.
2. **Meet assignment requirements end to end:** a real contextual Gmail Add-on and separately running backend must work before optional detectors/features.
3. **Explain every suspicion:** evidence must correspond to an actual observed signal; show what was observed, why it matters, and a safe next step. Avoid unexplained labels, hidden LLM claims, or made-up certainty.
4. **Security by default:** least-privilege access, safe processing of hostile emails, secured backend, protected secrets, minimal retention, no arbitrary link fetching or executing attachments.
5. **Honest uncertainty:** unavailable or insufficient signals are **unknown**, not clean. A 0–100 score is a **heuristic risk index, not a probability** unless independently calibrated.
6. **Reliable, demonstrable delivery:** a working narrow vertical slice outranks broad incomplete feature coverage.

## 5. MVP definition / acceptance criteria

### Must-have — required to claim MVP complete

- [ ] Newly created **Google Apps Script / Google Workspace Gmail Add-on** installed on a **real test Gmail account**; contextual view for the opened email.
- [ ] User explicitly initiates analysis via a simple, visible action (or an equally clear contextual user flow); the UI identifies the current email and does not silently scan the whole inbox.
- [ ] Add-on sends only necessary email fields to a **separate, reachable Python/FastAPI backend** through an authenticated/authorized, HTTPS-protected interface; integration tested live.
- [ ] Backend validates and safely normalizes inputs and returns a **versioned JSON contract** containing risk index (0–100), verdict, detector evidence, limitations/unknowns, and recommended action.
- [ ] At least **three independently implemented and unit-tested signal families** (proposed: sender/Reply-To identity anomalies, URL destination/display deception, credential-request/social-engineering context). Prefer a fourth: authentication indicators **only if reliable trustworthy metadata is available**.
- [ ] Conservative deterministic **multi-signal correlation**; neither a single generic keyword nor missing metadata is treated as proof of malice.
- [ ] User sees one of: **High risk**, **Suspicious**, **No significant suspicious signals found**, or **Unable to assess / Incomplete**; no definitive "safe" designation.
- [ ] User sees **2–4 plain-language findings**, a way to identify contributing evidence, and a specific safe next action; no automatic opening of suspicious URLs.
- [ ] Labeled safe synthetic `.eml`/JSON samples include malicious-looking and benign edge cases; automated tests evaluate both and report a confusion matrix or transparent per-case outcomes, plus known limitations.
- [ ] Backend never executes attachments, follows untrusted links, or treats message text as instructions. Secrets are outside Git; request validation, size limits, error handling, and sensitive log redaction exist.
- [ ] Public Git repo contains runnable source, tests, safe config examples, a root `README.md`, architecture sketch, setup instructions, explanation of score, security trade-offs, and demo steps.
- [ ] Demonstration rehearsed end to end using a real Gmail account and safe test messages; errors and fallback plan documented.

### Explicitly deferred

- Chrome extension, proactive inbox watcher, Gmail push/Pub/Sub, browser notifications, account-wide scanning, multi-user admin, auto-quarantine, malware sandbox, QR/image OCR, historic sender baseline, production reputation APIs, LLM-based verdicts, statistical calibration claims, Google Marketplace publication.
- Attachment **metadata-only** signals are optional after the core three detector families; no binary analysis.

## 6. Threat scope, interpretations, and scoring design

### Primary threats

- **Credential phishing / account takeover attempts:** suspicious credential prompts or login links paired with corroborating context.
- **Sender/brand impersonation:** identity inconsistencies, misleading Reply-To, or plausible lookalike domains; legitimate third-party senders are an important false-positive case.
- **Link deception:** mismatched visible/link destination domains, suspicious hostname forms, or credential links inconsistent with claimed sender. The mere presence of a link is not bad.

### Evidence and uncertainty rules

- Distinguish an **observation** (e.g. displayed domain differs from link host) from an **inference** (e.g. possible impersonation). Never claim confirmed phishing absent confirmation.
- Not all headers are trusted: `From` and message-supplied `Authentication-Results` may be forged. Treat SPF/DKIM/DMARC data as authoritative **only** when provenance is established; otherwise omit or flag unknown.
- Analyze safely without following URLs, resolving unknown hosts unnecessarily, opening attachments, or sending user content to third-party AI/reputation services.
- Do not assert the risk index equals likelihood. Initial weights/thresholds are **design choices** that must be versioned, justified, and checked against fixture tests. Avoid double counting correlated evidence. Show missing data distinctly from negative findings.
- Recommended response labels: `HIGH_RISK`, `SUSPICIOUS`, `NO_SIGNIFICANT_SIGNALS`, `INCOMPLETE`. Revisit thresholds based on tests; no fabricated numerical accuracy targets.
- Limit scope for first version to **English-language body/context heuristics**, while URL and sender structural parsing should not assume ASCII-only inputs. Explicitly document language limitations.

## 7. Target user experience

**Journey:** Open an email → open InboxGuardian's side panel → click **Analyze this email** → view a succinct card:

- **Verdict:** High risk / Suspicious / No significant suspicious signals / Incomplete.
- **Risk index:** e.g. `78/100` (illustrative only); label as heuristic.
- **Why:** up to three prominent evidence-backed reasons; optional compact additional details.
- **Recommended action:** concrete and non-alarming, e.g. "Do not use this login link. Visit the service directly."
- **Limitations:** "We could not verify authentication metadata" if applicable.

Use **Google Workspace Add-on CardService** components and supported contextual triggers; do not assume arbitrary HTML/CSS React-style rendering inside Gmail. Accessibility: text labels, readable contrast, uncluttered layout, legible error states. No false green guarantee.

## 8. Proposed architecture and technology

```text
Real Gmail account / opened message
      |
Google Workspace Gmail Add-on (new Apps Script project; CardService)
      |  current-message authorization; minimal field extraction
      |  validated authenticated request over HTTPS
      v
Python 3 / FastAPI backend (reachable by Apps Script)
      |
      +-- request validation / size limits / defensive normalization
      +-- independent sender / URL / phishing-context detectors
      +-- versioned conservative correlation and scoring
      +-- evidence + verdict + recommendation serializer
      v
Gmail Add-on results card (no external UI required)
```

**Implementation starting conditions:** A basic Google Apps Script test project now exists and was manually verified by the user, but there is **no configured Gmail Add-on**, OAuth/Google Cloud setup, backend deployment, or working Gmail integration assumed. No persistent database is necessary for the first version; process on demand and avoid storing email content.

**Practical priorities:** early proof-of-connectivity with a minimal `/health` endpoint and a test `/analyze` response, then implement real parsing/detection. The backend must be reachable from Google's servers: `localhost` alone is not sufficient for live Apps Script integration. Select and verify an HTTPS hosting/tunneling method before integration; avoid publicly exposing unauthenticated analysis endpoints. Do not rely on Google Cloud verification/public Marketplace launch as part of the 48-hour MVP. Verify the minimal current-message Gmail scope and required external-request scope against current Google docs; do not assume access to all inbox content.

### Proposed API contract (draft; freeze before implementation)

`POST /analyze` with bounded, validated JSON:

```json
{
  "schema_version": "1.0",
  "email": {
    "subject": "Illustrative subject",
    "from": "Service <notice@example.test>",
    "reply_to": "",
    "text_body": "Sample message body",
    "html_body": "<a href=\"https://example.test\">View notice</a>",
    "headers": {},
    "attachment_metadata": []
  }
}
```

Response example **for schema illustration, not a real score or detection claim**:

```json
{
  "schema_version": "1.0",
  "risk_score": 25,
  "score_type": "heuristic_risk_index_not_probability",
  "verdict": "SUSPICIOUS",
  "findings": [
    {
      "id": "link_sender_mismatch",
      "severity": "medium",
      "title": "Link destination differs from claimed sender",
      "observation": "The message claims one domain but points to a different host.",
      "interpretation": "This can indicate impersonation but may also be legitimate.",
      "contribution": 25
    }
  ],
  "limitations": ["Authentication metadata not verified"],
  "recommended_action": "Verify the request by visiting the service directly.",
  "detector_version": "0.1.0"
}
```

The sample score matches the one illustrated contribution. In implementation, enforce an auditable scoring invariant: every contribution (including correlation contributions) must be enumerated or its reconciliation explained. The example is illustrative and must not become a scoring threshold requirement.

**Auth note:** Never send Gmail access tokens as backend authentication by default. Choose an appropriate authenticated Apps Script ↔ backend arrangement, with backend request verification, secret rotation and no committed credentials. Document the residual security trade-offs for a single-user demo.

## 9. Proposed repository structure

```text
inboxguardian/
├── README.md
├── PROJECT_OBJECTIVE.md             # canonical context, rules, session handoff
├── WBS.md                           # work packages and gates
├── addon/
│   ├── Code.gs                     # Apps Script CardService and API client
│   └── appsscript.json              # manifest (no secrets)
├── backend/
│   ├── app/                          # FastAPI, schemas, validation, engine
│   │   ├── main.py
│   │   ├── models.py
│   │   ├── scoring.py
│   │   └── detectors/
│   ├── requirements.txt or pyproject.toml
│   └── .env.example
├── tests/
│   ├── fixtures/                     # safe illustrative emails and labels
│   ├── unit/
│   └── integration/
├── docs/
│   ├── architecture.md
│   ├── scoring-policy.md
│   ├── security-decisions.md
│   └── demo-runbook.md
└── .gitignore
```

The initial repository can be simpler if justified. Do not create placeholder modules that obscure progress.

## 10. Rules for Codex, Claude and other agents

### Mandatory start-of-session procedure

1. Read **`PROJECT_OBJECTIVE.md` fully**, then **`WBS.md`** and the relevant source files/tests.
2. State briefly: current status, selected WBS task, expected files to touch, and validation plan.
3. Check the repository state (`git status`, tree, existing tests). Never assume tasks checked in WBS match code without verification.
4. Implement **only the next agreed task / small vertical slice**. Do not add proactive monitoring, AI, or extension code merely because older project context mentions it.
5. Preserve existing working functionality and avoid unrelated refactoring; describe any unavoidable change.

### Development and security rules

- Favor minimal, readable, typed and testable Python; keep parsing, signal detection, scoring and UI decoupled.
- Never hardcode or commit passwords, Google access tokens, credentials, API keys, private email content, or production `.env` files.
- Restrict access to the single intended demo user wherever feasible; never mistake a CORS rule or secret embedded in a public extension for backend authentication.
- Treat **all** email bodies, HTML, headers, links, filenames, and any enrichment as untrusted data; never execute, follow, or render as trusted HTML. Handle oversized, malformed, missing and unusual encodings gracefully.
- Use explicit request/response validation, network timeouts, clear errors, and least-privilege permissions.
- Avoid unnecessary persistence and sensitive logging. No external ML/reputation data sharing without explicit approval and review.
- Do not invent accuracy, performance, correctness, or finished feature claims. Never silently bypass failing tests. Use synthetic/dummy email samples for reproducible demos.
- Each detector requires test cases for both triggering malicious-looking examples **and legitimate counterexamples**. Risk explanation must match actual rule findings.
- Favor first-party Google Workspace add-on APIs rather than scraping Gmail web pages or injecting browser JavaScript.
- Before pushing to a **public** GitHub repo, run a basic secret/privacy check and ensure sample content is synthetic/authorized. Never publish actual private mail.
- If internet/Google auth/GitHub deployment actions cannot be performed, report the blocker and provide exact manual steps; do not claim success.

### End-of-session / handoff procedure — REQUIRED

1. Run relevant tests or explicitly record why they could not run; do not check off unverified work.
2. Update **the Session Handoff section below** with date, summary, files touched, status, decisions, validation evidence, blockers, and precise next actions.
3. Update **`WBS.md`** checkboxes, evidence paths, outstanding blockers, and any changed task order.
4. Update the root `README.md` when user-facing setup, APIs, commands, or product behavior change.
5. Inspect `git status` and review all changes.
6. Perform a secrets/security check on files to be committed.
7. Create a descriptive Git commit.
8. Push changes to GitHub and verify synchronization, unless blocked by failed tests, missing authentication, or a public-release/security decision.
9. Provide the user a concise status report (implemented, tested, blocked, GitHub sync result, next action). Do not make unrequested destructive changes or deployments.

### Change control

Any agent proposing changes to approved scope, threat categories, score semantics, data sharing, Gmail permissions, hosting, or new dependencies must document the rationale, security impact and test impact **before** implementation; obtain user agreement for material changes. When docs disagree, surface the conflict and follow the upstream assignment requirement.

## 11. Critical decisions and current baseline

| Decision | Status | Reason / note |
|---|---|---|
| Option B: explainable multi-signal investigator | **Approved** | User selected it over pure rules or LLM-led analysis |
| Simplicity, assignment alignment, transparent suspicion | **Approved** | User's three product priorities |
| Two documents (`PROJECT_OBJECTIVE.md`, `WBS.md`) | **Approved design** | One source of truth + one operational plan |
| New Apps Script project from scratch | **Approved** | No preexisting Google setup assumed |
| Opened-email, on-demand Gmail Add-on (not proactive monitor) | **Approved direction** | Upwind assignment requirement and 48-hour limit |
| FastAPI + Apps Script CardService | **Proposed implementation** | Confirm compatibility during technical spike |
| English-only linguistic heuristics | **Proposed MVP scope** | Limited time; structural signals can work more broadly |
| Hosting, auth strategy, exact scopes | **OPEN** | Validate early against current Google documentation |
| Scoring weights / thresholds and dataset | **OPEN** | Must be explicit and checked before claims |
| Repository URL and live demonstration account | **NOT YET SET** | Record once created |

## 12. External Services and Integrations

### GitHub

| Item | Status |
|---|---|
| Repository URL | `https://github.com/Waffles4me/Inbox_Guardian` |
| Repository visibility | Public, per user-provided setup |
| Connection status | Repository reachable; `git ls-remote --heads origin` verified `refs/heads/master` |
| Local remote | `origin` configured to `https://github.com/Waffles4me/Inbox_Guardian.git` |
| Push permissions | Verified by successful push to `origin/master` |
| GitHub synchronization | Mandatory after every development session |

### Google Apps Script

| Item | Status |
|---|---|
| Project URL | `https://script.google.com/home/projects/1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs/edit` |
| Project ID | `1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs` |
| Basic Apps Script access | Verified manually by the user |
| Test function execution | Passed manually, per user report |
| Agent access | Not verified; project URL alone does not grant authenticated source/config access |
| Agent read/edit/sync capability | Not available until local clasp setup and Google authentication are completed |
| Local synchronization method | Recommended: Google `clasp` with `addon/` as the local root, after installing Node/npm, enabling Apps Script API, running `clasp login`, and connecting to the existing project ID |
| Gmail Add-on deployment | Not started |

### Local Apps Script Synchronization Plan

Use Google's `clasp` CLI to keep source files in `addon/` and synchronize them with the existing Apps Script project. The local `.clasp.json` file must stay out of Git because it is environment-specific; Google auth tokens must remain outside the repository.

Manual setup needed:

1. Install Node.js/npm.
2. Enable the Apps Script API at `https://script.google.com/home/usersettings`.
3. Install clasp, for example `npm install -g @google/clasp`.
4. Run `clasp login` and complete the Google OAuth flow in the browser.
5. Connect the local `addon/` directory to the existing project ID, for example from inside `addon/`: `clasp clone 1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs .` or create a local `.clasp.json` with that `scriptId`.
6. Use `clasp pull` to import the current remote source, and `clasp push` only after reviewing local changes. Do not deploy from clasp until the Gmail Add-on manifest/source is ready.

## 13. Session Handoff — continuously maintained

> **Agents must replace/update this section at the end of every working session.** Never mark something as deployed, tested or complete without evidence.

- **As of:** 2026-10-12 (initial setup session)
- **Current state:** Local repository and minimal backend scaffold created. Public GitHub repository URL is known, configured as `origin`, and synchronized on branch `master`. Apps Script project was created and tested manually by the user, but local/agent source synchronization is not configured. **No backend deployment, live HTTPS endpoint, Gmail integration, or threat detection engine exists yet.**
- **Completed decisions:** Preserve narrow on-demand Gmail Add-on MVP; Python/FastAPI backend scaffold; `pyproject.toml` dependency management; no committed credentials; stub `/analyze` returns `INCOMPLETE` until real detection exists.
- **Work completed in this session:** Initialized local Git repository; created minimal project structure (`addon/`, `backend/app/`, `tests/`, `docs/`); added `.gitignore`, `.env.example`, `README.md`, FastAPI `/health` and stub `/analyze`, Pydantic request/response models, setup/security docs, and backend skeleton tests.
- **In progress:** WBS 0 setup. Local Python backend environment exists in `.venv`; dependencies installed after resolving Windows temp/UTF-8 path issues.
- **Known blockers / unknowns:** Node/npm/clasp are not installed; agent Google authentication/App Script source access is not available; exact Gmail scopes, backend HTTPS hosting, add-on-to-backend authentication, request limits, logging/redaction policy, scoring thresholds, and detector dataset remain open.
- **Next WBS task:** Complete the remaining G0 decisions, especially backend HTTPS/auth plan and exact Gmail contextual-message scopes, then start WBS `1.1-1.5`: create the real Apps Script Gmail Add-on manually and prove opened-email -> backend -> card response.
- **Evidence of tests/deployment:** `.\.venv\Scripts\python.exe -m pytest -o cache_dir=.tmp\pytest-cache-current` passed `2 passed, 2 warnings` on 2026-10-12. `git ls-remote --heads origin` verified remote branch `master`. No backend deployment or Gmail integration test was performed.
- **Working tree/repository status:** Local Git repository initialized; `origin` configured to `https://github.com/Waffles4me/Inbox_Guardian.git`; branch `master` tracks `origin/master`. `UPWIND_HOME_ASSIGNMENT.md` is ignored and not tracked.

### Session log (append concise entries)

| Date | Agent/session | Verified changes | Tests/evidence | Outstanding action |
|---|---|---|---|---|
| 2026-10-12 | Planning / ChatGPT | Objective and WBS prepared; architecture and MVP agreed in principle | Documentation only | Start technical spike; validate Google integration |
| 2026-10-12 | Codex initial setup | Git repo initialized; minimal FastAPI backend, dependency config, README, `.gitignore`, `.env.example`, docs and tests added | `pytest`: 2 passed; backend import sanity check passed | Finish G0 decisions; manually create Apps Script project; prove Gmail-to-backend slice |
| 2026-10-12 | Codex assignment audit | `UPWIND_HOME_ASSIGNMENT.md` reviewed; assignment checklist updated; WBS 0.1 unblocked and marked complete | Documentation audit only | Verify Google/App Script access; choose HTTPS/auth plan |
| 2026-10-12 | Codex external services setup | GitHub repo reachability verified; `origin` configured; Apps Script project status and clasp sync plan documented | `git ls-remote` succeeded; no Apps Script source access verified | Decide whether to publish assignment text; verify push permissions; install/auth clasp |
| 2026-10-12 | Codex publishing policy and first sync | Permanent rule added: never commit/push `UPWIND_HOME_ASSIGNMENT.md`; file ignored; safe files committed and pushed to GitHub | `pytest`: 2 passed; secret scan/staged review passed; remote branch verified | Install/auth clasp; choose backend HTTPS/auth plan |

## 14. References

- Upwind provided assignment: `UPWIND_HOME_ASSIGNMENT.md`; external requirements are described above and mapped in `docs/assignment-checklist.md`.
- Original planning input: `Email_Threat_Monitor_WBS.md`; its proactive Chrome extension / push-monitoring assumptions are **superseded for this assignment**.
- Official Google Workspace guides (verify currency during setup):
  - https://developers.google.com/workspace/add-ons/gmail
  - https://developers.google.com/workspace/add-ons/gmail/extending-message-ui
  - https://developers.google.com/workspace/add-ons/guides/connect-third-party-service
  - https://developers.google.com/apps-script/reference/gmail/gmail-app
  - https://developers.google.com/apps-script/guides/clasp

