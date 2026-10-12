# InboxGuardian — 48-Hour Upwind Security Assignment WBS

> **Project status:** PLANNING — not built  
> **Last updated:** 2026-10-12  
> **Primary context:** [PROJECT_OBJECTIVE.md](PROJECT_OBJECTIVE.md) — read first.  
> **Reference:** Upwind Security — *Gmail Add-on: Malicious Email Scorer*.  
> **Time constraint:** 48-hour work plan; no phase is considered finished until its acceptance criteria are verified.

## Research question

> **How effectively can a lightweight, explainable multi-signal detection system identify suspicious and potentially malicious emails within Gmail, while minimizing false positives and clearly communicating the evidence and uncertainty behind each verdict?**

## 1. Reframed objective and boundaries

Build **InboxGuardian**, a simple, real Gmail Add-on for analyzing the **currently opened message**, backed by a separate Python analysis service. Present an **explainable heuristic risk score**, a verdict and evidence. The Upwind assignment's Gmail Add-on, backend, repo, documentation and live demonstration requirements are non-negotiable.

**Supersedes the old WBS:** This is **not** a Chrome extension, always-on Gmail threat monitor, automated notifications platform or machine-learning research project. Preserve the independent, tested engine and emphasis on false positives, but defer inbox-wide polling/watch/Pub/Sub, browser extensions, databases, AI analysis and production distribution.

**Product priorities:** (1) Simple Gmail UX, (2) satisfy assignment, (3) observable/evidence-backed suspicions. Explicitly treat incomplete data as unknown and do not treat risk scores as calibrated probabilities.

## 2. Work packages and time budget

Estimates are **effort allocation**, not completion guarantees. Work sequentially along the critical path but stop polishing when the integration or demonstration is at risk.

| WBS | Work package | Budget | Priority | Gate / verified deliverable |
|---|---|---:|---|---|
| 0 | Requirements, scope, tools and decisions | 4 h | P0 | G0: agreed MVP, running tools and security boundaries |
| 1 | **End-to-end Gmail ↔ backend technical spike** | 12 h | P0 | G1: opened email → add-on → backend → results card |
| 2 | Detection engine and scoring | 12 h | P0 | G2: three deterministic, explained signal families with tests |
| 3 | QA, reliability, security and evaluation | 10 h | P0 | G3: passing tests, benign counterexamples, safe data handling |
| 4 | Public repo, README, deployment and interview demo | 10 h | P0 | G4: reproducible live Gmail demonstration and handoff |
| 5 | Optional enhancements / post-interview | 0 h reserved | P2 | Only after G4; never jeopardize deliverables |
| | **Total planned time** | **48 h** | | |

**Integration checkpoint:** If G1 is not working near the end of its planned window, simplify backend response/detection to protect the interview demo. Do **not** continue adding detection complexity until the Google ↔ backend path works. The live flow is required; a CLI-only backend is not an adequate substitute.

## 3. Definition of MVP / clear acceptance test

- [ ] Opens in **a real Gmail account**, via a newly configured **Google Workspace Gmail Add-on** (Apps Script + supported CardService UI).
- [ ] A selected/opened email can be scanned **on demand**, with simple, obvious interaction.
- [ ] A separately running backend is called successfully over authenticated **HTTPS**.
- [ ] Displays **0–100 heuristic risk index**, verdict, 2–4 readable evidence explanations and recommended action. Score is not described as a probability.
- [ ] Supports `HIGH_RISK`, `SUSPICIOUS`, `NO_SIGNIFICANT_SIGNALS`, and `INCOMPLETE`/scan failure with clear user messages.
- [ ] Detects at least 3 families: sender identity, deceptive URLs, and credential-phishing context, with conservative multi-signal correlation.
- [ ] Meaningful fixture-based tests include ordinary benign and malicious-looking examples and trace each visible warning to a signal.
- [ ] Handles missing metadata/failed backend/hostile input without disclosing data or silently labelling email safe.
- [ ] Public Git repo contains working source, secure setup/config examples, tests and complete README.
- [ ] Presenter has rehearsed safe demo emails and can articulate trade-offs/limitations.

## 4. Detailed checklist and acceptance gates

### 0.0 — Define, prepare, and validate feasibility (4 h, P0)

- [x] **0.1 Requirements audit:** Map each line of the Upwind assignment to concrete implementation/demo/documentation evidence; avoid feature creep. Output: `docs/assignment-checklist.md` or README subsection. **Evidence:** `UPWIND_HOME_ASSIGNMENT.md` reviewed and mapped in `docs/assignment-checklist.md`.
- [x] **0.2 Confirm product boundaries:** Gmail opened-email analysis only; no automatic inbox monitoring, Chrome UI, LLM, link fetching, malware execution, or automatic quarantine. Record English-language heuristic limitation and optional auth-metadata handling. **Evidence:** `PROJECT_OBJECTIVE.md`, `README.md`, and `docs/security-decisions.md`.
- [ ] **0.3 Development baseline:** Create local project folder and Git repository; verify Python, environment tooling, relevant Google account, and ability to access Apps Script editor. Do **not** assume any Apps Script or Cloud project already exists.
- [ ] **0.4 Document technical choices:** Apps Script / CardService, minimal current-message permission, Python/FastAPI backend, security controls, hosting/HTTPS plan and deployment/test-account prerequisites. Use current official Google docs for manifest/event object/scopes rather than copying old examples unexamined.
- [ ] **0.5 Lock interface and scoring semantics:** Draft bounded input fields, detector findings, output schema, verdict meaning, unknowns and expected error responses. Ensure every score component can be accounted for. **Partial:** backend request/response models exist, but scoring semantics are not locked.

**0.3 partial evidence:** local Git repository initialized; Python 3.14.3, `py -m pip`, Git 2.54.0, and VS Code CLI are available; `.venv` created and dependencies installed. `pip` is not available as a bare command, but `py -m pip` works. Node/npm/clasp are not installed. Google account and Apps Script editor access were verified manually by the user, but agent/source access was not verified.

**0.4 partial evidence:** official Google docs were checked for Gmail add-on contextual triggers and `UrlFetchApp` external request scope; open decisions remain in `README.md` and `docs/security-decisions.md`.

**External service status:** GitHub repository `https://github.com/Waffles4me/Inbox_Guardian` is reachable and configured as `origin`; first push to branch `master` succeeded. The user manually verified Apps Script project creation and test function execution for project ID `1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs`; agent/source access is not verified. Local Apps Script synchronization should use `clasp`, but Node/npm/clasp installation and Google OAuth login remain manual prerequisites.

**Publishing policy:** `UPWIND_HOME_ASSIGNMENT.md` is authoritative for local requirement review but must never be committed or pushed. It is explicitly ignored in `.gitignore`; `git ls-files --stage -- UPWIND_HOME_ASSIGNMENT.md` and `git log --all --oneline -- UPWIND_HOME_ASSIGNMENT.md` returned no entries on 2026-10-12.

**Gate G0:** Requirements mapped, tech chosen, unknowns logged, task order approved. **Do not overdesign**; the Gmail integration spike is next.

### 1.0 — Working Gmail-to-backend vertical slice (12 h, P0; FIRST BUILD)

- [ ] **1.1 New Google Apps Script project:** Create from scratch; set up Google Workspace Add-on project/manifest; configure Gmail contextual trigger; write simple CardService homepage/context card and **Analyze this email** button.
- [ ] **1.2 Minimal message access:** Request only necessary Gmail **current-message read** scope(s) and outbound `UrlFetchApp` scope; retrieve opened message ID/data using supported event token flow; document each permission. Do not assume universal mailbox read access.
- [ ] **1.3 Backend skeleton:** Create FastAPI service with `/health` and `/analyze`; define request and response models, input size constraints, structured safe errors and network timeouts. Make `/analyze` protected, not anonymous.
- [ ] **1.4 HTTPS endpoint and authentication:** Choose a deployment approach reachable from Apps Script (e.g. controlled HTTPS hosted endpoint or secured development tunnel); store secrets outside committed source; authenticate the add-on-to-backend request; document limits and rotation. **Localhost is not reachable from Apps Script remotely.**
- [ ] **1.5 First real integration:** A selected email → permitted fields → HTTPS request → stubbed, clearly labelled test JSON result → rendered results Card. Do not confuse a fake demonstration response with validated detection output.
- [ ] **1.6 Real-world failures:** Show helpful states for no selected email, missing consent/permissions, rejected/expired authentication, backend timeout, invalid response and oversized message.
- [ ] **1.7 Validate live account:** Install/test add-on in a real consenting Gmail account, not only Apps Script preview. Verify new-message selection/context and response rendering on demo laptop.

**Gate G1 — highest priority:** Video/screenshot/log evidence of real opened Gmail message yielding a backend-supplied result **in the add-on**; no private content or secrets shown in evidence. If blocked, document precise issue and reduce scope until working.

### 2.0 — Independent multi-signal threat detection engine (12 h, P0)

- [ ] **2.1 Canonical email representation:** Safe bounded normalization for `From`, `Reply-To`, subject, text/HTML, links, optional verified headers; handle missing/malformed fields, encodings and Unicode hostnames. Do not execute email HTML or retrieve external resources.
- [ ] **2.2 Sender identity detector:** Test address/Reply-To inconsistencies, obvious lookalikes when grounded; avoid treating legitimate delegated/marketing sends as automatically malicious.
- [ ] **2.3 URL deception detector:** Extract HTML anchor `href` and visible text safely, compare destination to claimed display/identity, detect misleading URL patterns; **never follow URLs**. Include legit tracking/redirect-style counterexamples.
- [ ] **2.4 Credential-phishing context detector:** Identify requests for login codes/passwords/account verification combined with other evidence. Urgency or the word "password" alone is weak and not conclusive.
- [ ] **2.5 Optional authentication detector:** Use SPF/DKIM/DMARC only when trusted provenance can be established with available API/message data; otherwise mark unknown. Optional attachment metadata only if core three families completed.
- [ ] **2.6 Evidence contract:** Every detector emits stable finding ID, original observation (redacted appropriately), interpretation, severity, and test provenance; no ungrounded explanations.
- [ ] **2.7 Risk aggregation:** Version explicit rules/weights, threshold mapping, correlation logic and deduplication; avoid double counting overlapping signals; enumerate or explain all score contributions. Missing signals do not reduce risk score as if cleared.
- [ ] **2.8 Human-friendly result:** 2–4 top findings, contextual action, clear limitations and uncertainty; no "100% malicious", "safe", or probabilistic interpretation unless supported by data.
- [ ] **2.9 Unit tests:** Positive and benign counterexamples for each detector plus aggregation/boundary cases. Ensure fixtures are synthetic/inert.
- [ ] **2.10 Integration:** Replace G1's stub result with real engine; verify all four verdict/availability states in actual add-on or via contract tests.

**Gate G2:** Live Gmail message is evaluated by independent backend detectors and returns explanation-consistent scoring. Three detectors and tests pass. Preserve a working known-good demo branch/commit.

### 3.0 — Evaluation, usability, security and resilience (10 h, P0)

- [ ] **3.1 Fixture corpus:** Version a compact, documented labeled set of synthetic examples: spoof/lookalike, misleading login link, suspicious request, legitimate password-reset notification, marketing sender, benign link and insufficient-information sample. Labels and rationale included.
- [ ] **3.2 Test protocol:** Separate examples used to tune scoring from held-out examples where feasible; run baseline simple heuristics versus correlated multi-signal logic only if credible. No fabricated performance metrics or universal accuracy claims.
- [ ] **3.3 Evaluation report:** Record confusion matrix or individually verified labeled results; note false positives, false negatives, incomplete scans, qualitative latency and dataset limits. If dataset too small for meaningful statistics, say so.
- [ ] **3.4 Security tests:** Oversized/hostile HTML, malformed URL, tricky Unicode, missing sender/header, encoded input, backend auth failure, command/prompt-like text in body, request-size limits and sanitized error/log messages.
- [ ] **3.5 Privacy controls:** Do not persist full messages by default; minimize uploaded fields; ensure no raw email or token in public repo, analytics, screenshots or logs. Verify handling of API credentials and HTTPS.
- [ ] **3.6 Gmail UX review:** Quick path from message to result; readable labels, no unnecessary fields, concise explanation, obvious unknown vs clean states, accessible text and error recovery.
- [ ] **3.7 End-to-end smoke tests:** Run at least one high-risk case, one benign case, one incomplete case and one backend-unavailable case in the real add-on; report observations.
- [ ] **3.8 Review source and tests:** Run formatter/linter/automated tests as applicable; fix broken imports/config, unused permissions and fragile dependencies.

**Gate G3:** Evidence-backed findings and clear UX hold up under realistic benign cases and failure modes. Security-critical omissions are documented; don't claim full production safety.

### 4.0 — Public deliverables and interview readiness (10 h, P0)

- [ ] **4.1 README (critical assignment deliverable):** Overview, feature scope, annotated screenshot (no private mail), architecture/data flow, environment, Google Apps Script manifest setup, necessary scopes, backend deployment/setup, demo use, scoring policy, tests/results, threats/mitigations, known gaps and roadmap.
- [x] **4.2 Version control hygiene:** `.gitignore`, `.env.example`, no credential dumps, no actual inbox content, dependencies pinned/documented. Run secret scan/manual diff before first public push. **Evidence:** `.gitignore` excludes secrets, local auth files, temp/cache files, and `UPWIND_HOME_ASSIGNMENT.md`; staged-file review and secret scan passed before first push.
- [x] **4.3 Publish public Git repository:** Include both `PROJECT_OBJECTIVE.md` and `WBS.md`, complete add-on/backend source, tests and docs; verify link is accessible and branch matches working demo. **Evidence:** pushed to `origin/master`; `git ls-remote --heads origin` verified remote branch. `UPWIND_HOME_ASSIGNMENT.md` is absent from the remote tree.
- [ ] **4.4 Runbook:** Set up Gmail add-on from scratch on demo account, start/verify backend, test endpoint, open known-safe synthetic emails, demonstrate high-risk/benign and a limitation, recover from backend outage.
- [ ] **4.5 Rehearse demonstration:** 3–5 minutes: user journey → score/verdict → evidence → architecture → false-positive safeguards → security boundaries → limitations; prepare fallback screenshots only as backup, not as replacement for live functioning.
- [ ] **4.6 Upwind compliance audit:** Check required Add-on, backend, real Gmail, public repo, README and explanation against the original PDF; record any unmet requirement honestly.
- [ ] **4.7 Final handoff:** Update the objective's Session Handoff and this WBS with actual completed tasks, test evidence, deployment addresses/IDs that are **not secrets**, known defects and next actions.

**Gate G4 — deliverable ready:** Public repo with complete reproducible instructions; real Gmail Add-on + backend live demo; explainable signal analysis with honest limitations. Project complete only if evidence is verified.

### 5.0 — Post-MVP backlog (P2; zero hours allocated)

- [ ] **5.1** Calibrate risk score using a larger legitimately labeled corpus, report precision/recall with uncertainty and operational base-rate sensitivity.
- [ ] **5.2** Improved trusted authentication-result analysis, domain reputation checks (subject to security/privacy review), attachment metadata.
- [ ] **5.3** Hebrew/multilingual context, image/QR phishing analysis, historical sender anomalies/BEC signals.
- [ ] **5.4** Feedback workflow and audit history with explicit retention/privacy governance.
- [ ] **5.5** **Original project direction:** Proactive Gmail watch, Pub/Sub ingestion, deduplicated alerts and optional Chrome extension; separate new project phase, not necessary for Upwind.

## 5. Stop/go and critical path

```text
G0: requirements + new Google environment plan
  ↓
G1: REAL GMAIL ADD-ON ↔ AUTHENTICATED HTTPS BACKEND ↔ CARD RESPONSE
  ↓
G2: real multi-signal engine + deterministic score + evidence + tests
  ↓
G3: threat/benign tests + security + simple UX + graceful failures
  ↓
G4: public Git repo + README + rehearsed live interview demo
```

**Priority hierarchy if delayed:** (1) working Gmail Add-on + backend, (2) score/verdict/evidence, (3) three detectors/test cases, (4) polished UX/security/docs, (5) optional features. Do not cut mandatory repository/README or essential security controls to create flashy extras.

## 6. Suggested repo structure

```text
inboxguardian/
├── PROJECT_OBJECTIVE.md
├── WBS.md
├── README.md
├── addon/                  # New Google Apps Script project source and manifest
├── backend/app/            # FastAPI schemas, parsers, detectors, scoring
├── tests/fixtures/         # Safe, labeled, synthetic emails
├── tests/unit/
├── tests/integration/
├── docs/                   # Architecture, scoring, decisions, security, demo
├── .env.example            # Examples only, never real keys
└── .gitignore
```

## 7. Agent usage and checklist discipline

- Read `PROJECT_OBJECTIVE.md` **first**, then this WBS and current repository state.
- Work on the next **P0 unchecked item** in the current gate, preferring the smallest tested end-to-end increment.
- Mark `[x]` **only after verifying the deliverable**. Add relevant file/test/commit evidence in the session handoff.
- Update **both files after every work session** (project status, decisions, task checkboxes, blockers, next step). Update README for changing setup and behavior.
- Avoid unapproved scope expansion, breaking changes, personal data exposure and false claims of tests/deployment.
- Source documents and official Google docs override outdated assumptions. Log all important design/permission decisions.

## 8. Current state / next actions

**As of 2026-10-12:** Initial local setup completed. `UPWIND_HOME_ASSIGNMENT.md` has been reviewed and mapped to `docs/assignment-checklist.md`, but permanent policy forbids committing or pushing that assignment file. Local Git repository, minimal structure, FastAPI skeleton, dependency config, README, `.gitignore`, `.env.example`, docs, and skeleton tests exist. Public GitHub repo is reachable, configured as `origin`, and synchronized on branch `master`. Apps Script project creation/basic execution was manually verified by the user, but local synchronization is not configured. No Gmail integration, backend deployment, or threat detection engine is assumed.

**Next session:** Finish unresolved G0 items: install/authenticate clasp or document a browser-only workflow, choose HTTPS hosting/tunnel and backend auth, and confirm exact current-message Gmail scopes. Then progress to `1.1–1.5` to prove a selected Gmail email can round-trip through a reachable protected backend and render a result.

## 9. References and design provenance

**Assignment (user-supplied):** `UPWIND_HOME_ASSIGNMENT.md`.  
**Original planning baseline:** `Email_Threat_Monitor_WBS.md`, revised/superseded here to reflect the interviewer-facing Gmail Add-on instead of proactive monitoring.  
**Official guides to validate against while building:**
- https://developers.google.com/workspace/add-ons/gmail
- https://developers.google.com/workspace/add-ons/gmail/extending-message-ui
- https://developers.google.com/workspace/add-ons/guides/connect-third-party-service
- https://developers.google.com/apps-script/reference/gmail/gmail-app
