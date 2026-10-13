# InboxGuardian â€” 48-Hour Upwind Security Assignment WBS

> **Project status:** Backend `/analyze` and local Gmail CardService source render Method C v1 scored results; live Gmail verification pending
> **Last updated:** 2026-10-13
> **Primary context:** [PROJECT_OBJECTIVE.md](PROJECT_OBJECTIVE.md) â€” read first. Technical interface and open scoring decisions: [docs/detection-contract.md](docs/detection-contract.md).
> **Reference:** Upwind Security â€” *Gmail Add-on: Malicious Email Scorer*.
> **Time constraint:** 48-hour work plan; no phase is considered finished until its acceptance criteria are verified.

## Research question

> **How effectively can a lightweight, explainable multi-signal detection system identify suspicious and potentially malicious emails within Gmail, while minimizing false positives and clearly communicating the evidence and uncertainty behind each verdict?**

## 1. Reframed objective and boundaries

Build **InboxGuardian**, a simple, real Gmail Add-on for analyzing the **currently opened message**, backed by a separate Python analysis service. Present an **explainable heuristic risk score**, a verdict and evidence. The Upwind assignment's Gmail Add-on, backend, repo, documentation and live demonstration requirements are non-negotiable.

**Supersedes the old WBS:** This is **not** a Chrome extension, always-on Gmail threat monitor, automated notifications platform or machine-learning research project. Preserve the independent, tested engine and emphasis on false positives, but defer inbox-wide polling/watch/Pub/Sub, browser extensions, databases, LLM/external AI analysis and production distribution. A **local, separately evaluated TF-IDF/logistic regression phishing classifier** is the one approved ML exception, not an excuse to expand into a research platform.

**Product priorities:** (1) Simple Gmail UX, (2) satisfy assignment, (3) observable/evidence-backed suspicions. Explicitly treat incomplete data as unknown and do not treat risk scores as calibrated probabilities.

## 2. Work packages and time budget

Estimates are **effort allocation**, not completion guarantees. Work sequentially along the critical path but stop polishing when the integration or demonstration is at risk.

| WBS | Work package | Budget | Priority | Gate / verified deliverable |
|---|---|---:|---|---|
| 0 | Requirements, scope, tools and decisions | 4 h | P0 | G0: agreed MVP, running tools and security boundaries |
| 1 | **End-to-end Gmail â†” backend technical spike** | 12 h | P0 | G1: opened email â†’ add-on â†’ backend â†’ results card |
| 2 | Detection engine and scoring | 12 h | P0 | G2: three tested core detectors with explainable score and real Gmail result; additional approved detectors tracked as subsequent increments |
| 3 | QA, reliability, security and evaluation | 10 h | P0 | G3: passing tests, benign counterexamples, safe data handling |
| 4 | Public repo, README, deployment and interview demo | 10 h | P0 | G4: reproducible live Gmail demonstration and handoff |
| 5 | Optional enhancements / post-interview | 0 h reserved | P2 | Only after G4; never jeopardize deliverables |
| | **Total planned time** | **48 h** | | |

**Scheduling clarification:** Six detector families are approved as target scope, but the original 48-hour effort split is unchanged and **not** a guarantee that all six will be delivered. Get an evidence-backed Gmail result working before optional breadth; record unfinished approved detectors honestly.

**Integration checkpoint:** If G1 is not working near the end of its planned window, simplify backend response/detection to protect the interview demo. Do **not** continue adding detection complexity until the Google â†” backend path works. The live flow is required; a CLI-only backend is not an adequate substitute.

## 3. Definition of MVP / clear acceptance test

- [ ] Opens in **a real Gmail account**, via a newly configured **Google Workspace Gmail Add-on** (Apps Script + supported CardService UI).
- [ ] A selected/opened email can be scanned **on demand**, with simple, obvious interaction.
- [ ] A separately running backend is called successfully over authenticated **HTTPS**.
- [ ] Displays **0â€“100 heuristic risk index**, verdict, 2â€“4 readable evidence explanations and recommended action. Score is not described as a probability.
- [ ] Supports `HIGH_RISK`, `SUSPICIOUS`, `NO_SIGNIFICANT_SIGNALS`, and `INCOMPLETE`/scan failure with clear user messages.
- [ ] Detects the first **three core families** (sender identity, deceptive URLs, credential-phishing context) with conservative multi-signal correlation; **six are approved as the total target scope**, but remaining detectors must be visibly marked planned/unavailable until actually tested.
- [ ] Meaningful fixture-based tests include ordinary benign and malicious-looking examples and trace each visible warning to a signal.
- [ ] Handles missing metadata/failed backend/hostile input without disclosing data or silently labelling email safe.
- [ ] Public Git repo contains working source, secure setup/config examples, tests and complete README.
- [ ] Presenter has rehearsed safe demo emails and can articulate trade-offs/limitations.

## 4. Detailed checklist and acceptance gates

### 0.0 â€” Define, prepare, and validate feasibility (4 h, P0)

- [x] **0.1 Requirements audit:** Map each line of the Upwind assignment to concrete implementation/demo/documentation evidence; avoid feature creep. Output: `docs/assignment-checklist.md` or README subsection. **Evidence:** `UPWIND_HOME_ASSIGNMENT.md` reviewed and mapped in `docs/assignment-checklist.md`.
- [x] **0.2 Confirm product boundaries:** Gmail opened-email analysis only; no automatic inbox monitoring, Chrome UI, LLM, link fetching, malware execution, or automatic quarantine. Record English-language heuristic limitation and optional auth-metadata handling. **Evidence:** `PROJECT_OBJECTIVE.md`, `README.md`, and `docs/security-decisions.md`.
- [x] **0.3 Development baseline:** Create local project folder and Git repository; verify Python, environment tooling, relevant Google account, and ability to access Apps Script editor. Do **not** assume any Apps Script or Cloud project already exists. **Evidence:** local Git repo, Python virtual environment, FastAPI dependencies, `clasp`, Apps Script access, and real Gmail add-on verification are documented below.
- [x] **0.4 Document technical choices:** Apps Script / CardService, minimal current-message permission, Python/FastAPI backend, security controls, hosting/HTTPS plan and deployment/test-account prerequisites. Use current official Google docs for manifest/event object/scopes rather than copying old examples unexamined. **Evidence:** `README.md`, `docs/gmail-integration-runbook.md`, `docs/development-startup.md`, and `docs/security-decisions.md`.
- [x] **0.5 Lock interface and scoring semantics:** **Method C v1 approved and implemented internally (2026-10-13)**: capped detector-family contributions, deduplicated underlying evidence, zero correlation bonus, approved initial weights/caps/thresholds, verdict boundaries, coverage rules and missing-evidence semantics. **Evidence:** `docs/scoring-policy.md`, `backend/app/scoring.py`, `tests/unit/test_scoring.py`. Public `/analyze` response mapping remains separate.

**0.3 evidence:** local Git repository initialized; Python 3.14.3, `py -m pip`, Git 2.54.0, VS Code CLI, and `clasp` 3.4.1 are available; `.venv` created and dependencies installed. `pip` is not available as a bare command, but `py -m pip` works. Google account and Apps Script editor access were verified manually by the user; local `.clasp.json` points to the documented Apps Script project ID and `clasp status` works locally.

**0.4 evidence:** official Google docs were checked for Gmail add-on contextual triggers and `UrlFetchApp` external request scope; decisions and open items are recorded in `README.md`, `docs/security-decisions.md`, `docs/gmail-integration-runbook.md`, and `docs/development-startup.md`.

**External service status:** GitHub repository `https://github.com/Waffles4me/Inbox_Guardian` is reachable and configured as `origin`; first push to branch `master` succeeded. Apps Script project ID `1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs` was synchronized with `clasp`, installed/authorized as an unpublished Gmail Add-on, and verified manually in a real Gmail account. ngrok HTTPS successfully forwarded Gmail-originated requests to local FastAPI.

**Publishing policy:** `UPWIND_HOME_ASSIGNMENT.md` is authoritative for local requirement review but must never be committed or pushed. It is explicitly ignored in `.gitignore`; `git ls-files --stage -- UPWIND_HOME_ASSIGNMENT.md` and `git log --all --oneline -- UPWIND_HOME_ASSIGNMENT.md` returned no entries on 2026-10-12.

**Gate G0:** Requirements mapped, tech chosen, unknowns logged, task order approved. **Do not overdesign**; the Gmail integration spike is next.

### 1.0 â€” Working Gmail-to-backend vertical slice (12 h, P0; FIRST BUILD)

- [x] **1.1 New Google Apps Script project:** Create from scratch; set up Google Workspace Add-on project/manifest; configure Gmail contextual trigger; write simple CardService homepage/context card and **Analyze this email** button. **Evidence:** user-reported manual verification: local source was synchronized with `clasp`; unpublished add-on installed/authorized in Gmail; card displayed subject/sender and Analyze Email action.
- [x] **1.2 Minimal message access:** Request only necessary Gmail **current-message read** scope(s) and outbound `UrlFetchApp` scope; retrieve opened message ID/data using supported event token flow; document each permission. Do not assume universal mailbox read access. **Evidence:** manifest uses `gmail.addons.current.message.readonly`, `gmail.addons.execute`, and `script.external_request`; Gmail displayed selected email subject/sender.
- [x] **1.3 Backend skeleton:** Create FastAPI service with `/health` and `/analyze`; define request and response models, input size constraints, structured safe errors and network timeouts. Make `/analyze` protected, not anonymous. **Evidence:** `/analyze` requires `X-InboxGuardian-Token`; Pydantic bounds bodies/header counts; tests cover success, invalid input, missing fields, auth failures, and oversized body.
- [x] **1.4 HTTPS endpoint and authentication:** Choose a deployment approach reachable from Apps Script (e.g. controlled HTTPS hosted endpoint or secured development tunnel); store secrets outside committed source; authenticate the add-on-to-backend request; document limits and rotation. **Localhost is not reachable from Apps Script remotely.** **Evidence:** ngrok HTTPS forwarded requests to local FastAPI; token-protected `/analyze` returned 401 without valid token and 200 with valid token.
- [x] **1.5 First real integration:** A selected email â†’ permitted fields â†’ HTTPS request â†’ stubbed, clearly labelled test JSON result â†’ rendered results Card. Do not confuse a fake demonstration response with validated detection output. **Evidence:** user-reported verified flow Gmail -> Apps Script -> ngrok HTTPS -> FastAPI -> JSON -> Gmail card with `DEMO / NOT ANALYZED`.
- [x] **1.6 Real-world failures:** Show helpful states for no selected email, missing consent/permissions, rejected/expired authentication, backend timeout, invalid response and oversized message. **Evidence:** local code/tests cover auth failure, invalid input, missing fields, oversized body, unavailable/unexpected backend states; live happy path verified. Additional live failure drills remain useful but are not blocking G1.
- [x] **1.7 Validate live account:** Install/test add-on in a real consenting Gmail account, not only Apps Script preview. Verify new-message selection/context and response rendering on demo laptop. **Evidence:** unpublished add-on installed/authorized and tested in a real Gmail account; multiple successful HTTP 200 `/analyze` requests observed in Uvicorn logs.

**Gate G1 â€” achieved 2026-10-12 by user-reported manual verification:** real opened Gmail message yielded a backend-supplied `DEMO / NOT ANALYZED` result in the add-on through ngrok HTTPS. This was the connectivity milestone; backend detection was added later.

### 2.0 â€” Six-family threat detection target (12 h P0 baseline; stage work to protect G2)

**Authoritative technical design:** [`docs/detection-contract.md`](docs/detection-contract.md). Six families are approved; the first three detector families and internal Method C v1 scoring are implemented, while attachment, financial and NLP remain planned. The remaining three are staged enhancements and must not break the known-good Gmail baseline. The 12 h allocation is an initial budget, not evidence that all six can be completed; report scope/time trade-offs rather than marking incomplete work finished.

- [x] **2.1 Canonical email representation:** Safely normalize From, Reply-To, text/HTML and URL evidence with bounded processing and structured missing/malformed/truncated/unknown states. Add synthetic positive and negative parser tests. **Evidence:** `backend/app/parsing.py` and `tests/unit/test_email_parsing.py`; `pytest -q` passed 28 tests with 2 warnings on 2026-10-13. `/analyze` demo behavior and Apps Script integration were not changed.
- [x] **2.2 Sender impersonation detector:** Explain actual mismatches/lookalikes with evidence, check legitimate delegation/marketing counterexamples and missing identity. **Evidence:** `backend/app/detectors/base.py`, `backend/app/detectors/sender.py`, and `tests/unit/test_sender.py`; `pytest -q` passed 43 tests with 2 warnings on 2026-10-13. Findings are now scored and exposed through backend `/analyze`.
- [x] **2.3 Deceptive URL detector:** Parse inert HTML anchors and text URLs, compare claimed versus actual hosts, bound input and never follow links; test legitimate tracking URLs. **Evidence:** `backend/app/detectors/urls.py` and `tests/unit/test_urls.py`; `pytest -q` passed 59 tests with 2 warnings on 2026-10-13. Findings are now scored and exposed through backend `/analyze`.
- [x] **2.4 Credential-phishing context detector:** Detect requests for passwords/OTP/account verification with appropriate corroboration and legitimate-reset counterexamples; English-focused. **Evidence:** `backend/app/detectors/credentials.py` and `tests/unit/test_credentials.py`; `pytest -q` passed 84 tests with 2 warnings on 2026-10-13. Findings are now scored and exposed through backend `/analyze`.
- [ ] **2.5 Suspicious attachment metadata detector (approved, later):** Verify safe Gmail metadata collection and missing-vs-empty semantics first; then inspect extensions, double extensions, declared MIME and size without retrieving or executing binary content.
- [ ] **2.6 Payment redirection / financial fraud detector (approved, later):** Detect contextual payment-change/transfer requests with independent supporting evidence; explicitly disclaim lack of historical vendor, payment or thread context.
- [ ] **2.7 NLP phishing classifier (approved, separate experimental increment):** Establish usable labeled data, licensing/provenance, leakage-resistant evaluation and TF-IDF/logistic regression baseline; report precision, recall, F1, false-positive rate and limitations. **Do not add model score to heuristic aggregation until an evidence-backed integration decision is approved.**
- [x] **2.8 Evidence and detector-status contract / internal orchestration:** Stable IDs, `TRIGGERED` / `NOT_TRIGGERED` / `INCONCLUSIVE` / `NOT_RUN` internal outcomes, observed and redacted evidence, uncertainty/limitations; preserve `schema_version: 1.0` public API unless explicitly reviewed. **Evidence:** `backend/app/engine.py` and `tests/unit/test_engine.py`; the engine parses once, runs sender/URL/credential detectors in stable order, preserves findings/evidence/limitations, marks planned detector families as `NOT_RUN`, and does not score or change `/analyze`.
- [x] **2.9 Risk scoring policy:** Implement **approved Method C architecture** after parser/detector evidence is verified: family caps, cross-detector evidence deduplication, auditable independent corroboration, score limits, thresholds, coverage rules and `INCOMPLETE`. **Evidence:** `backend/app/scoring.py`, `tests/unit/test_scoring.py`, and `docs/scoring-policy.md`; `pytest -q` passed 132 tests with 2 warnings on 2026-10-13. Checkpoint commit: `860b489eda2871e0f71a927e87a68e93eb3299cb`.
- [x] **2.10 Human-friendly backend result:** Return meaningful finding titles/observations/interpretations, 0â€“100 heuristic risk index only where assessment is meaningful, verdict, limitations and safe recommended action. **Evidence:** `backend/app/main.py` maps engine/scorer output into the existing `AnalyzeResponse`; `INCOMPLETE` uses a documented placeholder score with explicit uncertainty.
- [x] **2.11 Automated synthetic tests:** For each implemented detector, positive triggers, plausible benign counterexamples, ambiguous/missing data, dedup/correlation and API regression coverage. Keep the previously reported 13 baseline tests passing except consciously updated demo assertions when live detection replaces stub. **Evidence:** `tests/unit/test_backend_integration_stub.py` now covers real `/analyze` output, auth, validation, suspicious/high-risk/incomplete examples, exact high-risk contribution breakdown, unavailable planned detectors, deterministic responses, failures and redaction; `pytest -q` passed 145 tests with 2 warnings on 2026-10-13.
- [x] **2.12 Gmail integration source update:** In a separate reviewed change, replace stub response and hardcoded demo UI; show real score/verdict/evidence via existing CardService route, test real selected Gmail messages, preserve authentication and privacy. **Evidence:** `addon/Code.js` renders real backend verdicts, heuristic score or score-unavailable state, up to four findings, limitations and recommended action; `tests/unit/test_addon_source.py` covers the source contract. `pytest -q` passed 151 tests with 2 warnings and `node --check addon\Code.js` passed on 2026-10-13. Live selected-message Gmail verification remains pending.

**Gate G2 (first demonstrable slice):** Real Gmail email is analyzed by **three independently tested core detectors**; backend returns a defensible, traceable heuristic score and Gmail renders the result. Capture manual vs automated verification separately. Approved attachment/financial/NLP work remains openly pending until its own verified acceptance evidence exists. Do not claim the six-detector target is fully delivered if only three work.

### 3.0 â€” Evaluation, usability, security and resilience (10 h, P0)

- [ ] **3.1 Fixture corpus:** Version a compact, documented labeled set of synthetic examples: spoof/lookalike, misleading login link, suspicious request, legitimate password-reset notification, marketing sender, benign link and insufficient-information sample; add attachment/payment positives and legitimate counterexamples when those detectors are implemented. Labels and rationale included.
- [ ] **3.2 Test protocol:** Separate examples used to tune scoring from held-out examples where feasible; if NLP is implemented, document corpus provenance and prevent train/test leakage. Run baseline simple heuristics versus correlated multi-signal logic only if credible. No fabricated performance metrics or universal accuracy claims.
- [ ] **3.3 Evaluation report:** Record confusion matrix or individually verified labeled results; note false positives, false negatives, incomplete scans, qualitative latency and dataset limits. If dataset too small for meaningful statistics, say so.
- [ ] **3.4 Security tests:** Oversized/hostile HTML, malformed URL, tricky Unicode, missing sender/header, encoded input, backend auth failure, command/prompt-like text in body, request-size limits, suspicious attachment names/metadata (when collected), and sanitized error/log messages.
- [ ] **3.5 Privacy controls:** Do not persist full messages by default; minimize uploaded fields; ensure no raw email or token in public repo, analytics, screenshots or logs. Verify handling of API credentials and HTTPS.
- [ ] **3.6 Gmail UX review:** Quick path from message to result; readable labels, no unnecessary fields, concise explanation, obvious unknown vs clean states, accessible text and error recovery.
- [ ] **3.7 End-to-end smoke tests:** Run at least one high-risk case, one benign case, one incomplete case and one backend-unavailable case in the real add-on; report observations.
- [ ] **3.8 Review source and tests:** Run formatter/linter/automated tests as applicable; fix broken imports/config, unused permissions and fragile dependencies.

**Gate G3:** Evidence-backed findings and clear UX hold up under realistic benign cases and failure modes. Security-critical omissions are documented; don't claim full production safety.

### 4.0 â€” Public deliverables and interview readiness (10 h, P0)

- [ ] **4.1 README (critical assignment deliverable):** Overview, feature scope, annotated screenshot (no private mail), architecture/data flow, environment, Google Apps Script manifest setup, necessary scopes, backend deployment/setup, demo use, scoring policy, tests/results, threats/mitigations, known gaps and roadmap.
- [x] **4.2 Version control hygiene:** `.gitignore`, `.env.example`, no credential dumps, no actual inbox content, dependencies pinned/documented. Run secret scan/manual diff before first public push. **Evidence:** `.gitignore` excludes secrets, local auth files, temp/cache files, and `UPWIND_HOME_ASSIGNMENT.md`; staged-file review and secret scan passed before first push.
- [x] **4.3 Publish public Git repository:** Include both `PROJECT_OBJECTIVE.md` and `WBS.md`, complete add-on/backend source, tests and docs; verify link is accessible and branch matches working demo. **Evidence:** pushed to `origin/master`; `git ls-remote --heads origin` verified remote branch. `UPWIND_HOME_ASSIGNMENT.md` is absent from the remote tree.
- [ ] **4.4 Runbook:** Set up Gmail add-on from scratch on demo account, start/verify backend, test endpoint, open known-safe synthetic emails, demonstrate high-risk/benign and a limitation, recover from backend outage. **Partial:** `docs/development-startup.md` now covers local backend/ngrok startup, health/auth verification, Apps Script Property checks, opening the existing add-on, shutdown, and troubleshooting. Final demo runbook still needs real detector cases and recovery rehearsal.
- [ ] **4.5 Rehearse demonstration:** 3â€“5 minutes: user journey â†’ score/verdict â†’ evidence â†’ architecture â†’ false-positive safeguards â†’ security boundaries â†’ limitations; prepare fallback screenshots only as backup, not as replacement for live functioning.
- [ ] **4.6 Upwind compliance audit:** Check required Add-on, backend, real Gmail, public repo, README and explanation against the original PDF; record any unmet requirement honestly.
- [ ] **4.7 Final handoff:** Update the objective's Session Handoff and this WBS with actual completed tasks, test evidence, deployment addresses/IDs that are **not secrets**, known defects and next actions.

**Gate G4 â€” deliverable ready:** Public repo with complete reproducible instructions; real Gmail Add-on + backend live demo; explainable signal analysis with honest limitations. Project complete only if evidence is verified.

### 5.0 â€” Post-MVP backlog (P2; zero hours allocated)

- [ ] **5.1** Calibrate risk score using a larger legitimately labeled corpus, report precision/recall with uncertainty and operational base-rate sensitivity.
- [ ] **5.2** Improved trusted authentication-result analysis and domain reputation checks (subject to security/privacy review); enhanced attachment inspection beyond approved metadata-only scope remains deferred.
- [ ] **5.3** Hebrew/multilingual context, image/QR phishing analysis, historical sender anomalies/BEC signals.
- [ ] **5.4** Feedback workflow and audit history with explicit retention/privacy governance.
- [ ] **5.5** **Original project direction:** Proactive Gmail watch, Pub/Sub ingestion, deduplicated alerts and optional Chrome extension; separate new project phase, not necessary for Upwind.

## 5. Stop/go and critical path

```text
G0: requirements + new Google environment plan
  â†“
G1: REAL GMAIL ADD-ON â†” AUTHENTICATED HTTPS BACKEND â†” CARD RESPONSE
  â†“
G2: real multi-signal engine + deterministic score + evidence + tests
  â†“
G3: threat/benign tests + security + simple UX + graceful failures
  â†“
G4: public Git repo + README + rehearsed live interview demo
```

**Priority hierarchy if delayed:** (1) working Gmail Add-on + backend, (2) score/verdict/evidence, (3) three tested core detectors, (4) security/docs/live demo, (5) two more approved deterministic families, (6) approved NLP experiment if credible labeled data exists. All undelivered approved families remain marked planned; no misleading completion claims. Do not cut mandatory repository/README or essential security controls to create flashy extras.

## 6. Suggested repo structure

```text
inboxguardian/
â”œâ”€â”€ PROJECT_OBJECTIVE.md
â”œâ”€â”€ WBS.md
â”œâ”€â”€ README.md
â”œâ”€â”€ addon/                  # New Google Apps Script project source and manifest
â”œâ”€â”€ backend/app/            # FastAPI schemas, parsers, detectors, scoring
â”œâ”€â”€ tests/fixtures/         # Safe, labeled, synthetic emails
â”œâ”€â”€ tests/unit/
â”œâ”€â”€ tests/integration/
â”œâ”€â”€ docs/                   # Detection contract, architecture, scoring, decisions, security, demo
â”œâ”€â”€ .env.example            # Examples only, never real keys
â””â”€â”€ .gitignore
```

## 7. Agent usage and checklist discipline

- Read `PROJECT_OBJECTIVE.md` **first**, then this WBS and current repository state.
- Work on the next **P0 unchecked item** in the current gate, preferring the smallest tested end-to-end increment.
- Mark `[x]` **only after verifying the deliverable**. Add relevant file/test/commit evidence in the session handoff.
- Update **both files after every work session** (project status, decisions, task checkboxes, blockers, next step). Update README for changing setup and behavior.
- Avoid unapproved scope expansion, breaking changes, personal data exposure and false claims of tests/deployment.
- Source documents and official Google docs override outdated assumptions. Log all important design/permission decisions.

## 8. Current state / next actions

**As of 2026-10-13:** Gmail-to-backend integration proof of concept is complete and manually reconfirmed earlier on 2026-10-13. `UPWIND_HOME_ASSIGNMENT.md` has been reviewed and mapped to `docs/assignment-checklist.md`, but permanent policy forbids committing or pushing that assignment file. Local Git repository, FastAPI backend, Apps Script add-on source, README, `.gitignore`, `.env.example`, docs, and tests exist. Public GitHub repo is reachable, configured as `origin`, and synchronized on branch `master`. Backend `/analyze` returns real parser -> engine -> Method C scorer output in schema `1.0`; local Apps Script/Gmail UI source now renders those real results. This UI source has not been pushed to Apps Script or manually verified live.

**Documentation reconciliation (2026-10-13):** Six families are approved in `PROJECT_OBJECTIVE.md` and `docs/detection-contract.md`: sender identity, deceptive URLs, credential context, suspicious attachment metadata, financial fraud, and NLP classifier. **Method C correlation-aware, category-capped scoring architecture is approved, but not implemented**. The contract is still a **draft**; scoring weights, caps, correlation bonuses, threshold cutoffs, minimum coverage, metadata availability and NLP dataset remain undecided. No detector code was implemented. User reconfirmed local/tunneled `/health`, 401 unauthenticated `/analyze`, authenticated demo response and Gmail demo result. The earlier automated baseline was **reported** as 13 passed, 2 warnings; no tests were rerun in this documentation edit. Local Git state and remote sync following these new documents are **not verified**.

**WBS 2.1 implementation (2026-10-13):** Safe backend-internal parser/normalizer added in `backend/app/parsing.py` with synthetic tests in `tests/unit/test_email_parsing.py`. It parses From/Reply-To into explicit statuses, extracts inert visible HTML text and anchors, parses text/HTML HTTP(S) URL structure, retains unsupported/malformed link evidence, normalizes IDNA hostnames, redacts query/fragment from display-safe URL forms, deduplicates exact canonical URL evidence, and enforces documented bounds. It is now used by backend `/analyze`.

**WBS 2.2 implementation (2026-10-13):** Added the backend-internal detector package with a shared result contract and sender detector. Implemented conservative rules for unrelated From/Reply-To domain differences and explicit display-name domain claim mismatches. Missing or malformed identity data returns `INCONCLUSIVE`; matching domains, missing Reply-To, display-name/local-part differences, and conservative same/subdomain relationships do not trigger. Findings are now scored and exposed through backend `/analyze`.

**WBS 2.3 implementation (2026-10-13):** Added the backend-internal deceptive URL detector. Implemented conservative rules for displayed URL host vs actual destination mismatch, displayed-host prefix subdomain deception, literal IP-address hosts, and hostname-like URL userinfo. Missing links return `NOT_TRIGGERED` with limitations; malformed or unsupported-only URL evidence returns `INCONCLUSIVE`. Findings are now scored and exposed through backend `/analyze`.

**WBS 2.4 implementation (2026-10-13):** Added the backend-internal credential-context detector. Implemented conservative English-language rules for password/OTP/security-code collection requests, account verification language with link evidence, urgent account threat language, credential requests with links, and instructions to bypass normal security channels. Missing or ambiguous credential-related language returns `INCONCLUSIVE`; urgency alone, legitimate password-reset/MFA notices, generic password mentions, and normal account-security newsletters do not trigger. Findings redact code-like values and are now scored and exposed through backend `/analyze`.

**Internal orchestration implementation (2026-10-13):** Added `backend/app/engine.py` to parse a validated `EmailPayload` once, run the three implemented detectors in deterministic order, preserve detector statuses/findings/evidence/limitations, and represent attachment, financial and NLP families as planned `NOT_RUN` checks. The engine does not score, assign verdicts, deduplicate or correlate evidence, change the public API, or wire into `/analyze`.

**Scoring specification approval (2026-10-13):** Recorded approved Method C v1 scoring policy in `docs/scoring-policy.md`. It inventories implemented finding IDs, approved rule contributions, family caps, verdict thresholds, coverage/INCOMPLETE handling, and zero correlation bonus.

**WBS 2.9 implementation (2026-10-13):** Added Method C v1 scorer in `backend/app/scoring.py` with tests in `tests/unit/test_scoring.py`. The scorer consumes `EngineResult`, maps approved finding IDs to weights, deduplicates repeated evidence, reconciles overlapping URL and credential-link context, applies family caps, computes a bounded heuristic risk index, evaluates coverage, assigns an internal verdict, and records accounting. Checkpoint commit: `860b489eda2871e0f71a927e87a68e93eb3299cb`.

**Backend response-mapping implementation (2026-10-13):** Updated `backend/app/main.py` so authenticated `/analyze` calls the existing engine once, scores the `EngineResult`, maps scored findings into the existing public `AnalyzeResponse`, returns evidence-consistent recommendations, preserves auth and validation behavior, and returns bounded HTTP 500 errors for unexpected route-level failures. `INCOMPLETE` uses `risk_score: 0` only as a required-schema placeholder with explicit uncertainty while preserving positive warning findings. Updated `tests/unit/test_backend_integration_stub.py`; `pytest -q` passed 145 tests with 2 warnings.

**Gmail CardService result-source implementation (2026-10-13):** Updated `addon/Code.js` so the result card displays human-readable verdicts, a heuristic risk index for complete results, `Risk score unavailable` for `INCOMPLETE`, up to four backend findings, limitations and recommended action. Backend-provided text is escaped before insertion into CardService widgets; no suspicious links are made clickable. Updated add-on source tests; live Apps Script synchronization was not performed.

**Next session/task:** After review, run the approved Apps Script synchronization path and manually verify Gmail -> ngrok -> FastAPI real-result rendering for benign, suspicious/high-risk and incomplete synthetic messages. Do not start WBS 2.5 attachment detection, implement NLP, deploy, or push without separate authorization.

## 9. References and design provenance

**Assignment (user-supplied):** `UPWIND_HOME_ASSIGNMENT.md`.
**Technical scope and score decisions:** [`docs/detection-contract.md`](docs/detection-contract.md).
**Original planning baseline:** `Email_Threat_Monitor_WBS.md`, revised/superseded here to reflect the interviewer-facing Gmail Add-on instead of proactive monitoring.
**Official guides to validate against while building:**
- https://developers.google.com/workspace/add-ons/gmail
- https://developers.google.com/workspace/add-ons/gmail/extending-message-ui
- https://developers.google.com/workspace/add-ons/guides/connect-third-party-service
- https://developers.google.com/apps-script/reference/gmail/gmail-app
