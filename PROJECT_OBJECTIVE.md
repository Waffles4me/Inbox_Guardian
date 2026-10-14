# InboxGuardian — Project Objective & Agent Operating Guide

> **Status:** InboxGuardian V1.0.0 is published on GitHub (tag `v1.0.0`, commit `fdf9289`): a stable three-detector prototype with a user-verified Gmail dashboard, not production-grade protection. WBS 2.5 Stage 1 attachment metadata collection is implemented on branch `wbs-2.5-stage1` (not committed or synchronized); no attachment detector exists yet. The demonstration rehearsal and the dashboard screenshot are still outstanding
> **Last updated:** 2026-10-14
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
4. **[`docs/detection-contract.md`](docs/detection-contract.md)** defines the current six-detector target, data/evidence interfaces, unknowns, test gates, Method C scoring semantics, backend response mapping and Gmail result presentation source behavior. It was reconciled with the implementation on 2026-10-13; this document and `WBS.md` carry the latest handoff state.
5. Code and tests show what is actually implemented. Where code diverges from this guide, **report the discrepancy**; do not silently rewrite requirements to fit code.
6. The local project directory is the development source of truth. GitHub is the remote version-controlled repository once synchronization is verified.

The assignment explicitly requires:
- A **Gmail Add-on**, built with **Google Workspace APIs**, that works on an **opened email**; the add-on is the product users see first.
- A **backend service** that the add-on calls.
- A **maliciousness score, clear verdict, and explanation** shown in the add-on.
- A **public Git repository** containing complete add-on/backend source and a professional root `README.md` with setup, architecture, rationale, and evaluation/limitations.
- Deployment to a **real Gmail account** and a **live demonstration** on the developer's own laptop.
- Explicit attention to product choices, design, code quality, untrusted input, sensitive data, and trade-offs.

Not mandated by Upwind: continuous background monitoring, Chrome extensions, push notifications, LLMs, malware sandboxing, production rollout, or arbitrary feature count. Machine learning is approved only for the scoped NLP-based phishing classifier described below. **Do not build unapproved extras in the MVP.**

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

Checked items are supported by the evidence recorded in `WBS.md` as of 2026-10-13: automated tests for the backend and add-on, and user-performed Gmail checks. Three of the six detector families are implemented and the other three are reported as not checked. The synthetic samples are JSON, not `.eml`. The public-repository item was met by the V1.0.0 publication on 2026-10-13; the published README has no screenshot yet, by decision. The rehearsal item stays open until the demonstration is rehearsed.

- [x] Newly created **Google Apps Script / Google Workspace Gmail Add-on** installed on a **real test Gmail account**; contextual view for the opened email.
- [x] User explicitly initiates analysis via a simple, visible action (or an equally clear contextual user flow); the UI identifies the current email and does not silently scan the whole inbox.
- [x] Add-on sends only necessary email fields to a **separate, reachable Python/FastAPI backend** through an authenticated/authorized, HTTPS-protected interface; integration tested live.
- [x] Backend validates and safely normalizes inputs and returns a **versioned JSON contract** containing risk index (0–100), verdict, detector evidence, limitations/unknowns, and recommended action.
- [x] Exactly the **six approved threat detectors** documented below are implemented or explicitly marked as planned: sender impersonation, deceptive URLs, credential-phishing context, suspicious attachments, payment redirection / financial fraud, and NLP-based phishing classification. Do not add standalone SPF/DKIM/DMARC, historical sender profiling, QR/image, malware sandbox, or LLM-based detectors without separate approval.
- [x] Conservative deterministic **multi-signal correlation**; neither a single generic keyword nor missing metadata is treated as proof of malice.
- [x] User sees one of: **High risk**, **Suspicious**, **No significant suspicious signals found**, or **Unable to assess / Incomplete**; no definitive "safe" designation.
- [x] User sees **2–4 plain-language findings**, a way to identify contributing evidence, and a specific safe next action; no automatic opening of suspicious URLs.
- [x] Labeled safe synthetic `.eml`/JSON samples include malicious-looking and benign edge cases; automated tests evaluate both and report a confusion matrix or transparent per-case outcomes, plus known limitations.
- [x] Backend never executes attachments, follows untrusted links, or treats message text as instructions. Secrets are outside Git; request validation, size limits, error handling, and sensitive log redaction exist.
- [x] Public Git repo contains runnable source, tests, safe config examples, a root `README.md`, architecture sketch, setup instructions, explanation of score, security trade-offs, and demo steps.
- [ ] Demonstration rehearsed end to end using a real Gmail account and safe test messages; errors and fallback plan documented.

### Explicitly deferred

- Chrome extension, proactive inbox watcher, Gmail push/Pub/Sub, browser notifications, account-wide scanning, multi-user admin, auto-quarantine, malware sandbox execution, QR/image OCR, historic sender baseline, production reputation APIs, LLM-based verdicts, statistical calibration claims, Google Marketplace publication.
- Attachment analysis is limited to **metadata-only** inspection under the approved Suspicious Attachments detector; no binary execution, detonation, macro execution, unpacking, or malware sandboxing.

## Approved Threat Detection Scope

This project has exactly **six approved threat detectors**. As of 2026-10-13, sender identity, deceptive URL, and credential-context detectors are implemented and wired through backend `/analyze` via the internal orchestration layer and Method C v1 scorer. Attachment metadata, financial fraud and NLP remain planned/unavailable. The Gmail CardService source renders real backend results and has been synchronized to the existing Apps Script project; benign, credential-phishing, multi-signal deceptive URL, backend-unavailable and `INCOMPLETE` live Gmail scenarios were manually verified.

The six detectors should share a common evidence model: each finding must include a stable ID, severity, observable evidence, interpretation, contribution to the heuristic risk index, known limitations, and likely benign explanations where relevant.

### 1. Sender Impersonation

- **Status:** Implemented and wired into backend `/analyze`.
- **Purpose:** Detect suspicious sender identities that may misrepresent an individual, brand, service, or organization.
- **Threat or attack technique addressed:** Brand impersonation, executive impersonation, supplier impersonation, reply-to redirection, and lookalike-domain social engineering.
- **Observable indicators:** Display-name and address mismatch, sender name claiming a known service while using an unrelated domain, Reply-To domain different from From domain, visually similar domains, unusual subdomains, and non-obvious free-mail or delegated senders.
- **Intended implementation approach:** Parse and normalize From and Reply-To safely; compare display names, domains, and organizational hints; check for simple lookalike patterns without making reputation claims; treat legitimate third-party senders, mailing platforms, and delegated senders as important counterexamples.
- **Expected output:** Evidence-backed findings such as `sender_reply_to_mismatch` or `sender_lookalike_domain`, with the observed fields, why they are suspicious, and a recommended verification action.
- **Known limitations and potential false positives:** Gmail-provided message fields may be incomplete; some legitimate services use third-party senders or separate reply handling; lookalike detection is heuristic and cannot prove domain ownership or malicious intent.

### 2. Deceptive URLs

- **Status:** Implemented and wired into backend `/analyze`.
- **Purpose:** Identify misleading or suspicious hyperlinks without visiting them.
- **Threat or attack technique addressed:** Link deception, credential-harvesting links, misleading display text, malicious-looking redirects, and suspicious URL construction.
- **Observable indicators:** Displayed URL or domain differs from destination host, link text claims one brand/domain while `href` points elsewhere, IP-address hosts, suspiciously deep or noisy subdomains, URL shorteners or redirect-looking paths, punycode/unicode lookalikes, and credential-themed paths.
- **Intended implementation approach:** Safely extract links from text and HTML; normalize URLs and domains; compare visible text, claimed domains, sender domain, and destination host; flag suspicious structures while avoiding the rule that every unfamiliar URL is malicious.
- **Expected output:** Findings that name the visible text and destination relationship, the structural concern, and the uncertainty around benign tracking, marketing, or outsourced login infrastructure.
- **Known limitations and potential false positives:** The detector will not fetch, expand, or reputation-check URLs by default; legitimate email platforms often use tracking and redirect domains; unfamiliar domains alone are weak evidence.

### 3. Credential-Phishing Context

- **Status:** Implemented and wired into backend `/analyze`.
- **Purpose:** Detect attempts to obtain passwords, login approvals, MFA/OTP codes, or authentication actions.
- **Threat or attack technique addressed:** Credential phishing, account takeover preparation, MFA fatigue or OTP theft, and urgent fake verification workflows.
- **Observable indicators:** Requests to enter or reset passwords, verify account access, provide MFA/OTP/security codes, click login or document-access links, act under deadline pressure, avoid normal channels, or ignore prior security warnings.
- **Intended implementation approach:** Analyze subject and body text with conservative English-language heuristics; require corroborating evidence where possible, such as sender inconsistency, deceptive links, or unusual urgency; avoid treating generic account-security language as conclusive on its own.
- **Expected output:** Findings that separate the credential-related language observed from the inference that it may be phishing, plus a safe action such as navigating directly to the service.
- **Known limitations and potential false positives:** Legitimate password resets and security notices often contain similar language; first-version linguistic heuristics are English-focused; context may be missing from shortened email excerpts.

### 4. Suspicious Attachments

- **Status:** Approved / planned. Not implemented yet. Metadata-only analysis is approved; attachment execution or detonation is not.
- **Purpose:** Inspect attachment metadata for potentially dangerous or misleading file characteristics.
- **Threat or attack technique addressed:** Attachment-based phishing, malware delivery attempts, misleading file naming, and high-risk document or script delivery.
- **Observable indicators:** High-risk extensions, double extensions, misleading filenames, archive or executable-like names, macro-enabled document extensions, MIME-type and filename mismatch, unusually large or missing attachment metadata, and attachment claims inconsistent with the message context.
- **Intended implementation approach:** Analyze only metadata supplied to the backend, such as filename, content type, and size; normalize filenames safely; compare extension and MIME type; never open, execute, unpack, render, or detonate attachment content.
- **Expected output:** Findings that describe the attachment metadata concern and clearly state that no malware analysis was performed.
- **Known limitations and potential false positives:** Metadata can be absent, spoofed, or too coarse; many legitimate workflows use archives, invoices, or macro-enabled files; metadata-only inspection cannot determine whether a file is malicious.

### 5. Payment Redirection / Financial Fraud

- **Status:** Approved / planned. Not implemented yet.
- **Purpose:** Identify suspicious payment requests and attempts to alter financial instructions.
- **Threat or attack technique addressed:** Business email compromise, invoice fraud, gift-card scams, payroll or bank-detail redirection, and urgent transfer requests.
- **Observable indicators:** New or changed bank details, urgent wire or transfer instructions, gift-card or cryptocurrency requests, unusual confidentiality instructions, mismatch between sender identity and payment context, invoice/payment language paired with sender or link anomalies, and pressure to bypass normal approval.
- **Intended implementation approach:** Detect financial-request language and correlate it with sender, URL, attachment, and credential-context evidence; record when historical transaction or communication context is unavailable instead of assuming the request is normal.
- **Expected output:** Findings that explain the payment-related request, the corroborating anomalies if any, and a recommended out-of-band verification step.
- **Known limitations and potential false positives:** The system does not have full mailbox history, vendor master data, accounting records, or prior transaction patterns; legitimate finance workflows can be urgent; this detector should be conservative when payment language appears without corroborating evidence.

### 6. NLP-Based Phishing Classification

- **Status:** Approved / planned. Not implemented yet.
- **Purpose:** Use statistical machine learning to analyze message language and context as a complement to deterministic rules.
- **Threat or attack technique addressed:** Phishing patterns that are difficult to capture with individual handcrafted rules, especially combinations of tone, request framing, urgency, and credential/payment context.
- **Observable indicators:** Model features derived from labeled legitimate and phishing examples, initially suggested as TF-IDF text features over subject/body/context plus a logistic regression baseline.
- **Intended implementation approach:** Train and evaluate on labeled legitimate and phishing examples; report precision, recall, F1-score, and false-positive rate; distinguish raw model scores from calibrated phishing probabilities; only call a score a calibrated probability after separate calibration and validation.
- **Expected output:** A model finding or supporting score that explains it is statistical evidence, identifies the feature/input scope at a high level, and shows how it complements deterministic findings rather than replacing them.
- **Known limitations and potential false positives:** Requires enough representative labeled data; may overfit synthetic examples; language/domain drift can degrade performance; raw classifier scores are not inherently probabilities; advanced transformer/LLM-based classification and continuous retraining are out of scope unless separately approved.

## Out of Scope

InboxGuardian intentionally does **not** attempt complete protection against all email-related cyber threats. It is a focused, explainable Gmail Add-on prototype for opened-message analysis, not an enterprise mail gateway, secure email gateway, endpoint security product, or incident-response platform.

### Excluded Detection Capabilities

- **Dedicated SPF/DKIM/DMARC authentication analysis:** Deferred because trusted provenance is hard to guarantee from message-supplied headers alone and may require deeper Gmail/Google infrastructure access. Already available trusted metadata may still be used as supporting evidence when its provenance is clear.
- **Historical sender behavioral anomaly detection:** Excluded because it requires mailbox history, long-term profiling, storage, privacy governance, and more evaluation data.
- **QR-code phishing and image-only phishing detection:** Excluded because it requires image extraction/OCR, additional parsing complexity, and separate test data.
- **Deepfake audio/video analysis:** Excluded because it is outside opened-email text/link/metadata analysis and would require specialized media processing infrastructure.
- **Full malware analysis or attachment sandbox execution:** Excluded because it requires high-risk binary handling, sandbox infrastructure, and security controls beyond the current project.
- **Advanced multi-email or conversation-history-based BEC detection:** Excluded because it requires access to threads, prior communications, organizational context, and potentially sensitive historical data.
- **Zero-day exploit detection:** Excluded because the project does not execute, emulate, or deeply inspect exploit payloads and lacks threat-intelligence infrastructure for novel exploit discovery.

### Excluded Product Capabilities

- **Automatic deletion or quarantine of suspicious emails:** Excluded to avoid destructive user-impacting actions and additional Gmail permissions.
- **Automatic blocking of senders:** Excluded because sender blocking can cause false-positive harm and requires broader account-level control.
- **Enterprise-wide mailbox administration and monitoring:** Excluded because the assignment target is a user-initiated Gmail Add-on for the currently opened message, not tenant-wide security operations.
- **Automated incident response or remediation:** Excluded because reliable remediation needs workflow integration, approvals, audit trails, and operational ownership beyond this prototype.
- **Guarantees that emails classified as low risk are safe:** Excluded because a low heuristic score only means approved detectors did not find significant suspicious evidence in the available data.

### Excluded or Deferred Advanced Features

- **Advanced transformer/LLM-based phishing classification unless separately approved:** Deferred due to scope control, privacy review, evaluation complexity, and risk of ungrounded explanations.
- **Continuous retraining of machine-learning models:** Deferred because it requires data pipelines, labeling governance, monitoring, drift detection, and reproducible evaluation.
- **Full sender-history profiling:** Deferred because it overlaps with historical anomaly detection and has significant privacy and storage implications.
- **Large-scale threat-intelligence infrastructure:** Deferred because it requires external feeds, reputation systems, operational maintenance, and careful data-sharing controls.

## Detection and Scoring Principles

**Technical contract:** See [`docs/detection-contract.md`](docs/detection-contract.md) for the six approved families, `TRIGGERED`/`NOT_TRIGGERED`/`INCONCLUSIVE`/`NOT_RUN` internal outcomes, data collection gaps, evidence accountability, internal scoring and evaluation requirements. Preserve the current external `schema_version: "1.0"` models until a response-mapping change is separately reviewed.

1. The system combines deterministic analysis and stochastic analysis: five approved deterministic detectors plus one approved NLP-based statistical classifier.
2. Every warning must be supported by traceable evidence from the email fields or metadata available to the backend.
3. A suspicious indicator is not automatically proof of malicious activity; explanations must separate observation from inference.
4. The scoring mechanism must avoid double-counting correlated signals, such as treating the same deceptive login link as multiple independent high-confidence findings without reconciliation.
5. Risk scores must not be represented as calibrated probabilities without validation. The default `0-100` value is a heuristic risk index.
6. Missing information must be handled explicitly as unknown, incomplete, or unavailable rather than assumed safe.
7. User privacy and safe handling of untrusted email content are fundamental requirements: do not execute attachments, follow links, render untrusted HTML as trusted, or send message content to third-party services without explicit approval.
8. False positives and false negatives must be measured using labeled test cases; do not invent accuracy, precision, recall, or readiness claims.
9. Detection logic must remain separate from the Gmail add-on UI so backend parsing, detection, scoring, and API serialization can be tested independently.
10. No detector should be described as production-ready without supporting evaluation evidence.
11. **Implemented scorer (2026-10-13): Method C v1 — correlation-aware, category-capped deterministic evidence scoring.** Deduplicate overlapping observations across rules/families, cap each family's credited contribution, use a zero correlation bonus, and require independent evidence for `HIGH_RISK`. NLP classification remains outside the combined heuristic score pending separate evaluation. Backend `/analyze` maps this result into schema `1.0`; the synchronized Gmail UI presents the response and was manually verified live in five scenarios. A subject line alone does not qualify a message for `NO_SIGNIFICANT_SIGNALS`; without readable body text or a supported link the result is `INCOMPLETE` unless positive evidence reaches the suspicious threshold. See `docs/scoring-policy.md`.
12. Recommended response labels remain `HIGH_RISK`, `SUSPICIOUS`, `NO_SIGNIFICANT_SIGNALS`, and `INCOMPLETE`.
12. Limit first-version linguistic analysis to English-language body/context heuristics, while URL and sender structural parsing should not assume ASCII-only inputs.

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
      +-- six approved detectors: sender, URL, credential context, attachment metadata, payment fraud, NLP classifier
      +-- versioned conservative correlation and scoring
      +-- evidence + verdict + recommendation serializer
      v
Gmail Add-on results card (no external UI required)
```

**Implementation status:** The Gmail-to-backend vertical slice has been manually verified: opened Gmail message -> Apps Script Gmail Add-on -> ngrok HTTPS -> local FastAPI -> JSON response -> Gmail card. Parser, three core detectors, orchestration, Method C v1 scoring, backend `/analyze` response mapping and Gmail CardService real-result rendering are implemented. The reviewed Apps Script source has been synchronized to the existing Apps Script project, and live Gmail checks have passed for benign, credential-phishing, multi-signal deceptive URL, backend-unavailable and `INCOMPLETE` scenarios. No persistent database is necessary for the first version; process on demand and avoid storing email content.

**Practical priorities:** preserve the verified proof-of-connectivity while implementing real parsing/detection behind the existing `/analyze` contract. The backend must be reachable from Google's servers: `localhost` alone is not sufficient for live Apps Script integration. The current local development path uses ngrok HTTPS forwarding to `127.0.0.1:8000`; avoid publicly exposing unauthenticated analysis endpoints. Do not rely on Google Cloud verification/public Marketplace launch as part of the 48-hour MVP. Verify any future Gmail scope changes against current Google docs; do not assume access to all inbox content.

### Existing API envelope and proposed scoring contract (do not change during parser milestone)

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

The sample score matches the one illustrated contribution. In implementation, enforce an auditable scoring invariant: every contribution (including correlation contributions) must be enumerated or its reconciliation explained. **The numerical score, verdict and contribution here illustrate JSON shape only; the example is not a valid approved score/verdict mapping or a scoring threshold requirement.** The authoritative open decisions are tracked in `docs/detection-contract.md`.

**Auth note:** Never send Gmail access tokens as backend authentication by default. Choose an appropriate authenticated Apps Script ↔ backend arrangement, with backend request verification, secret rotation and no committed credentials. Document the residual security trade-offs for a single-user demo.

## 9. Proposed repository structure and modular backend architecture

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

### Approved modular architecture

InboxGuardian uses one FastAPI backend process with modular internal components. The six detector families are **not** separate servers or microservices; they run inside the backend process behind the existing authenticated HTTP API.

Target backend structure:

```text
backend/app/
|-- main.py                 # Thin FastAPI HTTP/auth layer
|-- models.py               # Public request/response models
|-- parsing.py              # Implemented: canonical parsing/normalization
|-- engine.py               # Implemented internal detector orchestration
|-- scoring.py              # Implemented internal Method C v1 scorer
`-- detectors/
    |-- __init__.py         # Implemented package marker
    |-- base.py             # Implemented internal detector contract
    |-- sender.py           # Implemented WBS 2.2 sender detector
    |-- urls.py             # Implemented WBS 2.3 URL detector
    |-- credentials.py      # Implemented WBS 2.4 credential detector
    |-- attachments.py      # Future
    |-- financial.py        # Future
    `-- nlp.py              # Future inference module
```

Testing target:

```text
tests/unit/
|-- test_email_parsing.py   # Implemented parser tests
|-- test_sender.py          # Implemented sender tests
|-- test_urls.py            # Implemented URL detector tests
|-- test_credentials.py     # Implemented credential detector tests
|-- test_attachments.py     # Future
|-- test_financial.py       # Future
|-- test_nlp.py             # Future
`-- test_scoring.py         # Implemented scoring tests
```

Responsibilities:

- `parsing.py` normalizes existing validated input and extracts structural evidence. It does not decide maliciousness.
- `detectors/*.py` implement independent detector logic. Each detector receives normalized data and returns structured internal evidence; detectors do not calculate final email risk.
- `detectors/base.py` defines the shared internal detector-result contract, statuses, finding shape and evidence conventions.
- `engine.py` orchestrates parser/detector execution for `/analyze` and preserves evidence for scoring.
- `scoring.py` implements Method C v1: approved finding weights, evidence deduplication, detector-family caps, zero correlation bonus, coverage handling and internal verdict mapping used by `/analyze`.
- `main.py` remains the HTTP layer for authentication, validation, endpoint behavior and public response serialization.
- `addon/Code.js` remains the Gmail-facing UI/client and must not contain backend detection algorithms.
- Each detector should have independent unit tests for triggering cases, benign counterexamples and inconclusive/missing-data behavior.
- NLP model training, if approved with suitable data, should be separate from backend inference. The future `detectors/nlp.py` should load/evaluate an approved model, not train during request handling.

Do not create placeholder modules for future detectors merely to match this target tree.

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
| Existing Apps Script project preservation | **Approved** | Project ID is documented and local source is synchronized with `clasp`; do not recreate it |
| Opened-email, on-demand Gmail Add-on (not proactive monitor) | **Approved direction** | Upwind assignment requirement and 48-hour limit |
| FastAPI + Apps Script CardService | **Backend and Gmail UI wired / live-verified in five scenarios** | Existing Apps Script project is synchronized; benign, credential-phishing, multi-signal deceptive URL, backend-unavailable and `INCOMPLETE` live Gmail checks passed |
| Exactly six threat detectors | **Approved / three implemented** | Five deterministic detectors plus one stochastic NLP classifier are approved; sender, URL and credential detectors are implemented, scored and exposed through `/analyze`; attachment metadata, financial fraud and NLP remain planned |
| English-only linguistic heuristics | **Proposed MVP scope** | Limited time; structural signals can work more broadly |
| Local HTTPS tunnel and demo auth | **Verified for prototype** | ngrok HTTPS to `127.0.0.1:8000`; shared demo token via env var and Script Properties |
| Detection contract and implementation order | **Drafted 2026-10-13; review pending** | `docs/detection-contract.md`; core three first, then attachment/financial, then separately evaluated NLP |
| Scoring architecture (Method C) | **IMPLEMENTED AND WIRED TO BACKEND** | Category caps + cross-rule evidence deduplication + zero correlation bonus + explainable backend verdict; no automatic NLP vote |
| Scoring weights / thresholds / coverage / dataset | **PARTIAL** | Method C v1 weights, caps, thresholds and coverage are implemented internally for the first three detector families; future attachment/financial/NLP scoring and public response mapping remain open |
| Repository URL and live demonstration account | **PUBLISHED AS V1.0.0 / USER-VERIFIED** | Repository published with annotated tag `v1.0.0` on commit `fdf9289`; real Gmail account add-on verification was reported by the user for all ten dashboard acceptance checks; the interview demonstration is not yet rehearsed |

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
| Published baseline | V1.0.0: annotated tag `v1.0.0` on commit `fdf928908b8057867cfd8815db74691b2da26792`, pushed 2026-10-13 as a fast-forward; local and remote `master` matched after the push |

### Google Apps Script

| Item | Status |
|---|---|
| Project URL | `https://script.google.com/home/projects/1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs/edit` |
| Project ID | `1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs` |
| Basic Apps Script access | Verified manually by the user |
| Test function execution | Passed manually, per user report |
| Agent access | Local clasp connection verified; source synchronized by user-approved workflow |
| Agent read/edit/sync capability | Local files can be edited; `clasp status` works and lists `Code.js` and `appsscript.json`; reviewed real-result source was pushed to the existing project with `clasp` |
| Local synchronization method | Google `clasp` with `addon/` as the local root and local `.clasp.json` pointing to the existing project ID |
| Gmail Add-on deployment | Unpublished add-on installed/authorized in a real Gmail account. The modular dashboard is synchronized to the existing project and was manually verified by the user for all ten agreed desktop checks, including the backend-unavailable state |

### Local Apps Script Synchronization Plan

Use Google's `clasp` CLI to keep source files in `addon/` and synchronize them with the existing Apps Script project. The local `.clasp.json` file must stay out of Git because it is environment-specific; Google auth tokens must remain outside the repository.

Manual setup needed:

1. Install Node.js/npm.
2. Enable the Apps Script API at `https://script.google.com/home/usersettings`.
3. Install clasp, for example `npm install -g @google/clasp`.
4. Run `clasp login` and complete the Google OAuth flow in the browser.
5. Connect the local `addon/` directory to the existing project ID, for example from inside `addon/`: `clasp clone 1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs .` or create a local `.clasp.json` with that `scriptId`.
6. Use `clasp pull` to import the current remote source, and `clasp push` only after reviewing local changes. Do not deploy from clasp until the Gmail Add-on manifest/source is ready.

### Local Development Startup

Use [docs/development-startup.md](docs/development-startup.md) to restart the local backend/ngrok development flow, verify `/health`, verify authenticated `/analyze`, confirm Apps Script Properties, open the existing Gmail Add-on, and stop processes manually. This guide preserves the current working implementation and does not create or deploy a new Apps Script project.

## 13. Session Handoff — continuously maintained

> **Agents must replace/update this section at the end of every working session.** Never mark something as deployed, tested or complete without evidence.

- **As of:** 2026-10-14 (WBS 2.5 Stage 1 attachment metadata collection prepared on branch `wbs-2.5-stage1`)
- **Current state:** Gmail-to-backend integration is preserved. The existing Gmail Add-on uses Google Apps Script/CardService, reaches the authenticated FastAPI backend over HTTPS/ngrok, and the reviewed real-result UI is synchronized to the existing Apps Script project `1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs`. Backend `/analyze` returns parser -> engine -> Method C v1 scorer output in public schema `1.0`. The user has manually verified five live Gmail scenarios covering all four verdicts plus the backend-unavailable state. The deceptive-URL false negative and the subject-only false reassurance are both resolved. A 30-case labeled synthetic evaluation baseline now exists, and the one defect it exposed in the credential detector is fixed. A pre-submission security and correctness audit has been run; its security-bypass false-positive finding is fixed and the remaining findings are listed below. The bounded backend cleanup that followed the audit is committed. Five live Gmail scenarios were verified before the audit. After the backend commits that followed it, the user confirmed two further live Gmail results (tests 6 and 7 below) after restarting FastAPI on the latest code, and the redesigned modular result card was then synchronized to Apps Script, verified by the user in Gmail and committed. The documentation was then refreshed and the audited result was published to GitHub as V1.0.0.
- **Implemented backend:** Safe canonical parser, sender impersonation detector, deceptive URL detector, credential-phishing context detector, orchestration engine, Method C v1 scoring, real `/analyze` response mapping, `/health`, token-protected FastAPI authentication, request validation and bounded sanitized errors are implemented.
- **Approved detector scope:** Exactly six detection families are approved: sender, URL, credential context, attachment metadata, financial fraud, NLP. Only the first three are implemented. Suspicious attachment metadata, payment redirection / financial fraud and NLP-based phishing classification remain planned/unavailable and must not be presented as clean completed checks.
- **Manual live Gmail validation (user-performed, not automated):** (1) benign message: `NO_SIGNIFICANT_SIGNALS` `0/100`; (2) credential phishing: `SUSPICIOUS` `25/100`; (3) multi-signal deceptive-URL phishing: `HIGH_RISK` `60/100` with deceptive-subdomain evidence `+35` and credential-context evidence `+25`; (4) backend unavailable (FastAPI stopped, ngrok running): the card showed "Unable to analyze this email. Backend unavailable. Try again after confirming the backend is running and reachable over HTTPS." with no score or verdict; (5) subject with empty body: `INCOMPLETE`, risk score shown as unavailable, reason that there was no readable body text or supported links so only the subject could be checked, recommended action to verify through a trusted channel, and no misleading `0/100`. The credential case passed after commit `d53d0ddf4ef1bbb59ae84165f3fc9c40ccd17dff`, the multi-signal case after commit `2200b85f47e729e0aa7f2404b7ed4d1912170dda`, and the `INCOMPLETE` case after commit `2f3dfbf947b0c388b9ded680b0bfc72ef6c2ee61`; each needed only a backend restart, with no Apps Script change. No sender-identity finding has been triggered in live Gmail yet; that detector is covered by automated tests only. **Later user-performed tests:** (6) legitimate verification notice: `NO_SIGNIFICANT_SIGNALS` `0/100`; (7) forwarded synthetic phishing message: `INCOMPLETE`, score unavailable. Tests 6 and 7 first returned different results because the running FastAPI process had been started before the latest commits; after FastAPI was restarted with the latest code both gave the results above. Those first results are therefore not treated as regressions in the committed implementation. Tests 6 and 7 were run against the previously synchronized card, not the redesigned dashboard. **Redesigned dashboard, user-performed after synchronization, all reported as passing:** (a) the add-on opens, shows the message identity and offers the Analyze Email action; (b) benign result `0/100`; (c) suspicious result `25/100`; (d) high-risk result `60/100` with the URL finding listed first; (e) empty-body `INCOMPLETE` result; (f) forwarded-message `INCOMPLETE` result; (g) the findings section and the additional-details section expand; (h) icons, verdict colours and the ten-segment score bar render; (i) suspicious hostnames shown in findings are not clickable. **Tenth check (user-performed, manual):** with FastAPI stopped, the redesigned add-on displayed `Analysis unavailable` and no security verdict or risk score. **Not manually verified:** the separate result-could-not-be-displayed state, Gmail's dark theme, the mobile app and accessibility with a screen reader.
- **URL false-negative root cause and fix:** The received message was `multipart/alternative`; its `text/html` part contained the intended anchor unchanged, and its `text/plain` part contained both the visible URL and the destination URL. `backend/app/parsing.py` shared one deduplication set between plain-text URLs and HTML anchors, so the anchor was discarded as a duplicate of the plain-text destination URL and the URL detector had no visible-text/destination relationship to compare. Earlier direct backend tests passed only because they supplied no plain-text destination URL. Commit `2200b85f47e729e0aa7f2404b7ed4d1912170dda` (`Fix cross-source URL deduplication false negatives`) deduplicates plain-text URLs and HTML anchors separately and keys anchors on canonical destination plus visible text. Detectors, scorer, API schema and Apps Script were not changed.
- **Scoring decision:** Method C v1 is implemented internally from `docs/scoring-policy.md`: approved finding weights, caps, thresholds, coverage policy and zero correlation bonus. The credential-context family cap remains unchanged; the latest credential fix changed pattern recognition only, not weights, caps or thresholds. NLP remains experimental and excluded from the aggregate until evaluated. **Coverage rule (commit `2f3dfbf947b0c388b9ded680b0bfc72ef6c2ee61`):** `NO_SIGNIFICANT_SIGNALS` requires a parseable sender plus body evidence, meaning non-blank plain text, visible HTML text, or at least one supported HTTP(S) link. A subject line alone is not body evidence. When the score is below the unchanged suspicious threshold of 20 and body evidence or a parseable sender is missing, the verdict is `INCOMPLETE` with a stated reason; any findings are still returned. A score of 20 or more keeps its `SUSPICIOUS`/`HIGH_RISK` verdict. An implemented detector that did not run forces `INCOMPLETE` at any score. Missing Reply-To, missing HTML when plain text exists, and absence of URLs do not force `INCOMPLETE`. Empty, whitespace-only and image-only bodies are treated conservatively because the backend cannot tell an empty body from one that was not collected. This changed no weights, caps, correlation bonus or numerical thresholds.
- **Incomplete-reason visibility:** `/analyze` now lists the score-unavailable notice first and the specific coverage reasons directly after it, ahead of all other limitations, because the Gmail card shows only the first six limitations. Previously the reasons were last in a list of up to 20 and were never displayed.
- **Unresolved policy discrepancy (decision required):** `docs/scoring-policy.md` says `NO_SIGNIFICANT_SIGNALS` is eligible only when sender identity and at least one body/link-oriented family completed as `NOT_TRIGGERED`. The code does not consult detector statuses for this decision, so a message with usable content whose URL and credential detectors are both `INCONCLUSIVE` (for example only an unsupported link plus ambiguous credential wording) still receives `NO_SIGNIFICANT_SIGNALS`. This was left unchanged on purpose and neither the policy nor the code has been altered to hide it; deciding which one to change requires user approval. The same policy document also does not yet describe the subject-only rule above.
- **Synthetic evaluation baseline (commit `1b382c905a72bbb627c5686f4b952ac9adbfac08`):** A 30-case labeled synthetic set (`tests/fixtures/evaluation/cases.json`, 15 benign and 15 suspicious across six groups) is run by `tests/evaluation/run_evaluation.py` through the unchanged engine and Method C scorer. Labels were fixed and the fixture hashed before any case was run. **Original baseline** (measured at commit `58fceef`, `docs/evaluation-results.md`): 8 true positives, 2 false positives, 13 true negatives, 7 false negatives, 0 abstentions; precision 8/10, recall 8/15, false-positive rate 2/15, coverage 30/30. **After the B2 fix** (`docs/evaluation-results-post-b2-fix.md`): only case B2 changed; 1 false positive, precision 8/9, recall 8/15, false-positive rate 1/15. These figures describe a small, author-written synthetic set whose author had read the detector rules; they are not detection accuracy and must not be quoted as such. Analysis, limitations and recommended priorities are in `docs/evaluation-baseline.md`.
- **Multipart credential false-positive fix:** The evaluation exposed a false positive on a legitimate multipart sign-in-code notice: the credential detector joined the plain-text body and the visible HTML text, and the security-bypass pattern matched across the join. Commit `52bd5b3de6c346f4ac147861d0dd4151a8912802` matches each representation as its own context and takes the first match per rule; no pattern, weight, cap or threshold changed. Review before commit found that this would have started flagging forwarded content in multipart messages, so the HTML copy is still skipped when the plain text carries a forwarded-message marker, as before.
- **Security-bypass false-positive fix:** The pre-submission audit showed that ordinary security wording was flagged as a bypass instruction: eight of eight benign phrasings returned `SUSPICIOUS` `20`, including "you can safely ignore this email. For security, this link expires in 24 hours", "do not disable MFA" and "IT will never ask you to bypass security checks". Commit `b86011fb118a3946fd65024ee16393eb21558716` requires the bypass verb and the security term to sit in the same sentence and skips matches governed by a nearby negation, while still detecting double negatives that urge the action ("don't forget to disable MFA") and a real instruction that follows a warning. The pattern itself, the other credential rules, the separate text/HTML contexts, forwarded-content handling and all weights are unchanged. Rerunning the frozen 30-case evaluation changed no case (`docs/evaluation-results-post-bypass-fix.md`).
- **Pre-submission backend cleanup:** Commit `886bc346dcd8f368c3f0700d3fab4fdbacbab4dc` made eight bounded backend changes with no change to weights, caps, thresholds, sender or URL rules, the public schema or the add-on. (1) **Forwarded and quoted content:** the credential detector still skips it and still never attributes it to the sender, but now reports the skip. A forwarded-message marker in the plain-text body, or a body consisting only of quoted or header-style lines, is a coverage gap: the result is `INCOMPLETE` with a stated reason unless positive evidence reaches the suspicious threshold of 20, in which case the verdict stands and the gap is listed among the first limitations. Quoted `>` lines next to the sender's own text add a limitation only. Coverage gaps are distinct from detector failures, which still force `INCOMPLETE` at any score. (2) The subject is matched as its own context, so a pattern cannot span the subject/body boundary; urgency in the subject still combines with a request in the body. (3) A non-ASCII token header returns 401 instead of 500. (4) Public findings are returned strongest first, ties in detector order, contributions unchanged. (5) The limitations list leads with one line naming the planned checks that did not run (attachments, payment or financial-fraud requests, NLP classification), after any incomplete reason. (6) An absent optional Reply-To no longer produces the generic parser note; malformed senders and links still do. (7) The backend action text no longer starts with `Recommended action:`, which the Gmail card already prints. (8) `.gitignore` ignores `*.eml`.
- **Modular Gmail dashboard (committed, synchronized, user-verified for ten checks):** Commit `48f0e6bb1106925e218e0c0465b8e84eb5f27f41`. `addon/Code.js` builds a modular CardService dashboard in place of the single plain-text card. Sections: message (subject, sender, analyze button); **Assessment** (verdict with icon and coloured label - red for `HIGH_RISK`, amber for `SUSPICIOUS`, restrained green with a neutral information icon for `NO_SIGNIFICANT_SIGNALS`, muted amber for `INCOMPLETE` - a one-line meaning, and the risk index with a ten-segment text bar); **Key findings** (backend order kept, strongest first, three visible and the rest behind the native expand control); **Recommended action**; **Analysis coverage** (the three checks this version has, the backend's own not-checked statement, and coverage limits specific to the message); and a collapsed **Additional details** section holding every remaining limitation. `INCOMPLETE`, unrecognised verdicts and out-of-range scores show `Risk score unavailable` with no number and no bar. A backend failure shows an `Analysis unavailable` section with no verdict or score, and a failure while building the result card is reported separately instead of as a backend outage. Only the presentation layer changed: message collection, the backend call, response validation, error mapping, redaction, the manifest and OAuth scopes are identical to the previously synchronized source, and there are no backend API, detector or scoring changes. Widgets used are CardBuilder, CardHeader, CardSection with collapsing, DecoratedText, TextParagraph, TextButton, Divider and IconImage with built-in Material icons, all documented as available to Google Workspace add-ons; the developer-preview collapse control is not used. No links, image URLs or extra network calls were added, and backend and message text is redacted and escaped before display. **Synchronization:** after the user approved it, `clasp push` (no `--force`) uploaded `Code.js` and the unchanged `appsscript.json` to the existing project; the remote had first been confirmed identical to the last committed source, and read-backs before the commit showed the remote `Code.js` identical to the committed file. No new project, deployment, scope or Script Property change. **Automated evidence:** rendering tests execute the source in Node against a recording stand-in for CardService, which proves card structure and escaping but not Gmail's rendering. **Manual evidence (user-performed in real Gmail, all reported as passing):** (a) the add-on opens, shows the message identity and offers the Analyze Email action; (b) benign result `0/100`; (c) suspicious result `25/100`; (d) high-risk result `60/100` with the URL finding listed first; (e) empty-body `INCOMPLETE` result; (f) forwarded-message `INCOMPLETE` result; (g) the findings section and the additional-details section expand; (h) icons, verdict colours and the ten-segment score bar render; (i) suspicious hostnames shown in findings are not clickable. **Tenth check (user-performed, manual):** with FastAPI stopped, the redesigned add-on displayed `Analysis unavailable` and no security verdict or risk score. **Not manually verified:** the separate result-could-not-be-displayed state, Gmail's dark theme, the mobile app and accessibility with a screen reader.
- **Documentation refresh (2026-10-13):** `README.md` was rewritten for a new reviewer (purpose, workflow, architecture diagram, detectors, Method C v1, verdicts, setup, tests, evaluation with caveats, security, limitations, demo script, roadmap), and `docs/detection-contract.md`, `docs/scoring-policy.md`, `docs/security-decisions.md`, `docs/gmail-integration-runbook.md`, `docs/development-startup.md`, `docs/assignment-checklist.md`, `docs/status-2026-10-12.md` and `addon/README.md` were reconciled with the implementation. The health and `/analyze` commands were run against a local backend; two documented commands were corrected (a PowerShell flag that does not exist in Windows PowerShell 5.1, and a minimal request that now returns `INCOMPLETE`). The `INCONCLUSIVE` discrepancy is documented as an open decision without changing the approved policy text. The README has no screenshot yet, and its fresh-project add-on setup steps were not exercised from a clean machine. No application code, test, manifest or configuration changed.
- **WBS 2.5 Stage 1 attachment metadata collection (2026-10-14, branch `wbs-2.5-stage1`, not committed, not synchronized to Gmail):** the user ran the WBS 2.5A probe in real Gmail: T00-T08 and T10 passed and T09 (forwarded `.eml` attachment) is blocked and unresolved; exact MIME types and timings were not recorded. The existing `gmail.addons.current.message.readonly` scope is sufficient for `getAttachments()`, `getName()`, `getContentType()` and `getSize()`. Stage 1 implements the approved contract on Method C v1 scoring: `addon/Code.js` collects name, declared type and size only when Analyze Email runs (never on message open), never calls content methods, logs nothing, sends at most 25 items, examines at most 100 names within a provisional 5-second budget, clips names over 255 code points to a 64-code-point head and 191-code-point tail with the removed middle summarised, and sends the optional `attachment_collection` state (`COLLECTED`, `NONE`, `TRUNCATED`, `UNAVAILABLE`; absent means legacy `UNKNOWN`). The backend validates and parses it, keeps clipped names as separate segments that are never joined, turns contradictory metadata into `UNKNOWN` with a parser issue, and adds one count-only limitation line that the dashboard shows under Analysis coverage; filenames never appear in responses. The attachment detector stays planned `NOT_RUN`, and no score, verdict, weight, threshold, scope or manifest changed. Details: `docs/attachment-collection-feasibility.md`. Two review fixes are included: request validation errors return only error locations and types and never echo rejected values (unauthenticated invalid requests get 401), and an unexpected collection error is reported as `UNAVAILABLE` (`unexpected_error`) without stopping the analysis. Not yet run in the real add-on.
- **V1.0.0 publication (2026-10-13):** InboxGuardian V1.0.0 is published at `https://github.com/Waffles4me/Inbox_Guardian`. On 2026-10-13, after user approval, `master` was pushed to `origin/master` as a plain fast-forward (`54a4c06` to `fdf9289`, 27 commits, no force) and the annotated tag `v1.0.0` was created on commit `fdf928908b8057867cfd8815db74691b2da26792` and pushed on its own. After the push, local and remote `master` were identical and the remote tag resolved to the same commit; the working tree was clean. Checks made immediately before publishing: the full suite passed 283 tests with 1 known warning; no `.env`, `.clasp.json`, `.eml`, key file or `UPWIND_HOME_ASSIGNMENT.md` was tracked or present in any pushed commit; a pattern search of all commits found no private keys, API tokens, real tunnel hostnames or email addresses outside the reserved `.test` domain; and the live Apps Script source was identical to the committed `addon/` source. **What V1.0.0 is:** a stable, published prototype with three implemented detector families (sender identity, URL deception, credential context), Method C v1 scoring and the modular Gmail dashboard, whose ten agreed desktop acceptance checks were all verified by the user in real Gmail. Three approved families (attachment metadata, financial fraud, NLP classification) are not implemented and are reported as not checked. It is not production-grade protection and makes no detection-accuracy claim. **Publicly visible by the user's decision:** the commit author address, the Apps Script project ID in the documentation, and the development history including AI co-author trailers.
- **Open findings after the cleanup (from the pre-submission audit; synthetic probes):** **Forwarded/HTML ambiguity that remains:** every message whose plain text carries a forwarded-message marker and has no other evidence is now `INCOMPLETE`, including benign forwards and forwards where the sender wrote a substantial message of their own; no reliable way was found to tell an incidental forward from one that is the point of the message. The parser flattens HTML to one line, so HTML is not structure-aware: a reply whose HTML copy quotes a request inside a blockquote is still scored against the sender, and an HTML-only forward is analysed in full. Ordinary text plus a single line starting `Subject:` that carries a request still returns `NO_SIGNIFICANT_SIGNALS`, with only the quoted-lines limitation. **Bounded audit items not yet addressed:** links the parser cannot read (`//host`, `https:\\host`) under a displayed URL leave the URL detector inconclusive and the verdict clean, with real-world reach in Gmail unverified; legitimate `www` and parent-domain links are flagged (text `www.shop.test`, link `shop.test`, +30); truncation at 50,000 characters is silent; the generic parser note still appears for `mailto:` links and repeated URLs; after the not-checked line, the limitations the card shows are generic detector notes. **Remaining bypass-rule limits:** benign single-sentence uses such as "turn off these security notifications" or "ignore the approval request" still trigger, as do sentences without terminal punctuation followed by a `Security Team` signature and negations separated from the verb by a comma; a double negative outside the six exempted words would be missed. **Documented limitations:** two-level public suffixes such as `.co.il` defeat sender-domain comparison; sibling subdomains and tracking redirects are flagged; zero-width characters evade keyword rules; hidden HTML text is read as visible; `/docs` and `/openapi.json` are reachable without a token; there is no request-size cap or rate limit; the commit author address is in public history. **Not verified:** whether Gmail makes bare hostnames in a finding clickable on the card.
- **Roadmap after V1.0.0 (nothing here is implemented):** In priority order. (1) **Attachment metadata detector - next milestone** (approved, WBS 2.5). Begin with design, not code: establish which attachment metadata the Gmail API exposes under the current current-message read-only scope, and define a collection-state contract so the backend can tell `no attachments` from `not collected`. The add-on currently sends an empty list, so this needs an Apps Script change and a reviewed `clasp push`; no scope change may be made without separate approval. Files are never opened, downloaded or executed. (2) **Financial fraud detector** (approved, WBS 2.6). (3) **NLP phishing classifier** (approved as a separately evaluated experiment, WBS 2.7; no score integration before evaluation). (4) **Method C v2 scoring** - proposed, **not approved**, to be reviewed separately; inputs include very strong single-family evidence, tracking-redirect weighting, Reply-To domains that imitate the From domain, detections with no margin over the threshold and the `INCONCLUSIVE` coverage rule. (5) **Optional VirusTotal reputation enrichment** - proposed, **not approved**. External reputation queries require explicit privacy approval and API-licensing approval before any implementation: they would send URLs taken from a user's email to a third party, which the current security decisions exclude. If ever approved, enrichment must be opt-in, never required for a verdict, and reported as unavailable rather than clean when absent. Each detector increment must be followed by rerunning the frozen 30-case evaluation to a new report file without editing labels.
- **Outstanding items:** this documentation commit was made after the tag, is not part of `v1.0.0`, and is local until a push is separately approved; `docs/assignment-checklist.md` was written before publication and still describes the repository as not yet pushed in two checklist lines; the real dashboard screenshot is intentionally deferred until after the additional detector features, so the README still only describes where it will go; the final interview demonstration has not been rehearsed; the `INCONCLUSIVE` coverage-policy discrepancy remains an open decision (documented in `docs/scoring-policy.md`); the remaining audit findings listed above; remaining evaluation failures (one false positive, C3, and seven false negatives); body collection status (empty body versus failed retrieval); dark theme, mobile, screen-reader behaviour and the result-could-not-be-displayed state are not manually verified; the non-ASCII token handling has automated evidence only; no sender-identity finding has been triggered in live Gmail; the fresh-project add-on setup steps in the README were not exercised from a clean machine; there is no `LICENSE` file or dependency lock file; `.env.example` lists two variables the backend does not read; `Email_Threat_Monitor_WBS.md` is referenced as planning input but is not in the repository; the recorded fixture SHA-256 is of the LF-normalised file as stored in Git. Attachment metadata, financial fraud and NLP detectors remain planned/unavailable.
- **Next task:** Review the `wbs-2.5-stage1` diff and commit it only with approval. Then a separately approved `clasp push`, backend restart and Gmail check of T01, T02, T03 and T08 through the real add-on plus the existing dashboard cases; push only with separate approval. Resolve T09 with one more synthetic forwarded-as-attachment test before any Stage 2 rule depends on nested attachments. Stage 2 attachment rules and weights need separate approval. Method C v1.1 is kept separately on branch `method-c-v1.1` for its own review.
- **Automated validation evidence:** At dashboard commit `48f0e6bb1106925e218e0c0465b8e84eb5f27f41`, `.\.venv\Scripts\python.exe -m pytest -q` passed 283 tests with 1 warning (the existing Starlette/httpx deprecation). That is 259 tests at the last backend commit `886bc346dcd8f368c3f0700d3fab4fdbacbab4dc` plus 24 add-on cases: 23 rendering tests that execute `addon/Code.js` in Node against a recording stand-in for CardService (all four verdicts, the benign `0`, credential `25` and multi-signal `60` responses, incomplete and forwarded results, backend failure, a rendering failure, many findings, long limitations, hostile text, missing optional fields, malformed responses and the set of widgets used) and one source test asserting that no links, image URLs or extra network calls exist. Four older add-on source-string tests were rewritten for the new renderer. `node --check addon/Code.js` passes. No backend test changed. The stand-in proves card structure and escaping, not Gmail's actual rendering. The evaluation runner is not collected by pytest. Automated tests use synthetic `.test` content only and do not exercise Gmail or Apps Script.
- **Git/security handoff:** `v1.0.0` (commit `fdf928908b8057867cfd8815db74691b2da26792`) is the published baseline; at that checkpoint local `master`, `origin/master` and the tag all pointed to the same commit and the working tree was clean. This handoff commit follows the tag and is local only until a push is separately approved, so local `master` is one commit ahead of `origin/master`. The pre-publication audit covered all tracked files and every commit: no `.eml`, `.env`, `.clasp.json` or assignment file has ever been committed, and no private keys, API tokens, real tunnel hostnames or non-`.test` email addresses were found in commit contents. `.gitignore` ignores `*.eml`. Before any future commit/push, confirm `UPWIND_HOME_ASSIGNMENT.md`, downloaded `.eml` files, `addon/.clasp.json`, real `.env`, credentials, tokens and real email content are not staged or tracked. Do not move or re-create the `v1.0.0` tag.

### Session log (append concise entries)

| Date | Agent/session | Verified changes | Tests/evidence | Outstanding action |
|---|---|---|---|---|
| 2026-10-12 | Planning / ChatGPT | Objective and WBS prepared; architecture and MVP agreed in principle | Documentation only | Start technical spike; validate Google integration |
| 2026-10-12 | Codex initial setup | Git repo initialized; minimal FastAPI backend, dependency config, README, `.gitignore`, `.env.example`, docs and tests added | `pytest`: 2 passed; backend import sanity check passed | Finish G0 decisions; manually create Apps Script project; prove Gmail-to-backend slice |
| 2026-10-12 | Codex assignment audit | `UPWIND_HOME_ASSIGNMENT.md` reviewed; assignment checklist updated; WBS 0.1 unblocked and marked complete | Documentation audit only | Verify Google/App Script access; choose HTTPS/auth plan |
| 2026-10-12 | Codex external services setup | GitHub repo reachability verified; `origin` configured; Apps Script project status and clasp sync plan documented | `git ls-remote` succeeded; no Apps Script source access verified | Decide whether to publish assignment text; verify push permissions; install/auth clasp |
| 2026-10-12 | Codex publishing policy and first sync | Permanent rule added: never commit/push `UPWIND_HOME_ASSIGNMENT.md`; file ignored; safe files committed and pushed to GitHub | `pytest`: 2 passed; secret scan/staged review passed; remote branch verified | Install/auth clasp; choose backend HTTPS/auth plan |
| 2026-10-12 | Codex local Gmail integration slice | Local Apps Script add-on UI and protected backend demo `/analyze` contract implemented; runbook added | `pytest`: 13 passed; `clasp status` works locally | Approve `clasp push`; configure HTTPS tunnel and Script Properties; live Gmail test |
| 2026-10-12 | User/Codex verified integration handoff | Live Gmail-to-backend integration status recorded; G1 marked achieved in WBS | User-reported Gmail/ngrok/FastAPI/Uvicorn evidence; `pytest`: 13 passed | Build repeatable startup flow, then start detector pipeline |
| 2026-10-12 | Codex end-of-day checkpoint | Startup guide added; manual vs automated verification boundaries documented; project handoff refreshed | `pytest`: 13 passed, 2 warnings; assignment/clasp/env files not tracked | Commit/push docs-only checkpoint; start WBS 2 tomorrow |
| 2026-10-13 | Codex approved detection scope update | `PROJECT_OBJECTIVE.md` updated with six approved detectors, exclusions, and scoring principles | Documentation-only change; no application code modified | Reconcile WBS and define contract |
| 2026-10-13 | ChatGPT draft documentation reconciliation | Drafted `docs/detection-contract.md`; aligned objective/WBS with six-detector roadmap and staged delivery | Documentation review only; no application tests, Git commit, or push performed | Review unresolved score decisions; apply docs to actual repo; Codex parser-only task |
| 2026-10-13 | User scoring architecture decision | Approved Method C (category caps, evidence deduplication, only independent corroboration); numerical parameters and coverage remain open | Decision recorded in documentation only; no code/tests/Git changes verified locally | Codex read-only baseline inspection, then WBS 2.1 parsing only |
| 2026-10-13 | Codex WBS 2.1 parser implementation | Backend-internal parser/normalizer and synthetic parser tests added; docs synchronized; `/analyze` and Apps Script unchanged | `pytest -q`: 28 passed, 2 warnings | Review diff; then WBS 2.2 sender impersonation detector |
| 2026-10-13 | Codex WBS 2.2 sender detector implementation | Internal detector contract and sender detector added; architecture documented; `/analyze` and Apps Script unchanged | `pytest -q`: 43 passed, 2 warnings | Review diff; then WBS 2.3 deceptive URL detector |
| 2026-10-13 | Codex WBS 2.3 URL detector implementation | Internal deceptive URL detector added; checkpoint commits created for WBS 2.1/2.2/docs; `/analyze` and Apps Script unchanged | `pytest -q`: 59 passed, 2 warnings | Review diff; then WBS 2.4 credential context detector |
| 2026-10-13 | Codex WBS 2.4 credential-context detector implementation | URL boundary tests added and WBS 2.3 committed; internal credential-context detector added; `/analyze` and Apps Script unchanged | `pytest -q`: 84 passed, 2 warnings | Review diff; then WBS 2.5 attachment metadata design |
| 2026-10-13 | Codex internal orchestration implementation | WBS 2.4 committed; internal engine added to run parser plus three core detectors; `/analyze` and Apps Script unchanged | `pytest -q`: 97 passed, 2 warnings | Review proposed Method C scoring plan |
| 2026-10-13 | Codex Method C scoring policy approval | Approved scoring policy recorded; no API, Gmail, auth or detector changes made | Documentation/specification only | Implement internal Method C v1 scoring |
| 2026-10-13 | Codex Method C v1 scoring implementation | Internal scorer and scoring tests added; `/analyze` and Apps Script unchanged | `pytest -q`: 132 passed, 2 warnings | Review scoring implementation; then map scored results to `/analyze` |
| 2026-10-13 | Codex backend analysis integration | `/analyze` now runs parser, engine and Method C scorer; Apps Script unchanged | `pytest -q`: 144 passed, 2 warnings | Update Gmail CardService UI to display real results |
| 2026-10-13 | Codex Gmail CardService result rendering | Local Apps Script source renders real backend verdict, score, findings, limitations and action; manifest unchanged | `pytest -q`: 150 passed, 2 warnings; `node --check addon\Code.js` passed | Review, then synchronize and manually verify live Gmail |
| 2026-10-13 | Codex Apps Script synchronization | Reviewed real-result `addon/Code.js` and unchanged manifest were pushed to existing Apps Script project `1yLQiiIje9whhVcqtIzN77FEQgguyFBasuHoFiGbVDUu-ro7MmW3rFfxs`; no new project/deployment/scopes | `clasp status`, isolated remote pull/readback and post-push comparison succeeded | Run live Gmail benign, credential, high-risk/incomplete and failure-state checks |
| 2026-10-13 | User/Codex credential false-negative fix | Live credential phishing initially returned `0/100`; credential patterns were narrowed/extended for `reply to ... with ...`, `six-digit verification code`, and normal-login bypass context | Commit `d53d0ddf4ef1bbb59ae84165f3fc9c40ccd17dff`; `pytest -q`: 159 passed, 2 warnings; user manually verified Gmail now returns `SUSPICIOUS` `25/100` | Investigate live multi-signal deceptive URL false negative |
| 2026-10-13 | Codex URL false-negative diagnosis | Direct backend test of simplified anchor produced `url_deceptive_subdomain` and `HIGH_RISK`, but live Gmail still returns `SUSPICIOUS` without URL findings | No code changes; Git clean before documentation edit | Claude should inspect downloaded original `.eml` outside Git and compare received HTML to parser output |
| 2026-10-13 | Claude Code URL false-negative root cause | Decoded the received synthetic message outside Git tracking; HTML anchor was intact and the plain-text part repeated the destination URL; parser cross-source deduplication dropped the anchor | Received content reproduced `SUSPICIOUS` `25/100` with `url_duplicate_omitted`; HTML-only input gave `HIGH_RISK` `60/100`; no code changed | User approval of the parser fix |
| 2026-10-13 | Claude Code parser fix | Plain-text URLs and HTML anchors deduplicated separately; anchors keyed on destination plus visible text; 11 regression tests added | Commit `2200b85f47e729e0aa7f2404b7ed4d1912170dda`; `pytest -q`: 170 passed, 1 warning | Manual Gmail re-test |
| 2026-10-13 | User live verification / Claude Code handoff | Original multi-signal test email re-analyzed in Gmail after backend restart; objective and WBS updated; encoding corruption in both documents repaired | User-reported Gmail result `HIGH_RISK` `60/100` with URL `+35` and credential `+25` | Live `INCOMPLETE` and backend-unavailable checks; evaluation; publication review; GitHub synchronization; demo rehearsal |
| 2026-10-13 | User backend-unavailable verification | With FastAPI stopped and ngrok running, the Gmail card showed the backend-unavailable message and no score or verdict | User-reported manual Gmail result; not an automated test | Coverage investigation |
| 2026-10-13 | Claude Code coverage investigation | Confirmed that subject plus sender with no usable body returned `NO_SIGNIFICANT_SIGNALS` `0/100`, and that `INCOMPLETE` reasons fell outside the six limitations the card displays | Synthetic scenario runs through the existing engine, scorer and API; no code changed | User approval of the two backend corrections |
| 2026-10-13 | Claude Code coverage correction | Clean verdict now requires body evidence; coverage reasons lead the public limitations; weights, caps and thresholds unchanged | Commit `2f3dfbf947b0c388b9ded680b0bfc72ef6c2ee61`; `pytest -q`: 198 passed, 1 warning | Manual Gmail empty-body test |
| 2026-10-13 | User live verification / Claude Code handoff | Subject-with-empty-body email analyzed in Gmail after backend restart; objective and WBS updated with five manual scenarios and the open policy discrepancy | User-reported Gmail result `INCOMPLETE` with score unavailable and a subject-only reason | False-positive evaluation; docs refresh; policy decision; publication review; GitHub synchronization; demo rehearsal |
| 2026-10-13 | Claude Code synthetic evaluation | 30 labeled synthetic cases, runner and reports created; labels fixed and fixture hashed before the first run; no detection code changed | Baseline: 8 TP, 2 FP, 13 TN, 7 FN, 0 abstentions on a small author-written set; `pytest -q`: 198 passed, 1 warning | Investigate the B2 false positive |
| 2026-10-13 | Claude Code multipart credential fix | Plain-text and HTML alternatives matched as separate contexts; forwarded-content handling preserved; 13 regression cases added | Commit `52bd5b3de6c346f4ac147861d0dd4151a8912802`; `pytest -q`: 211 passed, 1 warning; frozen evaluation rerun changed only B2 | Commit evaluation artifacts |
| 2026-10-13 | Claude Code evaluation checkpoint | Evaluation fixtures, runner, original baseline report and labeled post-fix report committed; objective and WBS updated with results, open issues and backlog | Commit `1b382c905a72bbb627c5686f4b952ac9adbfac08`; history scanned for secrets and private mail | Docs refresh; policy decisions; publication review; GitHub synchronization; demo rehearsal |
| 2026-10-13 | Claude Code pre-submission audit | Synthetic probes of credential boundaries, coverage, user-facing output and operational security; findings prioritised; no code changed | Bypass rule flagged 8 of 8 benign phrasings; forwarded/quoted content skipped with a clean verdict; not-checked limitations hidden beyond the card's six lines; no secrets in history | User decision on which findings to fix |
| 2026-10-13 | Claude Code security-bypass fix | Bypass verb and security term must share a sentence; nearby negation marks a warning; double negatives still trigger; 23 regression cases added | Commit `b86011fb118a3946fd65024ee16393eb21558716`; `pytest -q`: 234 passed, 1 warning; frozen evaluation rerun changed no case | Remaining audit findings; docs refresh; publication review; GitHub synchronization; demo rehearsal |
| 2026-10-13 | Claude Code backend cleanup | Excluded forwarded/quoted content reported as a coverage gap; subject matched separately; non-ASCII token gives 401; findings strongest first; not-checked line leads the limitations; Reply-To parser note removed; duplicate action label removed; `*.eml` ignored | Commit `886bc346dcd8f368c3f0700d3fab4fdbacbab4dc`; `pytest -q`: 259 passed, 1 warning; frozen evaluation unchanged; not verified in Gmail | Manual Gmail re-check; modular card design; docs refresh; publication review; GitHub synchronization; demo rehearsal |
| 2026-10-13 | User Gmail tests 6 and 7 | Legitimate verification notice and forwarded synthetic phishing message analyzed in Gmail with the previously synchronized card | User-reported: `NO_SIGNIFICANT_SIGNALS` `0/100` and `INCOMPLETE` with score unavailable, after restarting FastAPI on the latest code; earlier differing results came from a stale backend process | Dashboard review |
| 2026-10-13 | Claude Code modular dashboard | Result card rebuilt as sectioned CardService dashboard in local `addon/Code.js`; rendering failure reported separately from backend failure; manifest, scopes, collection and backend call unchanged | `pytest -q`: 283 passed, 1 warning; `node --check` passes; rendered against a Node CardService stand-in only | Review; approved `clasp push`; manual Gmail rendering checks |
| 2026-10-13 | Claude Code Apps Script synchronization | After user approval, `clasp push` without `--force` uploaded the dashboard `Code.js` and unchanged manifest to the existing project; remote checked for unexpected edits first | Remote identical to last committed source before the push and to local source after it; no new project, deployment, scope or Script Property change | Manual Gmail rendering checks |
| 2026-10-13 | User dashboard verification / Claude Code commit | Redesigned dashboard tested by the user in real Gmail; dashboard and rendering tests committed as `48f0e6bb1106925e218e0c0465b8e84eb5f27f41`; objective and WBS updated | User-reported PASS for nine checks (opening and action, `0`, `25`, `60` with URL finding first, two `INCOMPLETE` cases, expandable sections, icons/colours/score bar, hostnames not clickable); `pytest -q`: 283 passed, 1 warning | Backend-unavailable check on the new card; docs refresh; publication review; GitHub synchronization; demo rehearsal |
| 2026-10-13 | User backend-unavailable check on the dashboard | FastAPI stopped; redesigned add-on analyzed a message | User-reported PASS: `Analysis unavailable` shown, no verdict or risk score; manual test, not automated | Documentation refresh |
| 2026-10-13 | Claude Code documentation refresh | README rewritten; supporting docs, assignment checklist, objective and WBS reconciled with the implementation; no code, test or configuration change | Setup commands run against a local backend; relative links checked; `pytest -q`: 283 passed, 1 warning | Review and commit; screenshot; publication review; GitHub synchronization; demo rehearsal |
| 2026-10-13 | Claude Code documentation commit and release audit | Documentation committed as `fdf9289`; all tracked files and all 32 commits reviewed for secrets, private mail, identifiers, assignment text and licences | No confirmed security issue; `pytest -q`: 283 passed, 1 warning; recommendation READY TO PUSH | User approval to publish |
| 2026-10-13 | Claude Code V1.0.0 publication | After user approval, `master` pushed to `origin/master` as a fast-forward and annotated tag `v1.0.0` pushed for commit `fdf9289`; no force, no history rewrite | Remote `master` and remote tag verified against the audited commit; `pytest -q`: 283 passed, 1 warning; Apps Script source identical to committed source | Record publication; attachment metadata design |
| 2026-10-13 | Claude Code post-publication handoff | Objective and WBS reconciled with the publication; roadmap prioritised with attachment metadata next; no code, test or configuration change | Publication facts re-verified against the remote before editing | Approval to push this commit; attachment metadata scope and collection-state design; demo rehearsal |
| 2026-10-14 | Claude Code WBS 2.5A results and Stage 1 attachment collection | Probe results recorded (T00-T08, T10 pass; T09 blocked); optional `attachment_collection` contract in models, parser and `/analyze` limitations; add-on collection on Analyze Email only; tests; feasibility report. Detector still `NOT_RUN`; Method C v1 scoring, scopes and manifest unchanged | See the Stage 1 verification in `docs/attachment-collection-feasibility.md` | User review; commit approval; approved `clasp push` and Gmail check; T09 |

## 14. References

- Upwind provided assignment: `UPWIND_HOME_ASSIGNMENT.md`; external requirements are described above and mapped in `docs/assignment-checklist.md`.
- Detection contract and open score decisions: [`docs/detection-contract.md`](docs/detection-contract.md).
- Original planning input: `Email_Threat_Monitor_WBS.md`; its proactive Chrome extension / push-monitoring assumptions are **superseded for this assignment**.
- Official Google Workspace guides (verify currency during setup):
  - https://developers.google.com/workspace/add-ons/gmail
  - https://developers.google.com/workspace/add-ons/gmail/extending-message-ui
  - https://developers.google.com/workspace/add-ons/guides/connect-third-party-service
  - https://developers.google.com/apps-script/reference/gmail/gmail-app
  - https://developers.google.com/apps-script/guides/clasp

