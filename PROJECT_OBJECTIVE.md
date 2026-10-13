# InboxGuardian â€” Project Objective & Agent Operating Guide

> **Status:** Gmail-to-backend integration reconfirmed 2026-10-13; WBS 2.4 credential-context detector implemented internally; live threat output pending
> **Last updated:** 2026-10-13
> **Assignment:** Upwind Security â€” Security Analyst Home Assignment
> **Delivery constraint:** 48-hour focused development window, with a working live Gmail demonstration as the primary milestone.
> **Read this file first.** Then read `WBS.md`. Both must remain synchronized.

## 1. Project in one minute

**InboxGuardian** is a user-friendly, explainable **Gmail Add-on** that analyzes the *currently opened email* on demand and displays a **0â€“100 heuristic risk score, understandable verdict, concrete evidence, and recommended safe action**. A separate **Python backend** parses the email, runs independent security checks, correlates findings, and returns a structured result. The goal is a convincing, reliable, securely implemented interview demonstrationâ€”not an enterprise mail gateway.

### Research question

> **How effectively can a lightweight, explainable multi-signal detection system identify suspicious and potentially malicious emails within Gmail, while minimizing false positives and clearly communicating the evidence and uncertainty behind each verdict?**

This question motivates the project; a 48-hour prototype cannot establish general real-world detection accuracy. Any empirical claims must be limited to the actual test dataset.

## 2. Source-of-truth hierarchy and assignment alignment

1. **Upwind's supplied assignment** (`UPWIND_HOME_ASSIGNMENT.md`) is authoritative for external requirements.
2. **This document** defines agreed project scope, implementation constraints, decisions, and session status.
3. **`WBS.md`** defines ordered implementation work and acceptance gates.
4. **[`docs/detection-contract.md`](docs/detection-contract.md)** defines the current six-detector target, data/evidence interfaces, unknowns, test gates, and proposed scoring semantics. Numerical weights/thresholds remain open pending review.
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

1. **Simple for the user:** open Gmail â†’ select InboxGuardian â†’ choose **Analyze this email** â†’ read a score/verdict and short reasons. Show a clear loading/error/incomplete state. Minimize steps and jargon.
2. **Meet assignment requirements end to end:** a real contextual Gmail Add-on and separately running backend must work before optional detectors/features.
3. **Explain every suspicion:** evidence must correspond to an actual observed signal; show what was observed, why it matters, and a safe next step. Avoid unexplained labels, hidden LLM claims, or made-up certainty.
4. **Security by default:** least-privilege access, safe processing of hostile emails, secured backend, protected secrets, minimal retention, no arbitrary link fetching or executing attachments.
5. **Honest uncertainty:** unavailable or insufficient signals are **unknown**, not clean. A 0â€“100 score is a **heuristic risk index, not a probability** unless independently calibrated.
6. **Reliable, demonstrable delivery:** a working narrow vertical slice outranks broad incomplete feature coverage.

## 5. MVP definition / acceptance criteria

### Must-have â€” required to claim MVP complete

- [ ] Newly created **Google Apps Script / Google Workspace Gmail Add-on** installed on a **real test Gmail account**; contextual view for the opened email.
- [ ] User explicitly initiates analysis via a simple, visible action (or an equally clear contextual user flow); the UI identifies the current email and does not silently scan the whole inbox.
- [ ] Add-on sends only necessary email fields to a **separate, reachable Python/FastAPI backend** through an authenticated/authorized, HTTPS-protected interface; integration tested live.
- [ ] Backend validates and safely normalizes inputs and returns a **versioned JSON contract** containing risk index (0â€“100), verdict, detector evidence, limitations/unknowns, and recommended action.
- [ ] Exactly the **six approved threat detectors** documented below are implemented or explicitly marked as planned: sender impersonation, deceptive URLs, credential-phishing context, suspicious attachments, payment redirection / financial fraud, and NLP-based phishing classification. Do not add standalone SPF/DKIM/DMARC, historical sender profiling, QR/image, malware sandbox, or LLM-based detectors without separate approval.
- [ ] Conservative deterministic **multi-signal correlation**; neither a single generic keyword nor missing metadata is treated as proof of malice.
- [ ] User sees one of: **High risk**, **Suspicious**, **No significant suspicious signals found**, or **Unable to assess / Incomplete**; no definitive "safe" designation.
- [ ] User sees **2â€“4 plain-language findings**, a way to identify contributing evidence, and a specific safe next action; no automatic opening of suspicious URLs.
- [ ] Labeled safe synthetic `.eml`/JSON samples include malicious-looking and benign edge cases; automated tests evaluate both and report a confusion matrix or transparent per-case outcomes, plus known limitations.
- [ ] Backend never executes attachments, follows untrusted links, or treats message text as instructions. Secrets are outside Git; request validation, size limits, error handling, and sensitive log redaction exist.
- [ ] Public Git repo contains runnable source, tests, safe config examples, a root `README.md`, architecture sketch, setup instructions, explanation of score, security trade-offs, and demo steps.
- [ ] Demonstration rehearsed end to end using a real Gmail account and safe test messages; errors and fallback plan documented.

### Explicitly deferred

- Chrome extension, proactive inbox watcher, Gmail push/Pub/Sub, browser notifications, account-wide scanning, multi-user admin, auto-quarantine, malware sandbox execution, QR/image OCR, historic sender baseline, production reputation APIs, LLM-based verdicts, statistical calibration claims, Google Marketplace publication.
- Attachment analysis is limited to **metadata-only** inspection under the approved Suspicious Attachments detector; no binary execution, detonation, macro execution, unpacking, or malware sandboxing.

## Approved Threat Detection Scope

This project has exactly **six approved threat detectors**. As of 2026-10-13, sender identity, deceptive URL, and credential-context detectors are implemented internally and can be run by the internal orchestration layer; the current backend `/analyze` endpoint still returns the explicit `DEMO / NOT ANALYZED` / `INCOMPLETE` response. The approved scope below is therefore the implementation target for WBS 2 and later validation work, not evidence of live Gmail detection capability.

The six detectors should share a common evidence model: each finding must include a stable ID, severity, observable evidence, interpretation, contribution to the heuristic risk index, known limitations, and likely benign explanations where relevant.

### 1. Sender Impersonation

- **Status:** Implemented internally; not wired into `/analyze`.
- **Purpose:** Detect suspicious sender identities that may misrepresent an individual, brand, service, or organization.
- **Threat or attack technique addressed:** Brand impersonation, executive impersonation, supplier impersonation, reply-to redirection, and lookalike-domain social engineering.
- **Observable indicators:** Display-name and address mismatch, sender name claiming a known service while using an unrelated domain, Reply-To domain different from From domain, visually similar domains, unusual subdomains, and non-obvious free-mail or delegated senders.
- **Intended implementation approach:** Parse and normalize From and Reply-To safely; compare display names, domains, and organizational hints; check for simple lookalike patterns without making reputation claims; treat legitimate third-party senders, mailing platforms, and delegated senders as important counterexamples.
- **Expected output:** Evidence-backed findings such as `sender_reply_to_mismatch` or `sender_lookalike_domain`, with the observed fields, why they are suspicious, and a recommended verification action.
- **Known limitations and potential false positives:** Gmail-provided message fields may be incomplete; some legitimate services use third-party senders or separate reply handling; lookalike detection is heuristic and cannot prove domain ownership or malicious intent.

### 2. Deceptive URLs

- **Status:** Implemented internally; not wired into `/analyze`.
- **Purpose:** Identify misleading or suspicious hyperlinks without visiting them.
- **Threat or attack technique addressed:** Link deception, credential-harvesting links, misleading display text, malicious-looking redirects, and suspicious URL construction.
- **Observable indicators:** Displayed URL or domain differs from destination host, link text claims one brand/domain while `href` points elsewhere, IP-address hosts, suspiciously deep or noisy subdomains, URL shorteners or redirect-looking paths, punycode/unicode lookalikes, and credential-themed paths.
- **Intended implementation approach:** Safely extract links from text and HTML; normalize URLs and domains; compare visible text, claimed domains, sender domain, and destination host; flag suspicious structures while avoiding the rule that every unfamiliar URL is malicious.
- **Expected output:** Findings that name the visible text and destination relationship, the structural concern, and the uncertainty around benign tracking, marketing, or outsourced login infrastructure.
- **Known limitations and potential false positives:** The detector will not fetch, expand, or reputation-check URLs by default; legitimate email platforms often use tracking and redirect domains; unfamiliar domains alone are weak evidence.

### 3. Credential-Phishing Context

- **Status:** Implemented internally; not wired into `/analyze`.
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

**Technical contract:** See [`docs/detection-contract.md`](docs/detection-contract.md) for the six approved families, `TRIGGERED`/`NOT_TRIGGERED`/`INCONCLUSIVE`/`NOT_RUN` internal outcome proposal, data collection gaps, evidence accountability and evaluation requirements. Its scoring thresholds and weights are **not yet frozen**. Preserve the current external `schema_version: "1.0"` models during the first parsing milestone.

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
11. **Approved scorer architecture (2026-10-13): Method C â€” correlation-aware, category-capped deterministic evidence scoring.** Deduplicate overlapping observations across rules/families, cap each family's credited contribution, and allow correlation increases only for genuinely independent, auditable evidence. A high-confidence standalone indicator may still warrant a warning. NLP classification remains outside the combined heuristic score pending separate evaluation. **Weights, caps, bonuses, evidence-identity logic, coverage requirements, and verdict thresholds are not yet approved or implemented.** See `docs/detection-contract.md`.
12. Recommended response labels remain `HIGH_RISK`, `SUSPICIOUS`, `NO_SIGNIFICANT_SIGNALS`, and `INCOMPLETE`.
12. Limit first-version linguistic analysis to English-language body/context heuristics, while URL and sender structural parsing should not assume ASCII-only inputs.

## 7. Target user experience

**Journey:** Open an email â†’ open InboxGuardian's side panel â†’ click **Analyze this email** â†’ view a succinct card:

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

**Implementation status:** The basic Gmail-to-backend vertical slice has been manually verified: opened Gmail message -> Apps Script Gmail Add-on -> ngrok HTTPS -> local FastAPI -> JSON response -> Gmail card. The backend response remains `DEMO / NOT ANALYZED`; no real threat detection or scoring engine is implemented. No persistent database is necessary for the first version; process on demand and avoid storing email content.

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

**Auth note:** Never send Gmail access tokens as backend authentication by default. Choose an appropriate authenticated Apps Script â†” backend arrangement, with backend request verification, secret rotation and no committed credentials. Document the residual security trade-offs for a single-user demo.

## 9. Proposed repository structure and modular backend architecture

```text
inboxguardian/
â”œâ”€â”€ README.md
â”œâ”€â”€ PROJECT_OBJECTIVE.md             # canonical context, rules, session handoff
â”œâ”€â”€ WBS.md                           # work packages and gates
â”œâ”€â”€ addon/
â”‚   â”œâ”€â”€ Code.gs                     # Apps Script CardService and API client
â”‚   â””â”€â”€ appsscript.json              # manifest (no secrets)
â”œâ”€â”€ backend/
â”‚   â”œâ”€â”€ app/                          # FastAPI, schemas, validation, engine
â”‚   â”‚   â”œâ”€â”€ main.py
â”‚   â”‚   â”œâ”€â”€ models.py
â”‚   â”‚   â”œâ”€â”€ scoring.py
â”‚   â”‚   â””â”€â”€ detectors/
â”‚   â”œâ”€â”€ requirements.txt or pyproject.toml
â”‚   â””â”€â”€ .env.example
â”œâ”€â”€ tests/
â”‚   â”œâ”€â”€ fixtures/                     # safe illustrative emails and labels
â”‚   â”œâ”€â”€ unit/
â”‚   â””â”€â”€ integration/
â”œâ”€â”€ docs/
â”‚   â”œâ”€â”€ architecture.md
â”‚   â”œâ”€â”€ scoring-policy.md
â”‚   â”œâ”€â”€ security-decisions.md
â”‚   â””â”€â”€ demo-runbook.md
â””â”€â”€ .gitignore
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
|-- scoring.py              # Future Method C scorer
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
`-- test_scoring.py         # Future
```

Responsibilities:

- `parsing.py` normalizes existing validated input and extracts structural evidence. It does not decide maliciousness.
- `detectors/*.py` implement independent detector logic. Each detector receives normalized data and returns structured internal evidence; detectors do not calculate final email risk.
- `detectors/base.py` defines the shared internal detector-result contract, statuses, finding shape and evidence conventions.
- `engine.py` orchestrates parser/detector execution internally and preserves evidence for future scoring. It is not wired into `/analyze` yet.
- `scoring.py` will later implement approved Method C: evidence deduplication, detector-family caps, independent-evidence correlation adjustments and final verdict mapping. It is not implemented yet.
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

### End-of-session / handoff procedure â€” REQUIRED

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
| FastAPI + Apps Script CardService | **Implemented for integration spike** | Manual Gmail-to-backend flow verified; detection remains pending |
| Exactly six threat detectors | **Approved / planned** | Five deterministic detectors plus one stochastic NLP classifier; none implemented yet |
| English-only linguistic heuristics | **Proposed MVP scope** | Limited time; structural signals can work more broadly |
| Local HTTPS tunnel and demo auth | **Verified for prototype** | ngrok HTTPS to `127.0.0.1:8000`; shared demo token via env var and Script Properties |
| Detection contract and implementation order | **Drafted 2026-10-13; review pending** | `docs/detection-contract.md`; core three first, then attachment/financial, then separately evaluated NLP |
| Scoring architecture (Method C) | **APPROVED / NOT IMPLEMENTED** | Category caps + cross-rule evidence deduplication + explainable correlation only with distinct evidence; no automatic NLP vote |
| Scoring weights / thresholds / coverage / dataset | **OPEN** | Rule weights, caps, evidence identity, correlation adjustments, verdict cutoffs, minimum coverage and ML data require review and tests |
| Repository URL and live demonstration account | **SET / USER-VERIFIED** | GitHub URL is recorded; real Gmail account add-on verification was reported by the user |

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
| Agent access | Local clasp connection verified; source synchronized by user-approved workflow |
| Agent read/edit/sync capability | Local files can be edited; `clasp status` works and lists `Code.js` and `appsscript.json`; `clasp push` was performed during the verified integration milestone |
| Local synchronization method | Google `clasp` with `addon/` as the local root and local `.clasp.json` pointing to the existing project ID |
| Gmail Add-on deployment | Unpublished add-on installed/authorized and manually verified in a real Gmail account |

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

## 13. Session Handoff â€” continuously maintained

> **Agents must replace/update this section at the end of every working session.** Never mark something as deployed, tested or complete without evidence.

- **As of:** 2026-10-13 (internal detector orchestration implementation)
- **Current state:** Gmail-to-backend integration remains preserved: `/analyze` still returns the explicit `DEMO / NOT ANALYZED` / `INCOMPLETE` response and the Apps Script source/manifest were not modified in this detector task. A backend-internal parser, sender detector, URL detector, credential-context detector and orchestration layer now exist, but no detector output is exposed through Gmail or the public API yet. No scorer, NLP model, or Gmail UI replacement is implemented.
- **Approved product scope:** Exactly six detection families are planned: sender, URL, credential context, attachment metadata, financial fraud, NLP. Full scope **does not** imply completed implementation. Three original deterministic families are the initial reliable slice; attachment/financial follow, while NLP is evaluated separately before aggregation.
- **Work completed in this session:** Verified and committed WBS 2.4 credential detector implementation and documentation. Added `backend/app/engine.py` and `tests/unit/test_engine.py` for internal orchestration: parse once, run sender/URL/credential detectors in stable order, preserve statuses/findings/evidence/limitations, and mark planned detector families as `NOT_RUN` when represented. `/analyze`, Apps Script, auth behavior and public response schema were not changed.
- **Scoring decision (2026-10-13):** Method C (correlation-aware, category-capped evidence scoring) approved as architecture **only**. No scoring implementation, weights, caps, bonuses, thresholds, or required evidence coverage approved. NLP remains experimental and excluded from the aggregate until evaluated.
- **Open decisions:** Final numerical weights, caps, thresholds, scoring evidence keys, correlation/coverage requirements, attachment metadata collection, NLP dataset/evaluation, public-suffix/registered-domain comparison, and possible future API status/truncation extensions. WBS 0.5 remains open until scoring parameters and semantics are approved. Sender, URL and credential-context detector findings are currently unscored and internal.
- **Next task:** Approve the smallest Method C scoring and response-mapping plan needed to connect internal engine output to a real Gmail result. Do not start WBS 2.5 attachment detection, alter Gmail UI, implement NLP, or replace `/analyze` output without separate authorization.
- **Validation evidence:** `.\.venv\Scripts\python.exe -m pytest -q` passed 97 tests with 2 warnings on 2026-10-13. The warnings were the existing Starlette/httpx deprecation and pytest cache write warning. Engine coverage added 13 tests.
- **Git/security handoff:** WBS 2.4 implementation commit `8a69a1f` and documentation commit `32c893c` were created locally. Orchestration code/tests/docs remain uncommitted for review. Before any future commit, review the diff and confirm `UPWIND_HOME_ASSIGNMENT.md`, `addon/.clasp.json`, `.env`, credentials, tokens and real email content are not staged or tracked.

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
| 2026-10-13 | Codex internal orchestration implementation | WBS 2.4 committed; internal engine added to run parser plus three core detectors; `/analyze` and Apps Script unchanged | `pytest -q`: 97 passed, 2 warnings | Review diff; approve minimal Method C scoring plan |

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

