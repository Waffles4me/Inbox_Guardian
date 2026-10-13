# InboxGuardian - Detection Contract

> **Version:** Draft 0.1 - 2026-10-13
> **Status:** Six-detector scope and **Method C v1 scoring wired to backend `/analyze`**; parser, three core detectors, orchestration, scoring and response mapping exist; Gmail UI adaptation remains pending
> **Source of truth:** [`PROJECT_OBJECTIVE.md`](../PROJECT_OBJECTIVE.md) and [`WBS.md`](../WBS.md)
> **Purpose:** Specify testable evidence, input availability, detector outcomes, scoring semantics, and acceptance criteria without changing the working Gmail integration.

> **Implementation note:** WBS 2.1 parser, WBS 2.2 sender detector, WBS 2.3 URL detector, WBS 2.4 credential-context detector, internal orchestration, Method C v1 scoring and backend response mapping now exist. The latest automated run passed **145 tests, 2 warnings** on 2026-10-13.

## 1. Baseline and change boundary

The **manually verified** flow is Gmail opened message -> Apps Script (`addon/Code.js`) -> ngrok HTTPS -> authenticated FastAPI `POST /analyze` -> Gmail CardService. The backend `/analyze` endpoint now returns real parser -> engine -> scorer output in the existing schema. The Gmail CardService UI source was not changed in this backend integration and may still display demo-specific text until the next UI milestone. The live Gmail flow was manually reconfirmed by the user earlier on 2026-10-13, before this backend response-mapping change.

Preserve `POST /analyze`, `GET /health`, `X-InboxGuardian-Token`, Apps Script project, current OAuth scopes, and request/response schema version `1.0` during the initial engine work. Do not deploy or rewrite the Add-on as part of the first parser milestone. Treat any future API/schema, Gmail permission, hosting, or ML dependency change as a separately reviewed decision.

## 2. Approved scope and implementation sequence

| ID | Detector family | Approved | Data needed | First implementation priority |
|---|---|---|---|---|
| `sender_identity` | Sender impersonation | Yes; implemented and exposed through backend `/analyze` | `from`, `reply_to`, optional corroborating subject/body | Core |
| `url_deception` | Deceptive URLs | Yes; implemented and exposed through backend `/analyze` | `text_body`, `html_body`, optionally sender | Core |
| `credential_context` | Credential phishing | Yes; implemented and exposed through backend `/analyze` | `subject`, `text_body`, safely extracted visible HTML text, optional link evidence | Core |
| `attachment_metadata` | Suspicious attachments | Yes; not implemented | filename, MIME/content type, size from trustworthy message API access | Later deterministic increment; blocked on actual data collection |
| `financial_fraud` | Payment redirection / financial fraud | Yes; not implemented | subject/body and independent identity/link context | Later deterministic increment; cannot establish historical changes |
| `nlp_phishing` | NLP phishing classifier (TF-IDF + logistic regression candidate) | Yes; not implemented | labeled training/evaluation data, bounded subject/body | Experimental increment, evaluated before score integration |

The approved **target scope** contains six detectors. This does **not** imply all six are mandatory to claim the first usable three-family vertical slice. Each unimplemented detector must be explicitly labeled *planned/unavailable*, not silently presented as having passed. Upwind's supplied assignment does not mandate a detector count or machine learning; prioritize a reliable Gmail score/verdict/evidence demo over incomplete breadth.

Explicit exclusions: dedicated SPF/DKIM/DMARC claims without verified provenance, mailbox-history profiling, QR/image phishing, malware execution or detonation, link visiting or reputation lookups, automatic quarantine, background inbox monitoring, external inference services, and LLM-based verdicts.

## 3. Observed input contract (existing implementation)

### Request to keep stable

```json
{
  "schema_version": "1.0",
  "email": {
    "subject": "Synthetic notice",
    "from": "Service <notice@example.test>",
    "reply_to": "",
    "text_body": "This is a synthetic test email.",
    "html_body": "<p>This is a synthetic test email.</p>",
    "headers": {},
    "attachment_metadata": []
  }
}
```

In existing `backend/app/models.py`, `EmailPayload` accepts `subject` (max 998 chars), `from` via Python alias `from_address` (max 998), `reply_to` (max 998), `text_body` and `html_body` (each max 50,000), `headers` (max 50; each key max 255 and value max 2,000), and `attachment_metadata` (max 25; filename max 512, content type max 255, optional nonnegative size). `schema_version` is `1.0`. An invalid request currently returns validation HTTP 422. Empty optional fields are allowed by the input model; that does not establish assessment sufficiency.

**Actual Apps Script collection (`addon/Code.js`):** subject, From, Reply-To, truncated plain text, truncated HTML. It sends `headers: {}` and `attachment_metadata: []` as placeholders. Therefore absence of attachment metadata currently means **not collected**, not **no attachments**; the empty headers likewise are not authentication evidence. Body truncation currently provides no explicit truncation flag; do not claim a full-message assessment when completeness cannot be established. A later Add-on enhancement should introduce a reliably distinguished *not collected* state before drawing negative attachment conclusions, using separately approved schema/UI changes if necessary.

### Parsing and normalization constraints

- Normalize email mailbox fields defensively; retain original bounded strings for traceability, but derive display name, mailbox, domain and parse/validity status separately. Malformed, missing or multi-address fields become *unknown* rather than accepted as trustworthy sender identity.
- Normalize case where semantically appropriate; handle internationalized/IDNA hostnames carefully and preserve enough original spelling to explain confusables. Never assume a different domain is a confirmed impersonation attempt. Do not invent a trusted brand/organization reference list.
- Extract visible text and anchors from HTML **as inert data**, never execute scripts, load remote images, fetch URLs, or render hostile HTML. Resolve HTML entities; bound parsed URL count, URL length and parsing work to avoid abuse.
- Parse HTTP(S) URLs, hosts and userinfo explicitly; reject or mark malformed/non-HTTP(S) targets unsupported rather than following them. Avoid simplistic substring matches for a URL's true hostname. Respect legitimate tracking/redirect and delegation cases as counterexamples.
- Normalize text for conservative **English-language** context rules. Do not imply multilingual coverage. Beware quoted/forwarded material, signatures and benign warnings when interpreting language.
- Never execute or open attachments. Attachment **filename, declared MIME type and size** are untrusted metadata; even a suspicious-looking extension is not evidence of confirmed malware.
- Do not treat arbitrary `Authentication-Results` headers from unverified origins as authoritative Google SPF/DKIM/DMARC verdicts.
- Avoid logging raw email bodies, URLs with sensitive query parameters, credentials, token values, or private attachment names. Sanitize/redact observations sent to UI or logs.

## 4. Detector outcome contract (internal; proposed implementation interface)

Use a consistent internal result for each detector, separate from the externally stable `AnalyzeResponse`. Recommended fields:

```text
DetectorResult:
  detector_id: stable family ID
  status: TRIGGERED | NOT_TRIGGERED | INCONCLUSIVE | NOT_RUN
  findings: list[Finding]       # existing external Finding fields where applicable
  evidence_sources: list[str]   # e.g., from, reply_to, html_body; no raw private content
  limitations: list[str]
  implementation_version: str
```

- `TRIGGERED`: at least one specific observed, testable suspicious signal.
- `NOT_TRIGGERED`: the detector actually ran on sufficient applicable data but found no defined trigger; **not** a guarantee that the message is clean.
- `INCONCLUSIVE`: attempted but data is malformed, ambiguous, truncated or otherwise insufficient for a meaningful decision.
- `NOT_RUN`: not implemented, disabled, missing required collected fields, or model unavailable; include reason.

These fields are **internal design guidance, not a present API capability**. Preserve external `schema_version: "1.0"` and existing `Finding`/`AnalyzeResponse` until a versioned API change is explicitly accepted. A future response extension for per-detector statuses may be valuable but is not necessary for the first normalization slice.

### Engine result contract

`backend/app/engine.py` now exposes `analyze_with_detectors(payload: EmailPayload) -> EngineResult` for internal use. It:

- Receives an already validated `EmailPayload`.
- Calls `parse_email_payload` exactly once.
- Runs implemented detectors in stable order: `sender_identity`, `url_deception`, `credential_context`.
- Represents planned but unavailable families as `NOT_RUN`: `attachment_metadata`, `financial_fraud`, `nlp_phishing`.
- Preserves each detector's `DetectorResult`, findings, evidence source identities, limitations and parser issues.
- Returns aggregate `findings`, `evidence_sources`, `limitations`, `parse_issues` and `implementation_version`.

The engine intentionally does **not** produce `risk_score`, `verdict`, user-facing recommendations, correlation bonuses, deduplicated score contributions, or public API responses. It does not fetch links, execute HTML, retrieve attachments, train/evaluate NLP, or perform Gmail-specific logic. Unexpected detector failures become bounded `NOT_RUN` detector results so they cannot be mistaken for successful clean checks.

### Scorer result contract

`backend/app/scoring.py` exposes `score_engine_result(result: EngineResult) -> ScoringResult` for internal use. It maps implemented finding IDs to approved Method C v1 weights, deduplicates repeated evidence, reconciles overlapping URL/link and credential-link context, applies family caps, assigns a bounded `0..100` heuristic risk index and returns an internal verdict. It preserves explainable accounting through `ScoredFinding`, `FamilyScore`, coverage assessment, limitations, independent evidence families and a `correlation_bonus` currently fixed at `0`.

The scorer intentionally does **not** serialize public API responses, change `AnalyzeResponse`, wire into `/analyze`, fetch links, execute HTML, retrieve attachments, run NLP, or call external services.

### Findings (existing public fields)

Existing `Finding` fields: `id`, `severity` (`info|low|medium|high`), `title`, `observation`, `interpretation`, and integer `contribution` (0-100). Each emitted finding must have a stable rule-specific ID, an **observed** condition, a **qualified** interpretation that permits benign explanations, and a score contribution that is traceable to an explicit scoring rule. Do not invent evidence, reverse-lookup unverifiable reputation, or expose passwords/OTP codes/URL secrets in observation strings. A detector may yield zero findings while still reporting that it ran.

Illustrative (not implemented, not a final weight):

```json
{
  "id": "sender_reply_to_domain_mismatch",
  "severity": "medium",
  "title": "Reply address differs from sender domain",
  "observation": "From and Reply-To use different domains in this message.",
  "interpretation": "Replies may go to a different operator; legitimate delegated senders can behave this way too.",
  "contribution": 0
}
```

The example contribution of `0` intentionally avoids prematurely agreeing a scoring weight; final noninformational contributions must be justified by a tested scoring policy.

## 5. Risk scoring and verdict semantics

**Already agreed:** 0-100 is a `heuristic_risk_index_not_probability`, **not** estimated probability of maliciousness. Conservative, evidence-led scoring; missing evidence never counts as a clean pass. Stable public verdicts:

| Verdict | Intended meaning |
|---|---|
| `HIGH_RISK` | Strong, explainable suspicious evidence under the approved conservative policy; **not proven malware or phishing** |
| `SUSPICIOUS` | Meaningful suspicious evidence needing user verification |
| `NO_SIGNIFICANT_SIGNALS` | Applicable implemented checks ran and found no significant suspicious evidence; **not safe/benign certification** |
| `INCOMPLETE` | Assessment could not meaningfully run, or essential evidence/engine capability was unavailable; a numeric placeholder must not be interpreted as low risk |

**Approved scoring architecture (Method C - correlation-aware, category-capped evidence scoring; decision 2026-10-13):**

1. Each deterministic detector emits evidence-backed, rule-specific findings, with stable identifiers and a way to identify the underlying *observation* that generated them.
2. Deduplicate overlapping evidence **within and across detector families** so the same URL/sender anomaly is not counted as independent support merely because multiple rules observed it.
3. Apply an explicit **maximum contribution per detector family** (category cap) after rule-level reconciliation. A family can report several findings while its credited points remain capped.
4. Permit a **correlation adjustment only for genuinely distinct, corroborating observations**, with an auditable explanation. The adjustment may be **zero** in the first scorer version; no bonus is preapproved.
5. Compute a deterministic bounded heuristic risk index, `0..100`, and map it to the established verdict vocabulary only when minimum evidence coverage is satisfied.
6. Preserve a route for a sufficiently strong *standalone* observable indicator to produce an appropriate warning; corroboration is not an absolute requirement for every high-risk rule.
7. The NLP classifier is **not** a sixth automatically weighted vote. Evaluate its incremental contribution separately and approve any score integration only after testing.

**Illustrative shape only (not executable or calibrated):** `risk_score = min(100, sum(capped_unique_family_contributions) + justified_distinct_evidence_adjustment)`. Contribution bookkeeping must explain deductions from deduplication, category caps and correlation adjustments without double counting. No specific numerical values are approved by this equation.

**Implemented Method C v1 policy:** approved finding weights, family caps, thresholds, zero correlation bonus and coverage rules are recorded in [`docs/scoring-policy.md`](scoring-policy.md). The scorer is exposed through backend `/analyze`; Gmail presentation is not yet adapted.

**Required invariants for the eventual scorer:**

1. Every nonzero point is attributable to an emitted finding or separately explicit, evidence-backed correlation finding/adjustment. If a cap or deduplication modifies totals, expose the reconciliation in deterministic metadata or documented rule explanations. A simple first implementation may set `risk_score = min(100, sum(finding.contribution))` after deduplication, with no bonus until tested.
2. Do not count the same underlying URL mismatch across multiple detectors as independent high-confidence corroboration. Detect/cap repeated evidence and require genuinely distinct observations for correlation increases.
3. Severity labels are *not* probabilities and are not substitutes for contribution accounting.
4. Missing or unavailable checks never subtract risk or boost confidence. If essential analysis cannot run, use `INCOMPLETE`; otherwise disclose the limits of the partial analysis.
5. A 0 score must not be displayed as "safe". If verdict is `INCOMPLETE`, its score (if schema requires one) is an unusable placeholder, explicitly labeled as such.
6. NLP model decision scores, `predict_proba` values and heuristic contribution points are not interchangeable. Do **not** add an NLP score to the aggregate until independently validated for incremental value, leakage, false positives and any calibration claim.
7. Do not publish accuracy or probability claims without measured evaluation on clearly described data.

## 6. Existing response contract and Gmail presentation

Retain the public schema from `backend/app/models.py`:

```text
AnalyzeResponse:
  schema_version: "1.0"
  risk_score: integer 0..100
  score_type: "heuristic_risk_index_not_probability"
  verdict: HIGH_RISK | SUSPICIOUS | NO_SIGNIFICANT_SIGNALS | INCOMPLETE
  findings: list[Finding]
  limitations: list[str]
  recommended_action: str
  detector_version: str
```

The current Gmail card hardcodes `DEMO / NOT ANALYZED` and does not yet reliably display the backend's real risk index. In a **later**, separate, tested UI milestone: show score (when meaningful), verdict, up to 2-4 informative findings where available, limitations/unknowns, and a concrete user action. If fewer than two meaningful findings exist, show fewer; **do not fabricate findings to fill the UI**. Escape all backend-provided text before passing it to CardService HTML-enabled text widgets. Only remove demo labels once the Gmail UI is updated and manually verified.

Expected HTTP behavior should remain: `/health` 200; authenticated well-formed request 200 with validated result; missing/wrong token 401; unconfigured server token 503; invalid input 422; unexpected analysis failures return bounded sanitized HTTP 500 errors rather than successful low-risk assessments or sensitive stack traces. Do not claim that status codes fully describe the operational security posture.

## 7. Evidence expectations per detector

| Detector | Stronger candidate observations | Weak signal / false-positive counterexample | Non-claim |
|---|---|---|---|
| Sender | Parsed distinct From/Reply-To domains **plus** impersonation wording, narrowly grounded lookalike | Mailing lists, delegated reply handling, legitimate brand alias | Domain mismatch alone proves spoofing |
| URLs | Visible claimed host different from actual `href` host; confusing userinfo or deceptive subdomain | Authorized link tracking, link redirects, URL shorteners | URL is malware-hosting without fetching/reputation |
| Credentials | Request for password/OTP plus an anomalous link or sender context | Legitimate password reset/security alert | Language alone proves credential theft |
| Attachments | Clear double executable extension or MIME/extension inconsistency from collected metadata | Legitimate macros, scripts, archives in work settings | Attachment contains malware |
| Financial fraud | Instructions to change payment details or bypass approvals, with corroborating sender/context anomalies | Legitimate new invoice or approved bank change | Request is historically unusual without history |
| NLP | Reproducible text-model prediction on held-out samples with evaluation | Domain drift, synthetic leakage, legitimate security alerts | Raw model score is calibrated probability |

## 8. Acceptance tests and fixtures (all synthetic/inert)

### Parser milestone (first Codex code task)

- Normalize valid and malformed From/Reply-To while retaining safe missing/invalid statuses.
- Extract plain-text URLs and HTML `href`/visible text without network requests or active rendering; deduplicate equivalent URLs where justified.
- Handle HTML entities, IP hosts, punycode/Unicode domains, encoded URLs, malformed HTML, missing body, truncation and input boundaries without exceptions or unsafe requests.
- Do not invent authentication results or attachment metadata. Do not modify `addon/Code.js`, `appsscript.json`, `main.py` behavior, or the public models unless a specific backward-compatible need is approved.
- Preserve all existing baseline tests (previously reported 13 passing); add parser-focused positive/negative tests using `example.test` and inert samples. Reports must state whether tests actually ran.

Implemented parser limits as of WBS 2.1: `backend/app/parsing.py` uses only Python standard-library parsing, retains at most 50 plain-text URLs and 50 HTML links per source, marks individual URLs longer than 2,048 characters as malformed, and caps extracted visible HTML text at 20,000 characters. URL display strings are redacted by removing query strings and fragments, while internal canonical matching preserves scheme, host, port, path, query and fragment for exact duplicate detection. Because `addon/Code.js` does not send a truncation flag, parser-level `input_completeness` remains `UNKNOWN` rather than claiming full-message coverage.

### Sender detector milestone

Implemented WBS 2.2 rules in `backend/app/detectors/sender.py`:

- `sender_reply_to_domain_mismatch`: triggers when parsed From and Reply-To domains are present and unrelated after conservative exact/same/subdomain comparison. Severity is `low`, contribution is `0`, and the interpretation explicitly allows benign support desks, newsletters and delegated services.
- `sender_display_domain_mismatch`: triggers when the display name contains an explicit domain claim and the parsed From domain is unrelated to that claimed domain. Severity is `medium`, contribution is `0`, and the interpretation remains qualified.

The detector returns `INCONCLUSIVE` when From is missing/malformed/ambiguous or Reply-To is malformed/ambiguous. Missing Reply-To, matching domains, display names that merely differ from mailbox local parts, and conservative same/subdomain relationships return `NOT_TRIGGERED`. The detector does not use brand lists, domain reputation, SPF/DKIM/DMARC, network lookups, scoring weights, or public `/analyze` output. Registered-domain/public-suffix handling remains open; the current comparison intentionally favors avoiding false positives over aggressive typosquat detection.

### URL detector milestone

Implemented WBS 2.3 rules in `backend/app/detectors/urls.py`:

- `url_display_destination_mismatch`: triggers when HTML link text explicitly displays an HTTP(S) URL host but the actual `href` destination host differs after parser normalization. Contribution remains `0`.
- `url_deceptive_subdomain`: triggers when the actual destination host starts with the displayed host plus an additional domain suffix, such as `accounts.example.test.attacker.test` when the visible claim is `accounts.example.test`. Contribution remains `0`.
- `url_ip_address_host`: triggers on literal IP-address HTTP(S) hosts. Severity is `low`; this is structural evidence only.
- `url_userinfo_hostname`: triggers when URL userinfo before `@` resembles a hostname while the actual destination host is different.

The detector returns `NOT_TRIGGERED` for normal links, matching displayed/destination hosts, legitimate tracking or redirect-style links without an explicit visible host claim, and messages with no link evidence. It returns `INCONCLUSIVE` when only malformed or unsupported URL evidence is available. It does not compare links to the sender domain, fetch links, expand redirects, resolve DNS, use reputation services, inspect page content, or assign scoring weights. Observations use parsed host values and preserve query/fragment redaction.

### Credential-context detector milestone

Implemented WBS 2.4 rules in `backend/app/detectors/credentials.py`:

- `credential_secret_collection_request`: triggers when active message text asks the recipient to provide passwords, OTP/MFA/security codes, or similar authentication secrets. Contribution remains `0`.
- `credential_account_verification_with_link`: triggers when account/login verification language appears with parsed URL evidence. Contribution remains `0`.
- `credential_urgent_account_threat`: triggers when credential request language is paired with account-threat or deadline pressure. Contribution remains `0`.
- `credential_request_with_link`: triggers when credential request language is paired with link evidence. Contribution remains `0`.
- `credential_security_bypass_instruction`: triggers when the message instructs the recipient to bypass normal security checks or channels. Contribution remains `0`.

The detector uses subject, plain text body, safely extracted visible HTML text and parsed link presence from `ParsedEmail`. It skips structurally identifiable quoted/forwarded content, redacts code-like 4-8 digit values from observations, and treats missing or ambiguous credential-related language as `INCONCLUSIVE`. Urgency alone, normal account-security newsletters, legitimate password-reset/MFA notifications, and generic password mentions do not trigger. It does not perform scoring, sender/link correlation beyond link-presence corroboration, language translation, reputation checks, page fetching, or public `/analyze` output.

### Internal orchestration milestone

Implemented in `backend/app/engine.py` with synthetic tests in `tests/unit/test_engine.py`:

- The parser is invoked once per analysis.
- Sender, URL and credential detectors run on the same `ParsedEmail`.
- Detector statuses remain independent; missing sender data does not prevent URL or credential checks.
- Findings and evidence identifiers are preserved for later Method C deduplication and correlation accounting.
- Planned attachment, financial and NLP detectors are represented as explicit `NOT_RUN` outcomes when included.
- The engine assigns no score or verdict and does not treat zero findings as proof of safety.
- Malformed evidence and unexpected detector failures are not converted into clean `NOT_TRIGGERED` results.

### Detector milestones

For each implemented rule: one positive synthetic trigger, at least one plausible benign counterexample, missing/ambiguous-field case, and a test that evidence text corresponds to observed input without disclosing secrets. Require aggregated tests for duplicate evidence, correlated vs unrelated signals, score boundaries and `INCOMPLETE` semantics. For attachments include missing metadata vs truly attachment-free distinction; for payments include cases where legitimate approval changes cannot be verified; for NLP use reproducible split, dataset provenance/license review, class-balance discussion, precision/recall/F1/false-positive rate and leakage checks. Small synthetic datasets support demonstrations **not** real-world accuracy claims.

### Live demonstration gate

A real Gmail account must show a suspicious/high-risk synthetic example, a benign-looking counterexample, and an incomplete/operational-failure state. Document manual outcomes distinctly from automated unit tests. Never use live private messages as publicly committed fixtures.

## 9. Open decisions requiring explicit approval before public scoring integration

1. **Gmail result presentation:** how to render the backend's real scored response in the existing CardService interface without demo wording.
2. **Attachment availability:** whether/how to collect metadata with existing Gmail scopes, and how to distinguish uncollected from absent, without downloading binaries.
3. **NLP go/no-go:** available legally usable representative labeled dataset, reproducible training and actual incremental performance; model output may remain informational if evidence is weak.
4. **Response extension:** whether a later API version needs explicit per-detector statuses, coverage and score-reconciliation fields; do not alter `1.0` without review.
5. **Parsing policy still open beyond WBS 2.1:** whether to add public-suffix/registered-domain comparison and any future schema support for reliable upstream truncation flags. Initial URL/HTML bounds and IDNA hostname normalization are pinned in parser tests.

## 10. First bounded implementation milestone and handoff

**Next Codex task:** update the existing Gmail CardService result view to display the backend's real score, verdict, findings, limitations and recommended action, then manually verify it through the live Gmail -> ngrok -> FastAPI flow. Keep scope backend/UI presentation only; do not add detector families, new Gmail scopes, model training, deploys or public response schema changes without separate authorization. Report file changes, tested scenarios, `pytest` outcomes and manual Gmail evidence. Update progress/checkpoints in `PROJECT_OBJECTIVE.md` and `WBS.md` only after verification; run Git secrecy/tracking checks before proposing commit/push. Never commit `UPWIND_HOME_ASSIGNMENT.md`, `.clasp.json`, real `.env`, credentials or real email content.

**Gate for this document:** Backend `/analyze` now returns real scored results, but G2 is not complete until Gmail renders them through the existing authenticated flow.
