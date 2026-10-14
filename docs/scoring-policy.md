# InboxGuardian - Method C v1 Scoring Policy

> **Status:** APPROVED, IMPLEMENTED AND WIRED TO BACKEND `/analyze`
> **Date:** 2026-10-13
> **Scope:** Scoring for the five implemented internal detector families: sender identity, URL deception, credential context, attachment metadata and financial fraud / BEC wording.

This document records the approved deterministic Method C v1 scoring policy implemented in `backend/app/scoring.py`, tested in `tests/unit/test_scoring.py`, and mapped into the backend `/analyze` response by `backend/app/main.py`. It does not change the public response schema, detector code or authentication behavior. Gmail presentation is implemented separately in `addon/Code.js`.

## Method C Summary

Method C is correlation-aware, category-capped evidence scoring:

1. Run parsing and implemented detectors through the internal engine.
2. Preserve all detector findings, statuses, evidence IDs, evidence sources and limitations.
3. Assign approved rule-level contributions only to implemented findings.
4. Reconcile repeated or overlapping findings within each detector family.
5. Apply a maximum contribution cap per detector family.
6. Apply no correlation bonus initially.
7. Require independent evidence from at least two families for `HIGH_RISK`.
8. Treat missing, malformed, inconclusive and unimplemented checks as coverage limitations, never as clean evidence.

Risk index is a heuristic index, not a probability.

## Approved Family Caps

| Family | Cap | Rationale |
|---|---:|---|
| `sender_identity` | 20 | Sender anomalies are useful supporting evidence but can be legitimate due to delegation, support desks and mailing platforms. |
| `url_deception` | 40 | URL deception is the strongest implemented structural signal because it can directly identify misleading link construction without fetching the link. |
| `credential_context` | 25 | Credential-language evidence is important but has common legitimate counterexamples, so it should not dominate without link/sender context. |
| `attachment_metadata` | 35 | A runnable or disguised attachment name is strong structural evidence, but a name never proves file content, so it stays below the URL cap. |
| `financial_fraud` | 35 | Payment-redirection and BEC wording is important, but the detector has no payment history, vendor records or approval state, so it remains capped below URL deception. |

The first four family caps are unchanged from the attachment milestone. With the financial-fraud family the raw total is 155, and the score is clamped to 100. The correlation bonus is explicitly `0`.

## Approved Verdict Thresholds

| Score / condition | Verdict | Notes |
|---|---|---|
| `INCOMPLETE` condition met | `INCOMPLETE` | Coverage can override numeric score. |
| 0-19 | `NO_SIGNIFICANT_SIGNALS` | Only when sufficient implemented checks ran and no meaningful suspicious finding remains. Not a safe/benign certification. |
| 20-59 | `SUSPICIOUS` | One meaningful family, or multiple lower-confidence signals. |
| 60-100 plus independent evidence from at least two families | `HIGH_RISK` | High risk requires enough score and distinct evidence families. |
| 60-100 without two-family independence | `SUSPICIOUS` | Prevents one family from producing high risk by accumulation alone. |

## Implemented Finding Inventory and Approved Contributions

| Finding ID | Family | Trigger condition | Severity | Evidence source / ID | Legitimate counterexamples | Overlap risk | Dedup readiness | Approved contribution |
|---|---|---|---|---|---|---|---|---:|
| `sender_reply_to_domain_mismatch` | `sender_identity` | Parsed From and Reply-To domains are unrelated. | low | `from`, `reply_to`; `sender.reply_to_domain:{from}->{reply_to}` | Support desks, newsletters, delegated reply handling, ticketing systems. | Can corroborate credential or URL findings but is distinct sender evidence. | Good for exact From/Reply-To pair; public-suffix precision is still open. | 5 |
| `sender_display_domain_mismatch` | `sender_identity` | Display name contains an explicit domain claim unrelated to From domain. | medium | `from`; `sender.display_domain:{claimed}->{from}` | Legitimate delegated senders, aliases, vendors sending for a brand. | Can overlap conceptually with URL brand/domain claims but evidence source is sender identity. | Good for claimed/from pair; brand ownership is not established. | 20 |
| `url_display_destination_mismatch` | `url_deception` | HTML link text displays an HTTP(S) URL host that differs from actual destination host. | medium | `html_body`; `url.display_mismatch:{visible}->{destination}` | Tracking links, marketing platforms, outsourced login/support infrastructure. | Can overlap with credential link context if the same link is used in a credential request. | Good for visible/destination host pair. | 30 |
| `url_deceptive_subdomain` | `url_deception` | Actual host starts with displayed host plus attacker-controlled suffix. | medium | `html_body`; `url.deceptive_subdomain:{visible}->{destination}` | Rare legitimate cases; mostly confusing host construction. | May overlap with display/destination mismatch for same link; current detector emits one or the other. | Good for visible/destination host pair. | 35 |
| `url_ip_address_host` | `url_deception` | URL destination host is a literal IP address. | low | URL source; `url.ip_host:{ip}` | Internal tooling, technical alerts, lab systems. | May be independent of credential language, but same URL may also be used in credential context. | Good for IP host; repeated same IP dedupes. | 5 |
| `url_userinfo_hostname` | `url_deception` | URL userinfo before `@` resembles a hostname while actual host differs. | medium | URL source; `url.userinfo:{userinfo}->{host}` | Rare legacy URL forms, technical examples. | Can overlap with visible URL deception if same URL is also displayed in HTML. | Good for userinfo/host pair. | 30 |
| `credential_secret_collection_request` | `credential_context` | Active message text requests passwords, OTP/MFA/security codes or similar login secrets. | medium | subject/body/link-presence sources; `credential.secret_collection_request` | Legitimate resets, security training, support workflows that mention credentials but do not request them. | Strong overlap with `credential_request_with_link` when same request is paired with any link. | Weak: evidence ID is rule-level, not snippet-specific. Needs future observation key for robust dedup. | 20 |
| `credential_account_verification_with_link` | `credential_context` | Account/login verification language appears and parsed link evidence exists. | medium | subject/body/link sources; `credential.account_verification_with_link` | Legitimate account verification, email confirmation, password reset flows. | Can overlap with URL findings and credential-link context. | Weak: rule-level evidence ID does not identify exact text/link pair. | 10 |
| `credential_urgent_account_threat` | `credential_context` | Credential/account verification language is paired with urgent account-loss pressure. | medium | subject/body/link sources; `credential.urgent_account_threat` | Legitimate service outage or account-security alerts with deadlines. | Correlated with credential request text; should be additive only within family cap. | Weak: rule-level evidence ID. | 10 |
| `credential_request_with_link` | `credential_context` | Credential request language appears alongside at least one parsed link. | low | subject/body/link sources; `credential.request_with_link` | Legitimate login, password reset and MFA workflows. | Directly overlaps with `credential_secret_collection_request` plus link evidence and may also overlap with URL findings. | Weak: rule-level evidence ID; should not be treated as independent evidence from URL family. | 0 |
| `credential_security_bypass_instruction` | `credential_context` | Message asks recipient to ignore/bypass/disable security, MFA, verification or approval. | medium | subject/body sources; `credential.security_bypass_instruction` | Rare legitimate troubleshooting instructions, internal support guidance. | Can overlap with credential request language but is a distinct text pattern. | Weak-to-moderate: rule-level evidence ID, but distinct text pattern. | 20 |
| `attachment_executable_extension` (ATT-01) | `attachment_metadata` | Final extension is a Windows program or installer. | medium | `attachments`; `attachment:{position}` | Software distribution inside organisations. | Overlaps with ATT-03 and ATT-04 on the same file. | Good: one evidence ID per distinct attachment. | 25 |
| `attachment_script_extension` (ATT-02) | `attachment_metadata` | Final extension is a script, command file or `.lnk` shortcut. | medium | as above | Administrators and developers exchanging scripts. | Overlaps with ATT-03 and ATT-04. | Good. | 20 |
| `attachment_deceptive_double_extension` (ATT-03) | `attachment_metadata` | A document, image, media or archive extension directly precedes an ATT-01/ATT-02 extension. | medium | as above | Rare. | Always accompanies ATT-01 or ATT-02 on the same file. | Good. | 30 |
| `attachment_bidi_control_name` (ATT-04) | `attachment_metadata` | Name contains a bidirectional embedding, override or isolate control (U+202A-202E, U+2066-2069). | medium | as above | Rare; ordinary Hebrew and Arabic names do not need these controls. | Overlaps with any extension rule. | Good. | 20 |
| `attachment_invisible_character_name` (ATT-05) | `attachment_metadata` | Name contains U+200B, U+2060 or U+FEFF, or a zero-width joiner/non-joiner next to an ASCII character. | low | as above | Copy-paste artefacts. | Overlaps with any extension rule. | Good. | 10 |
| `attachment_active_content_type` (ATT-06) | `attachment_metadata` | Final extension is HTML, MHTML, SVG or OneNote. | low | as above | Reports, logos, shared notebooks. | Exclusive with other extension rules. | Good. | 10 |
| `attachment_macro_enabled_office` (ATT-07) | `attachment_metadata` | Final extension is a macro-enabled Office format. | low | as above | Business spreadsheets and templates. | Exclusive with other extension rules. | Good. | 10 |
| `financial_payment_destination_change` | `financial_fraud` | Bank/account/payment-destination change wording appears in the same sentence as a payment instruction. | medium | subject/body; `financial_fraud.sentence:{context}:{sentence}:{digest}` | Legitimate vendor bank-detail changes with approved documentation. | May overlap with urgency/secrecy in the same sentence. | Moderate: sentence-level evidence ID, no raw account values. | 30 |
| `financial_urgent_payment_request` | `financial_fraud` | Payment or wire-transfer wording appears with urgency and wire/authority pressure. | medium | as above | Legitimate time-sensitive finance operations. | Can overlap with secrecy or bypass wording in the same sentence. | Moderate. | 20 |
| `financial_gift_card_code_request` | `financial_fraud` | Gift-card purchase wording is coupled with a request to send redemption codes or PINs. | medium | as above | Rare legitimate reward workflows, usually not via emailed code requests. | Distinct from ordinary invoice/payment wording. | Moderate. | 30 |
| `financial_verification_bypass_request` | `financial_fraud` | A financial request asks to skip normal approval, callback, purchase-order, procurement, accounting or finance checks. | medium | as above | Rare legitimate troubleshooting or emergency process changes. | Often co-occurs with urgency or secrecy. | Moderate. | 25 |
| `financial_secret_or_channel_avoidance` | `financial_fraud` | A financial request includes secrecy or asks to avoid normal communication channels. | medium | as above | Confidential legitimate transactions, HR or legal matters. | Often co-occurs with urgency or bypass wording. | Moderate. | 20 |

ATT-08 (metadata unavailable, malformed or clipped so that a rule cannot be evaluated) adds no points; it is reported as a detector limitation. The exact extension lists, and the reasons for what is left out, are in `docs/detection-contract.md`.

## Within-Family Reconciliation

For each family:

1. Start with proposed contribution for each finding.
2. Deduplicate exact repeated `evidence_id` values.
3. For URL findings about the same actual destination host and same visible claim, keep the highest contribution if two rules ever overlap.
4. For credential findings, treat `credential_request_with_link` as contextual support only. It has approved contribution `0`, should not raise the score, and must not establish independent corroboration with URL evidence.
5. For attachment findings, every rule reads the same filename, so all findings for one attachment share a deduplication key (`attachment.name:{evidence_id}`) and only the strongest is credited; on a tie the first one emitted is kept. Distinct attachments keep separate keys and are limited by the 35-point cap, allocated strongest first and then in finding order. Identical metadata entries are checked once by the detector. Every finding from the omitted-attachment summary shares one evidence ID and is credited at most once.
6. For financial-fraud findings, a sentence can satisfy several wording rules; credit only the strongest rule for that sentence, then apply the family cap across distinct sentences.
7. Sum remaining contributions and apply the family cap.

The scorer should expose a compact explanation of raw finding points, removed duplicates, cap reductions and final credited family contribution.

## Cross-Family Deduplication and Independence

Cross-family deduplication should avoid counting the same observation as independent support:

- URL structural findings and credential link-context findings may reference the same link evidence. This is correlated, not independent, unless there is also distinct credential request text.
- `credential_request_with_link` should never be the basis for a correlation bonus with `url_deception`; initial bonus is zero, and later correlation should require a URL finding plus distinct credential request text.
- Sender identity evidence is independent from URL and credential text when based on `from`/`reply_to` fields.
- URL evidence is independent from credential text when the URL finding identifies structural deception and the credential finding identifies separate request language.
- Multiple credential findings from the same sentence or request should remain within the credential cap and should not create separate family independence.
- Attachment evidence comes from attachment names, which no other family reads, so it is independent of sender, URL and credential evidence. Only ATT-01 to ATT-04 count as independent evidence. The weak rules ATT-05 to ATT-07 are common in legitimate mail and do not establish independence. Several attachment findings are still one family.
- Financial-fraud evidence comes from active subject/body wording. It is independent from sender, URL and attachment evidence, but several BEC findings from the same sentence remain one family and do not create high-risk eligibility by themselves.

Initial implementation computes no correlation bonus. It only needs enough metadata to explain whether `HIGH_RISK` eligibility is satisfied by at least two distinct triggered families with nonzero credited contributions.

## Coverage and INCOMPLETE Policy

Use `INCOMPLETE` when the available evidence is insufficient for a meaningful assessment, regardless of score. Proposed initial conditions:

- Parser fails to produce any subject, sender, body text, HTML text or URL evidence useful to implemented detectors.
- Sender is missing/malformed and both URL and credential detectors are `INCONCLUSIVE` or `NOT_TRIGGERED` due to missing applicable evidence.
- Any implemented detector returns `NOT_RUN` because of an unexpected internal failure.
- Essential current-message fields are absent or clearly truncated in a way that prevents meaningful interpretation, once truncation metadata exists.

Do **not** mark `INCOMPLETE` merely because the NLP family is planned but unimplemented. It should be disclosed as an unavailable limitation.

The attachment check is `INCONCLUSIVE`, never `NOT_RUN`, when attachment information is missing (a V1 client), unavailable, inconsistent, or truncated without a reliable finding. `INCONCLUSIVE` does not affect coverage, and the attachment detector reports no coverage gaps, so these states never turn a verdict into `INCOMPLETE`; they are disclosed as limitations. An internal failure of the attachment detector is `NOT_RUN` and makes the assessment `INCOMPLETE`, as for any implemented detector.

### Implemented coverage rule (2026-10-13)

The conditions above were written as proposals. The scorer currently returns `INCOMPLETE` when:

- An implemented detector is `NOT_RUN` because of an internal failure, at any score.
- The score is below 20 and the sender could not be parsed.
- The score is below 20 and there is no body evidence, meaning no non-blank plain text, no visible HTML text and no supported HTTP(S) link. A subject line alone is not body evidence, so empty, whitespace-only and image-only bodies are `INCOMPLETE`.
- The score is below 20 and a detector reports a coverage gap. The credential detector reports one when the plain-text body carries a forwarded-message marker, or consists only of quoted or header-style lines; that content is skipped and never attributed to the sender.
- A detector reports `NOT_TRIGGERED` while carrying findings.

A score of 20 or more keeps its `SUSPICIOUS` or `HIGH_RISK` verdict, with the gap listed among the limitations. Findings are returned in every case. Truncation metadata does not exist, so the truncation condition above is not implemented. No weight, cap, bonus or numerical threshold was changed by these rules.

### Known limitation: weak findings below the threshold (WBS 2.5 Stage 2)

A message whose only finding is a weak attachment rule (ATT-05, ATT-06 or ATT-07, 10 points each) scores below 20 and receives `NO_SIGNIFICANT_SIGNALS`, while the finding is still listed with `+10` and the recommended action still advises caution with attachments. Two or more such files reach `SUSPICIOUS`. This is the existing V1 threshold policy, kept unchanged for this milestone and pinned by `test_single_weak_finding_stays_below_the_suspicious_threshold`. Weak weights were deliberately not raised to cross the threshold. Whether a scored finding should change the verdict label is an open policy decision (Method C v1.1 explored it and is not adopted).

Likewise, when attachment information is missing or unavailable, a message can receive `NO_SIGNIFICANT_SIGNALS` although its attachments were not assessed; the limitations say so.

## Sufficient Coverage for NO_SIGNIFICANT_SIGNALS

`NO_SIGNIFICANT_SIGNALS` is eligible only when:

- The parser ran.
- At least sender identity and one body/link-oriented family completed as `NOT_TRIGGERED`.
- No implemented detector is `TRIGGERED`.
- No implemented detector has a blocking `NOT_RUN`.
- Inconclusive results, if any, are disclosed and do not affect the checks that did run.

This verdict must be phrased as no significant suspicious signals found, not safe.

### Open discrepancy: `INCONCLUSIVE` statuses (undecided)

The second bullet above is **not** what the code does. The scorer requires a parseable sender and body evidence, but it does not check whether any body/link-oriented detector actually completed as `NOT_TRIGGERED`. A message with usable content whose URL detector is `INCONCLUSIVE` (for example only an unsupported link) and whose credential detector is `INCONCLUSIVE` (ambiguous wording) therefore receives `NO_SIGNIFICANT_SIGNALS`.

This is recorded as an open decision. The approved policy text above has been left as written, and the code has not been changed to match it. Options are to tighten the code, which risks marking ordinary ambiguous notices incomplete, or to amend the policy to describe the evidence-based rule. Neither has been chosen.

## HIGH_RISK Independence Requirement

`HIGH_RISK` requires:

- Final score at least 60.
- Nonzero credited contributions from at least two implemented families.
- At least two genuinely distinct observations, such as sender identity mismatch plus deceptive URL, or deceptive URL plus credential request text.

Examples that should **not** be enough for high risk by themselves:

- Several credential-context findings from the same request sentence.
- Several financial-fraud findings from the same payment request sentence.
- URL deception plus `credential_request_with_link` when the only credential evidence is that the same link exists.
- Sender-only findings capped at 20.

## Synthetic Evaluation Matrix

| Case | Synthetic setup | Expected detector coverage | Intended verdict category |
|---|---|---|---|
| Legitimate ordinary email | Normal sender, no links, ordinary body. | Sender `NOT_TRIGGERED`; URL `NOT_TRIGGERED`; credential `NOT_TRIGGERED`; planned families `NOT_RUN`. | `NO_SIGNIFICANT_SIGNALS` |
| Legitimate password-reset notification | Mentions reset/security but does not request secret. | Credential likely `INCONCLUSIVE`; sender/URL may be `NOT_TRIGGERED`; disclose limitation. | `NO_SIGNIFICANT_SIGNALS` or `INCOMPLETE` depending coverage policy strictness |
| Legitimate delegated Reply-To | From and Reply-To differ for support/newsletter without other signals. | Sender may `TRIGGERED`; URL/credential `NOT_TRIGGERED`. | `NO_SIGNIFICANT_SIGNALS` if only the 5-point Reply-To mismatch appears; still disclose finding |
| Legitimate marketing/tracking links | Tracking `href` with generic link text, no displayed host claim. | URL `NOT_TRIGGERED`; sender/credential `NOT_TRIGGERED`. | `NO_SIGNIFICANT_SIGNALS` |
| Sender mismatch only | Unrelated Reply-To or display-domain mismatch only. | Sender `TRIGGERED`; others `NOT_TRIGGERED`. | `NO_SIGNIFICANT_SIGNALS` for low mismatch only; `SUSPICIOUS` if medium display-domain mismatch reaches threshold after final tuning |
| Deceptive URL only | Visible host differs from actual `href`. | URL `TRIGGERED`; sender/credential `NOT_TRIGGERED`. | `SUSPICIOUS` |
| Credential request only | Request to submit password/OTP, no link or sender anomaly. | Credential `TRIGGERED`; sender/URL `NOT_TRIGGERED`. | `SUSPICIOUS` |
| Multiple independent suspicious signals | Sender mismatch + deceptive URL + credential request. | Sender/URL/credential `TRIGGERED`. | `HIGH_RISK` if score >= 60 |
| Overlapping credential/link findings | Credential request with benign-looking link, no URL deception. | Credential request + credential link context; URL may `NOT_TRIGGERED`. | `SUSPICIOUS`; link-context does not create separate family independence |
| Missing sender/body | Empty From and empty body. | Sender `INCONCLUSIVE`; credential `INCONCLUSIVE`; URL `NOT_TRIGGERED` or no evidence; planned `NOT_RUN`. | `INCOMPLETE` |
| Malformed or truncated input | Malformed URL or parser issues. | Affected detector `INCONCLUSIVE`; parse issues preserved. | `INCOMPLETE` if meaningful checks cannot run, otherwise `SUSPICIOUS`/`NO_SIGNIFICANT_SIGNALS` with limitations |
| Unimplemented detector families | No financial/NLP implementation. | Planned families `NOT_RUN` with explicit limitations. | Does not force `INCOMPLETE` by itself |
| Attachment metadata | Runnable, disguised or active-content attachment names; missing or truncated collection. | Attachment `TRIGGERED`, `NOT_TRIGGERED` or `INCONCLUSIVE`. | See `docs/evaluation-results-attachments.md` |

This matrix is the design-time intent. Measured per-case behaviour on a separate 30-case labeled synthetic set is in `docs/evaluation-baseline.md`; that set is small and author-written and is not a measure of detection accuracy.

## Implemented Scorer Interface

`backend/app/scoring.py` exposes:

- `score_engine_result(result: EngineResult) -> ScoringResult`
- `ScoringResult`: `risk_score`, `verdict`, per-family accounting, scored findings, limitations, coverage assessment, independent evidence families, correlation bonus and implementation version.
- `ScoredFinding`: original immutable detector finding plus approved weight, effective contribution, counted flag and accounting note.
- `FamilyScore`: raw points, capped points, cap and per-family limitations.

The scorer consumes `EngineResult`, not raw `EmailPayload`, and the backend serializer preserves public `AnalyzeResponse` schema version `1.0`. The scorer does not mutate engine input objects and does not fetch URLs, execute HTML, retrieve or open attachments or use external services.

Backend `/analyze` mapping:

- Returns `risk_score`, `verdict`, scored detector findings, limitations, recommended action and `detector_version`. Findings are ordered by effective contribution, strongest first, with ties in detector order. Limitations lead with any incomplete reason, then any excluded-content note, then one line naming the planned checks that did not run.
- Uses `risk_score: 0` as the required-schema placeholder for `INCOMPLETE`, with an explicit limitation that no meaningful score was produced.
- Preserves contribution reconciliation for completed assessments by mapping effective scored contributions into public findings.
- Is rendered by the Gmail CardService dashboard, which is synchronized to the Apps Script project and was manually verified in Gmail on 2026-10-13.
