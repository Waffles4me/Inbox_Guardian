# InboxGuardian - Method C v1 Scoring Policy

> **Status:** APPROVED, IMPLEMENTED AND WIRED TO BACKEND `/analyze`
> **Date:** 2026-10-13
> **Scope:** Initial scoring specification for the three implemented internal detector families only: sender identity, URL deception and credential context.

This document records the approved deterministic Method C v1 scoring policy implemented in `backend/app/scoring.py`, tested in `tests/unit/test_scoring.py`, and mapped into the backend `/analyze` response by `backend/app/main.py`. It does not change the Gmail UI, public response schema, detector code or authentication behavior; Gmail presentation remains a separate milestone.

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

Total possible score from current implemented families is capped at 85 before any future families. Initial correlation bonus is explicitly `0`.

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

## Within-Family Reconciliation

For each family:

1. Start with proposed contribution for each finding.
2. Deduplicate exact repeated `evidence_id` values.
3. For URL findings about the same actual destination host and same visible claim, keep the highest contribution if two rules ever overlap.
4. For credential findings, treat `credential_request_with_link` as contextual support only. It has approved contribution `0`, should not raise the score, and must not establish independent corroboration with URL evidence.
5. Sum remaining contributions and apply the family cap.

The scorer should expose a compact explanation of raw finding points, removed duplicates, cap reductions and final credited family contribution.

## Cross-Family Deduplication and Independence

Cross-family deduplication should avoid counting the same observation as independent support:

- URL structural findings and credential link-context findings may reference the same link evidence. This is correlated, not independent, unless there is also distinct credential request text.
- `credential_request_with_link` should never be the basis for a correlation bonus with `url_deception`; initial bonus is zero, and later correlation should require a URL finding plus distinct credential request text.
- Sender identity evidence is independent from URL and credential text when based on `from`/`reply_to` fields.
- URL evidence is independent from credential text when the URL finding identifies structural deception and the credential finding identifies separate request language.
- Multiple credential findings from the same sentence or request should remain within the credential cap and should not create separate family independence.

Initial implementation computes no correlation bonus. It only needs enough metadata to explain whether `HIGH_RISK` eligibility is satisfied by at least two distinct triggered families with nonzero credited contributions.

## Coverage and INCOMPLETE Policy

Use `INCOMPLETE` when the available evidence is insufficient for a meaningful assessment, regardless of score. Proposed initial conditions:

- Parser fails to produce any subject, sender, body text, HTML text or URL evidence useful to implemented detectors.
- Sender is missing/malformed and both URL and credential detectors are `INCONCLUSIVE` or `NOT_TRIGGERED` due to missing applicable evidence.
- Any implemented detector returns `NOT_RUN` because of an unexpected internal failure.
- Essential current-message fields are absent or clearly truncated in a way that prevents meaningful interpretation, once truncation metadata exists.

Do **not** mark `INCOMPLETE` merely because attachment, financial and NLP families are planned but unimplemented. They should be disclosed as unavailable limitations.

## Sufficient Coverage for NO_SIGNIFICANT_SIGNALS

`NO_SIGNIFICANT_SIGNALS` is eligible only when:

- The parser ran.
- At least sender identity and one body/link-oriented family completed as `NOT_TRIGGERED`.
- No implemented detector is `TRIGGERED`.
- No implemented detector has a blocking `NOT_RUN`.
- Inconclusive results, if any, are disclosed and do not affect the checks that did run.

This verdict must be phrased as no significant suspicious signals found, not safe.

## HIGH_RISK Independence Requirement

`HIGH_RISK` requires:

- Final score at least 60.
- Nonzero credited contributions from at least two implemented families.
- At least two genuinely distinct observations, such as sender identity mismatch plus deceptive URL, or deceptive URL plus credential request text.

Examples that should **not** be enough for high risk by themselves:

- Several credential-context findings from the same request sentence.
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
| Unimplemented detector families | No attachment/financial/NLP implementation. | Planned families `NOT_RUN` with explicit limitations. | Does not force `INCOMPLETE` by itself |

## Implemented Scorer Interface

`backend/app/scoring.py` exposes:

- `score_engine_result(result: EngineResult) -> ScoringResult`
- `ScoringResult`: `risk_score`, `verdict`, per-family accounting, scored findings, limitations, coverage assessment, independent evidence families, correlation bonus and implementation version.
- `ScoredFinding`: original immutable detector finding plus approved weight, effective contribution, counted flag and accounting note.
- `FamilyScore`: raw points, capped points, cap and per-family limitations.

The scorer consumes `EngineResult`, not raw `EmailPayload`, and the backend serializer preserves public `AnalyzeResponse` schema version `1.0`. The scorer does not mutate engine input objects and does not fetch URLs, execute HTML, retrieve attachments or use external services.

Backend `/analyze` mapping:

- Returns `risk_score`, `verdict`, scored detector findings, limitations, recommended action and `detector_version`.
- Uses `risk_score: 0` as the required-schema placeholder for `INCOMPLETE`, with an explicit limitation that no meaningful score was produced.
- Preserves contribution reconciliation for completed assessments by mapping effective scored contributions into public findings.
- Does not alter Gmail CardService presentation; the existing add-on UI still needs a separate update before claiming real-score display.
