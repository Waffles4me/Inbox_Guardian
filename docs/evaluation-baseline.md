# InboxGuardian - Synthetic Evaluation Baseline

> **Date:** 2026-10-13
> **Scope:** the three implemented detector families (sender identity, URL deception, credential context) and the Method C v1 scorer, at engine `engine-0.1.0` / scorer `scoring-0.1.0`.
> **Status:** evaluation only. No detector, parser, scorer, API or add-on code was changed.

## Read this first

This is a **small, synthetic, author-written** set of 30 messages. It is **not** an independent or real-world benchmark, and the numbers below must not be quoted as detection accuracy.

- The cases were written by the same agent that had already read the detector rules, so they are not blind to the implementation.
- Fifteen cases per class cannot support general claims. As an illustration of the uncertainty only, a 95% Wilson interval on 8 of 15 spans roughly 0.30 to 0.75, and the cases are not a random sample of real mail in any case.
- The value of this baseline is the per-case behaviour and the failure patterns, not the aggregate figures.

## Dataset

- Fixture: [`tests/fixtures/evaluation/cases.json`](../tests/fixtures/evaluation/cases.json)
- Runner: [`tests/evaluation/run_evaluation.py`](../tests/evaluation/run_evaluation.py)
- Generated per-case results: [`docs/evaluation-results.md`](evaluation-results.md)

| Group | Cases | Label |
|---|---:|---|
| A. Ordinary legitimate messages | 5 | BENIGN |
| B. Legitimate account/security notifications | 5 | BENIGN |
| C. Legitimate newsletters, tracking links and delegated senders | 5 | BENIGN |
| D. Credential phishing | 5 | SUSPICIOUS |
| E. Deceptive-link phishing | 5 | SUSPICIOUS |
| F. Sender impersonation | 5 | SUSPICIOUS |

Every case records an ID, label, scenario description, expected behaviour, label rationale, the detector families it is meant to exercise, and whether it overlaps a pattern used in earlier development tests. All content is inert: reserved `.test` domains, documentation IP ranges, fictional names, no attachments. The runner refuses to run if a case references any other host.

**Overlap with development fixtures.** No message text was copied from existing tests and all hosts and wording are new. Twenty-two cases nevertheless reuse a *pattern* the unit tests already cover (for example a displayed URL that differs from its destination, or a reply-with-password request) and are marked `pattern: ...` in the fixture. Eight are marked `none`: A1, A3, B3, D3, D5, E5, F2 and F4. Overlap was judged from the detector rules and the tests reviewed during development, not by an automated comparison.

## How labels were fixed

1. Each label describes the scenario's ground truth ("is this the kind of message a careful analyst would want flagged?"), not what the detectors were expected to output. Several cases were deliberately labeled against the likely output, such as a legitimate tracking link (C3, BENIGN) and a brand-name-only impersonation (F2, SUSPICIOUS).
2. The fixture file was written in full and its SHA-256 recorded before any case was passed to the backend: `e8d7ed51cbc72acbe522baea5f9c04f0df413dd53aca39e9c6c0c4ca9e9857cc`.
3. The runner prints that hash in the generated report. The file was not edited after the first run, and no label was changed after results were seen.

## Method

Each case is validated into the public `EmailPayload` model, then passed unchanged to `analyze_with_detectors()` and `score_engine_result()`. The runner does not call the network and does not alter scoring.

Binary mapping: `HIGH_RISK` and `SUSPICIOUS` are predicted suspicious, `NO_SIGNIFICANT_SIGNALS` is predicted benign, and `INCOMPLETE` is an abstention that is excluded from precision, assessed recall and false-positive rate.

## Results

| | Predicted suspicious | Predicted benign | Abstained |
|---|---:|---:|---:|
| Labeled SUSPICIOUS (15) | 8 | 7 | 0 |
| Labeled BENIGN (15) | 2 | 13 | 0 |

| Metric | Value | Denominator |
|---|---|---|
| Precision | 0.80 | 8 / 10 predicted suspicious |
| Recall | 0.53 | 8 / 15 labeled suspicious |
| False-positive rate | 0.13 | 2 / 15 labeled benign |
| Coverage | 1.00 | 30 / 30 assessed, 0 abstentions |

No case abstained, so recall is the same with or without abstentions. Per-case verdicts, scores, detector statuses and findings are in [`evaluation-results.md`](evaluation-results.md).

By group: ordinary legitimate 5/5 matched; account/security notifications 4/5; newsletters and delegated senders 4/5; credential phishing 3/5; deceptive links 3/5; sender impersonation 2/5.

## Failure analysis

### False positives (benign flagged as suspicious)

| Case | What happened | Classification |
|---|---|---|
| B2 - sign-in code delivery | `credential_security_bypass_instruction` +20. The match is "ignore this message. Your verification code is ...": it starts at the end of the plain-text body and ends in the HTML copy of the same message. With only the text body, or only the HTML body, there is no finding. | **Potential detector defect.** The credential detector joins the plain-text body and the visible HTML text, so ordinary multipart mail is read twice, and the bypass pattern is allowed to cross a sentence boundary. |
| C3 - marketing link with visible shop URL and a tracking redirect | `url_display_destination_mismatch` +30. | **Scoring-policy consequence** of a documented counterexample: the rule cannot tell a tracking redirect from a deceptive link, and its weight of 30 alone exceeds the suspicious threshold of 20. |

### False negatives (suspicious not flagged)

| Case | What happened | Classification |
|---|---|---|
| D3 - "forward me the 6-digit code you just received" | No finding. "forward" is not a recognised request verb and "6-digit code" without "verification/security/login" is not a recognised secret. | **Potential detector gap** (pattern coverage). |
| D5 - "type your login details on the secure form ... prevent deactivation" | No finding. "login details" is not a recognised secret and "deactivation" is not a recognised threat word. | **Potential detector gap** (paraphrase coverage); keyword rules are inherently brittle here. |
| E4 - shared-document lure linking to a raw IP address | `url_ip_address_host` +5, verdict clean. | **Scoring-policy consequence.** The same finding and score occur on the benign maintenance notice A5; the weight of 5 is deliberate. |
| E5 - link text `www.swiftparcel.test/account`, href on a lookalike host | No finding. Link text is compared only when it contains `http://` or `https://`. | **Potential detector gap.** A bare domain in link text is a common host claim. |
| F2 - brand name in display name, unrelated address, callback request | No finding. | **Intended scope limitation.** There is no brand list, and callback-number lures are outside the three families. |
| F3 - Reply-To on a lookalike of the From domain | `sender_reply_to_domain_mismatch` +5, verdict clean. | **Scoring-policy consequence plus detector gap.** Benign C1, C2 and C4 produce the identical finding and score; the rule does not notice that this Reply-To domain imitates the From domain. |
| F4 - supplier on a one-character lookalike domain, new bank details | No finding. | **Intended scope limitation / insufficient evidence.** A lookalike cannot be recognised without a reference domain, and the payment-change wording belongs to the planned financial-fraud detector. |

### Coverage

No case returned `INCOMPLETE`. The set contains no empty, subject-only or truncated bodies, so it does not evaluate abstention behaviour; that is covered by the unit tests and the manual Gmail checks instead.

### Other observations

- **Thresholds are not the lever.** Seven suspicious cases score 0 or 5, and four benign cases also score 5 with the same findings (A5 with E4; C1, C2, C4 with F3). No change to the suspicious threshold separates them; the misses are missing evidence, not mis-set cut-offs.
- **Several detections have no margin.** D1, D2, D4 and F1 each score exactly 20, the suspicious threshold, from a single finding.
- **Correlated evidence did not inflate scores.** In F5 the Reply-To mismatch was credited 0 under the sender cap and `credential_request_with_link` contributed 0; the total of 70 came from three independent families. In E2 the URL and account-verification findings gave 45, which stayed `SUSPICIOUS`.
- **Warning wording was handled correctly in isolation.** B5 ("we will never ask for your password ... do not turn off multi-factor authentication") and B1 produced no findings. The one warning-related failure is B2, caused by the body duplication described above.
- **Low-weight context behaved as designed.** B4 (welcome email, account verification with a link, +10) and the three Reply-To mismatches (+5 each) stayed clean.
- **Sender and URL structure rules behaved as specified.** Subdomain relationships (C5) and matching displayed URLs (A2) did not trigger; the deceptive-subdomain, display-mismatch and userinfo rules triggered on E1, E2, E3 and F5.

## Limitations

- Synthetic, small and written with knowledge of the rules; see the top of this document.
- English only, no attachments, no payment-fraud or NLP detectors, no real headers.
- One evaluator wrote the cases and the labels; there was no second labeler.
- Ground truth for C3 and E4 is debatable by design. They were included to expose where structure alone cannot decide.
- The results describe one code version and should be regenerated after any detector or scorer change.

## Recommended priorities (not implemented)

1. **Fix the B2 mechanism.** Stop analysing the same content twice when a message has both plain-text and HTML bodies, and stop the bypass pattern from spanning sentences. This is the only failure that looks like a defect, and it affects ordinary multipart security notices.
2. **Recognise a host claim in link text without a scheme** (E5), limited to text that looks like a domain.
3. **Flag a Reply-To domain that closely resembles the From domain** (F3), instead of treating every cross-domain Reply-To alike.
4. **Review credential request coverage** for "forward/pass on ... code" and "login details/credentials" wording (D3, D5), with benign counterexamples added first.
5. **Decide the policy for tracking redirects** (C3): accept the false positive as a documented limitation, or lower the standalone weight. This is a scoring-policy decision and needs explicit approval.
6. **Leave as documented limitations:** brand-name-only impersonation (F2), lookalike sender domains without a reference (F4) and IP-only links (E4).

Any change under 1 to 5 should be followed by rerunning this evaluation and reporting the before/after per-case differences, without editing the labels.

## Reproducing

```powershell
.\.venv\Scripts\python.exe tests\evaluation\run_evaluation.py --label "describe the run" --output docs\evaluation-results-<name>.md
```

`docs/evaluation-results.md` is the original baseline measurement, taken at commit `58fceef` before any change prompted by this evaluation. Write later runs to a new file so the baseline is not overwritten.

The runner is not collected by pytest and does not affect the unit-test count.

## Addendum - results after the B2 fix (2026-10-13)

Everything above this heading is the original baseline and has not been revised. This addendum records one later run.

**What changed.** The credential detector now matches the plain-text body and the visible HTML text as separate contexts instead of one joined string, so a pattern can no longer start in one representation and end in the other. No pattern, weight, cap or threshold changed. The fixture and labels are unchanged (same SHA-256).

**Result.** Post-fix per-case results are in [`evaluation-results-post-b2-fix.md`](evaluation-results-post-b2-fix.md). B2 is the only case whose outcome changed; the other 29 rows are identical.

| | Baseline | After B2 fix |
|---|---|---|
| B2 | `SUSPICIOUS` 20, false positive | `NO_SIGNIFICANT_SIGNALS` 0, true negative |
| False positives | 2 / 15 (B2, C3) | 1 / 15 (C3) |
| False negatives | 7 / 15 | 7 / 15 |
| Precision | 0.80 (8/10) | 0.89 (8/9) |
| Recall | 0.53 (8/15) | 0.53 (8/15) |
| False-positive rate | 0.13 (2/15) | 0.07 (1/15) |
| Coverage | 30/30 | 30/30 |

The same caveats apply: this is a small, author-written synthetic set, and the fix was made in response to a failure found on it, so the post-fix figures are not an independent measurement.

**Still open after the fix.**

- Within a single body the bypass pattern can still run across a sentence boundary, for example from "ignore this email." into a following sentence that begins with "Security". B2 no longer triggers only because its sentences are ordered the other way within each body.
- The subject is still joined to each body, so a pattern can span the end of the subject and the start of the body.
- Quoted-reply lines (`>`) are skipped in plain text but the same content inside an HTML blockquote is still analysed. This predates the fix.
- C3 and the seven false negatives are unchanged; recommended priorities 2 to 6 above still stand.

## Addendum 2 - results after the security-bypass fix (2026-10-13)

This addendum records a third run. Nothing above it has been revised.

**What changed.** Commit `b86011f` requires the security-bypass verb and the security term to be in the same sentence and treats a nearby negation ("do not disable MFA", "will never ask you to bypass security checks") as a warning. It was prompted by a pre-submission audit, not by a failure in this set. The fixture and labels are unchanged (same SHA-256).

**Result.** Per-case results are in [`evaluation-results-post-bypass-fix.md`](evaluation-results-post-bypass-fix.md). All 30 rows are identical to the post-B2 run: 8 true positives, 1 false positive (C3), 14 true negatives, 7 false negatives, 0 abstentions.

That no case moved is itself a limitation of this set: the audit found eight benign phrasings the bypass rule flagged, and none of them was represented here. The set should not be read as covering benign security wording.
