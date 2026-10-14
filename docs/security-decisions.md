# Security Decisions

## Already Decided

- Analyze only the currently opened Gmail message on demand.
- Do not scan the full inbox in the MVP.
- Do not execute attachments.
- Do not follow links from emails during analysis.
- Safe parser normalization may extract mailbox fields, visible HTML text, HTML anchors, and HTTP(S) URL structure as inert data only.
- Sender detection may compare parsed From/Reply-To domains and explicit domain claims in display names, but must not make authentication, reputation, ownership, or confirmed impersonation claims.
- URL detection may compare parsed visible URL text and actual destinations, identify IP-address hosts and confusing URL userinfo, but must not fetch, expand, resolve, render, or reputation-check URLs.
- Credential-context detection may inspect English subject/body/visible HTML text for request patterns, but must not treat isolated keywords, urgency alone, or legitimate security notifications as proof of phishing.
- Internal detector orchestration may aggregate detector statuses, findings, evidence identities and limitations, but must not assign risk scores, verdicts, correlation bonuses or clean/safe conclusions.
- Do not commit secrets, Gmail tokens, private email content, or production `.env` files.
- Treat the risk score as a heuristic index, not a calibrated probability.
- Method C v1 is the approved internal scoring policy: fixed heuristic finding weights, detector-family caps, deterministic deduplication/accounting, and a zero correlation bonus.
- Use a shared demo token in the `X-InboxGuardian-Token` header for the first single-user Apps Script-to-backend prototype.
- Store the backend URL and demo token outside Git: backend environment variables locally, Apps Script Properties remotely.
- The backend `/analyze` response exposes real parser, detector and Method C scoring results; the Gmail CardService dashboard renders them, is synchronized to the Apps Script project and was manually verified in Gmail.
- Use ngrok HTTPS forwarding to `127.0.0.1:8000` for the local single-user integration demo.
- Keep startup manual for now instead of adding an all-in-one script that might hide state or expose tokens.

## Resolved By Gmail Integration Spike

- HTTPS tunnel for Apps Script to reach the backend: ngrok was manually verified.
- Manifest scopes for current-message read and external requests were sufficient for the verified Gmail flow.
- Request size limits exist for message body, HTML, headers, and attachment metadata in the backend model.
- WBS 2.1 parser limits are explicit: at most 50 plain-text URLs and 50 HTML links are retained per source, individual URLs over 2,048 characters are marked malformed, and visible HTML text output is capped at 20,000 characters.
- WBS 2.2 sender findings carry no score themselves; weights are applied by the Method C scorer. The first sender detector treats unrelated Reply-To domains as low-severity supporting evidence, handles missing/malformed identity as inconclusive, and uses conservative same/subdomain handling to reduce false positives.
- WBS 2.3 URL findings carry no score themselves; weights are applied by the Method C scorer. The first URL detector treats deceptive display/destination mismatches, prefix-subdomain composition, literal IP hosts, and hostname-like userinfo as structural evidence only.
- WBS 2.4 credential-context findings carry no score themselves; weights are applied by the Method C scorer. The first credential detector redacts code-like values, ignores structurally identifiable quoted/forwarded content, and treats missing or ambiguous credential language as inconclusive rather than malicious.
- Skipped forwarded or quoted content is never attributed to the sender, but it is reported. A forwarded-message marker, or a body made only of quoted lines, makes the result `INCOMPLETE` unless other evidence reaches the suspicious threshold, so excluded content cannot pass as a clean assessment.
- A subject line alone is not sufficient evidence for `NO_SIGNIFICANT_SIGNALS`; an empty, whitespace-only or image-only body yields `INCOMPLETE`, because the backend cannot tell an empty body from one that was not collected.
- Attachment metadata (WBS 2.5 Stage 1, local): only name, declared content type and size are read, only when the user chooses Analyze Email, with the existing current-message scope. Content methods are never called and a source test forbids them. Names and types are untrusted: they are bounded, clipped with explicit loss markers, never logged, never returned in responses, and hidden or direction-control characters are flagged rather than rendered. Missing, failed or contradictory collection is reported as such and is never treated as an absence of attachments or of risk; an unexpected collection error becomes `UNAVAILABLE` and does not stop the analysis.
- Request validation errors are sanitized: a 422 response carries only error locations (schema field names and list positions; any other location part is replaced) and error types, never the rejected values or parser messages, and nothing is logged. Unauthenticated invalid requests get 401 (or 503 when no token is configured) before any validation detail.
- Internal orchestration runs only the parser and the implemented sender, URL, credential, attachment metadata and financial-fraud detectors. The planned NLP family is represented as `NOT_RUN` when included, with an explicit reason that no check was performed.
- Attachment metadata detector (WBS 2.5 Stage 2, local): checks attachment names against fixed extension lists and hidden-character rules only. It never reads, downloads, opens, hashes, executes or uploads attachment content and calls no external service. Findings and limitations identify an attachment only by its position in Gmail's list and quote only listed extensions; filenames, MIME strings and hidden characters never appear in responses or logs, and an internal failure is reported only by exception type. A name is never presented as proof of malware, macros or executable content. Missing or unreliable metadata makes the check inconclusive and never lowers risk.
- Method C v1 scoring consumes `EngineResult`, preserves accounting, treats risk score as a heuristic index, and is wired to backend `/analyze`.
- For `INCOMPLETE`, `/analyze` returns `risk_score: 0` only as a required-schema placeholder and adds an explicit limitation. The Gmail UI displays the score as unavailable and still shows any positive findings returned by the backend.
- Unexpected route-level analysis errors return a bounded HTTP 500 instead of a successful reassuring assessment.
- The API token is compared as bytes in constant time, so a malformed non-ASCII token header is rejected with 401 like any other wrong token.
- The add-on redacts and escapes every backend and message string before display, puts only fixed words and numbers in plain-text labels, and creates no clickable links, remote images or additional network calls. Icons are built-in Material icons referenced by name.
- The add-on shows `Analysis unavailable` with no verdict or score when the backend cannot be reached, and reports a failure to build the result card separately from a backend failure.
- `.gitignore` excludes `*.eml` so downloaded messages cannot be staged by accident.

## Still Open

- Rotation/replacement plan for the demo token if the project becomes more than a single-user prototype.
- Sensitive logging and redaction rules for future detector findings and operational logs.
- Whether Gmail authentication metadata is available with trustworthy provenance.
- Whether an `INCONCLUSIVE` detector status should block `NO_SIGNIFICANT_SIGNALS`; the written scoring policy and the code currently differ (see `docs/scoring-policy.md`).
- No overall request-size cap or rate limiting exists beyond the per-field limits, and `/health`, `/docs` and `/openapi.json` are reachable without a token while the tunnel is running.
- The add-on cannot signal body truncation at 50,000 characters or distinguish an empty body from a failed retrieval.
- HTML is flattened by the parser, so quoted or forwarded content that appears only in HTML is analysed and can be attributed to the sender.
- Whether to add a public-suffix/registered-domain library for more precise domain relationship checks.
