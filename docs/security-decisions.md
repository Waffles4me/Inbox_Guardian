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
- The backend `/analyze` response exposes real parser, detector and Method C scoring results; the Gmail CardService source now renders real backend results, pending live synchronization and manual verification.
- Use ngrok HTTPS forwarding to `127.0.0.1:8000` for the local single-user integration demo.
- Keep startup manual for now instead of adding an all-in-one script that might hide state or expose tokens.

## Resolved By Gmail Integration Spike

- HTTPS tunnel for Apps Script to reach the backend: ngrok was manually verified.
- Manifest scopes for current-message read and external requests were sufficient for the verified Gmail flow.
- Request size limits exist for message body, HTML, headers, and attachment metadata in the backend model.
- WBS 2.1 parser limits are explicit: at most 50 plain-text URLs and 50 HTML links are retained per source, individual URLs over 2,048 characters are marked malformed, and visible HTML text output is capped at 20,000 characters.
- WBS 2.2 sender findings are internal and unscored. The first sender detector treats unrelated Reply-To domains as low-severity supporting evidence, handles missing/malformed identity as inconclusive, and uses conservative same/subdomain handling to reduce false positives.
- WBS 2.3 URL findings are internal and unscored. The first URL detector treats deceptive display/destination mismatches, prefix-subdomain composition, literal IP hosts, and hostname-like userinfo as structural evidence only.
- WBS 2.4 credential-context findings are internal and unscored. The first credential detector redacts code-like values, ignores structurally identifiable quoted/forwarded content, and treats missing or ambiguous credential language as inconclusive rather than malicious.
- Internal orchestration runs only the parser and implemented sender/URL/credential detectors. Planned attachment, financial and NLP families are represented as `NOT_RUN` when included, with an explicit reason that no check was performed.
- Method C v1 scoring consumes `EngineResult`, preserves accounting, treats risk score as a heuristic index, and is wired to backend `/analyze`.
- For `INCOMPLETE`, `/analyze` returns `risk_score: 0` only as a required-schema placeholder and adds an explicit limitation. The Gmail UI displays the score as unavailable and still shows any positive findings returned by the backend.
- Unexpected route-level analysis errors return a bounded HTTP 500 instead of a successful reassuring assessment.

## Still Open

- Rotation/replacement plan for the demo token if the project becomes more than a single-user prototype.
- Sensitive logging and redaction rules for future detector findings and operational logs.
- Whether Gmail authentication metadata is available with trustworthy provenance.
- Live Gmail verification of the updated CardService real-result presentation.
- Whether to add a public-suffix/registered-domain library for more precise domain relationship checks.
