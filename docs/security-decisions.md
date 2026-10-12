# Security Decisions

## Already Decided

- Analyze only the currently opened Gmail message on demand.
- Do not scan the full inbox in the MVP.
- Do not execute attachments.
- Do not follow links from emails during analysis.
- Do not commit secrets, Gmail tokens, private email content, or production `.env` files.
- Treat the risk score as a heuristic index, not a calibrated probability.

## Open Before Gmail Integration

- HTTPS hosting or secure tunnel for Apps Script to reach the backend.
- Authentication between Apps Script and the backend.
- Exact least-privilege Gmail scopes for current-message access.
- Request size limits for message body, HTML, headers, and attachments metadata.
- Sensitive logging and redaction rules.
- Whether Gmail authentication metadata is available with trustworthy provenance.
