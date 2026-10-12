# Security Decisions

## Already Decided

- Analyze only the currently opened Gmail message on demand.
- Do not scan the full inbox in the MVP.
- Do not execute attachments.
- Do not follow links from emails during analysis.
- Do not commit secrets, Gmail tokens, private email content, or production `.env` files.
- Treat the risk score as a heuristic index, not a calibrated probability.
- Use a shared demo token in the `X-InboxGuardian-Token` header for the first single-user Apps Script-to-backend prototype.
- Store the backend URL and demo token outside Git: backend environment variables locally, Apps Script Properties remotely.
- The current backend response is `DEMO / NOT ANALYZED` and must not be presented as a real security assessment.

## Open Before Gmail Integration

- HTTPS hosting or secure tunnel for Apps Script to reach the backend.
- Rotation/replacement plan for the demo token if the project becomes more than a single-user prototype.
- Live verification that the local manifest scopes are sufficient and no broader Gmail scopes are needed.
- Request size limits for message body, HTML, headers, and attachments metadata.
- Sensitive logging and redaction rules.
- Whether Gmail authentication metadata is available with trustworthy provenance.
