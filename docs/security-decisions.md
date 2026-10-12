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
- Use ngrok HTTPS forwarding to `127.0.0.1:8000` for the local single-user integration demo.
- Keep startup manual for now instead of adding an all-in-one script that might hide state or expose tokens.

## Resolved By Gmail Integration Spike

- HTTPS tunnel for Apps Script to reach the backend: ngrok was manually verified.
- Manifest scopes for current-message read and external requests were sufficient for the verified Gmail flow.
- Request size limits exist for message body, HTML, headers, and attachment metadata in the backend model.

## Still Open

- Rotation/replacement plan for the demo token if the project becomes more than a single-user prototype.
- Sensitive logging and redaction rules.
- Whether Gmail authentication metadata is available with trustworthy provenance.
- Final scoring policy and detector evidence schema.
