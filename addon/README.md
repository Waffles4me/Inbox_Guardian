# Add-on Workspace

This folder is the source of the InboxGuardian Gmail Add-on.

- `Code.js` reads the opened message, calls the backend `/analyze` endpoint with a token from Script Properties, and builds the CardService result dashboard. It contains no detection logic.
- `appsscript.json` is the manifest: a Gmail contextual trigger and three scopes (run as an add-on, read the current message, make external requests).

The folder is synchronized to an existing Apps Script project with `clasp push`. Setup and the manual checks are described in the root `README.md` and in `docs/gmail-integration-runbook.md`.

Do not commit `.clasp.json` or Google authentication files.
