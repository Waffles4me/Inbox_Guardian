# InboxGuardian

InboxGuardian is a Gmail Add-on that analyzes the email you have open, on request, and shows a heuristic risk index, a verdict, the evidence behind it, and what it could not check. A separate Python backend does the analysis; the add-on collects the message and presents the result.

It was built as a time-boxed security-engineering prototype. It is a working prototype for a single test account, not a production mail-security product, and it is not published to the Google Workspace Marketplace.

## Why it is built this way

Three choices shape everything else:

- **Explain every warning.** Each finding names what was observed in the message and why it matters. There is no opaque model score.
- **Say what was not checked.** A message that could not be assessed gets the verdict `INCOMPLETE`, never a low score. A clean-looking result is labeled "No significant suspicious signals found", never "safe".
- **Treat the email as hostile.** Links are never opened, HTML is never rendered, attachments are never touched, and deterministic analysis makes no outbound requests. Optional VirusTotal enrichment is separate, disabled by default, and only sends normalized public domains or public IPs when explicitly enabled and requested.

## How it works

1. Open an email in Gmail and open InboxGuardian in the side panel.
2. Click **Analyze Email**. Nothing is sent anywhere until you do.
3. Read the result card: verdict and risk index, key findings, recommended action, analysis coverage, and additional details.

```text
Gmail (opened message)
   |
Gmail Add-on  - Google Apps Script, CardService
   |   reads subject, From, Reply-To, plain-text body, HTML body
   |   POST /analyze over HTTPS with a shared token header
   v
ngrok HTTPS tunnel  ->  FastAPI backend on 127.0.0.1:8000
                          |
                          +-- request validation and size limits
                          +-- parser: mailboxes, inert HTML text, anchors, URLs
                          +-- detectors: sender identity, URL deception, credential context, attachment metadata, financial fraud
                          +-- Method C v1 scorer: weights, family caps, coverage, verdict
                          +-- optional VirusTotal reputation context, separate from scoring
                          v
                        JSON result (schema 1.0)
   |
Gmail Add-on result card
```

The add-on contains no detection logic. The backend contains no Gmail-specific code and can be tested without Gmail.

### Result card

| Section | Content |
|---|---|
| Assessment | Verdict with a short guidance line, the risk index with a ten-segment bar, and the main (strongest) finding |
| Key findings | Strongest findings first, each with its point contribution, what was observed and why it matters; three visible, the rest behind the expand control |
| Recommended action | One concrete next step, labelled "What to do next" |
| Reputation context | Optional VirusTotal context, only after the separate opt-in action; labelled as external enrichment and separate from Method C findings |
| Analysis coverage | Checks the backend ran, checks it reports as not run, attachment status, and limits specific to this message |
| Additional details | Every remaining limitation and the analysis version, collapsed by default |

Display rules that never change the backend result:

- A `NO_SIGNIFICANT_SIGNALS` verdict with a score above 0 also shows **"Weak indicator detected — Review findings"**, marked as a display interpretation. The backend verdict and score are shown unchanged.
- A finding worth less than 20 points is labelled "Weak on its own", because it cannot reach the `SUSPICIOUS` threshold by itself.
- `INCOMPLETE` and unrecognised verdicts show no score. A low or zero score is never presented as safe.
- The **Checked** list is filtered by the backend's own "Not checked" line, so an older backend without a detector is not shown as having run it.

A backend failure shows "Analysis unavailable" with no verdict or score.

### Screenshot

No screenshot is committed yet. Demonstration scenarios, with expected results and places for screenshots, are in [examples/README.md](examples/README.md). Capture only **synthetic** test messages (never real mail), and check that each image shows no real addresses, account names or tunnel URLs.

## What it detects

Five detector families are implemented. Each emits findings with a stable ID; the scorer assigns the weights.

| Family | What it looks at | Example findings |
|---|---|---|
| Sender identity | From and Reply-To | Reply-To on an unrelated domain; a domain named in the display name that differs from the sending domain |
| URL deception | Links in the HTML and plain-text bodies | Link text shows one host but the link goes to another; the shown host used as a prefix of a different domain; IP-address hosts; hostname-like text before `@` in a URL |
| Credential context | Subject and body wording (English) | Requests for passwords or one-time codes; account verification with a link; account-loss pressure; instructions to bypass security controls |
| Attachment metadata | Attachment names only (Gmail's list, collected on request) | Program or script extensions; a document-like extension in front of one (`.pdf.exe`); hidden text-direction or zero-width characters in a name; HTML, SVG, OneNote and macro-enabled Office files as weak signals |
| Financial fraud / BEC | Subject and body wording (English) | Payment-destination changes with payment instructions; urgent wire-transfer pressure; gift-card code requests; instructions to bypass finance verification; secrecy or channel avoidance around financial requests |

The attachment check reads names, never content: files are not downloaded, opened, scanned or hashed, and a name does not prove what a file contains. MIME types and sizes are not scored. When attachment information is missing or incomplete the check is inconclusive and says so. Attachment metadata checks were verified in Gmail with synthetic attachments (no attachment, an ordinary PDF, an HTML file scoring 10, and a 30-attachment message with 25 detailed entries). A deceptive `.pdf.exe` test could not be sent because Gmail blocks executable attachments.

One more family is approved but **not implemented**: an NLP phishing classifier. Every result states that it was not checked.

## Scoring: Method C v1

The risk index is a number from 0 to 100. **It is a heuristic index, not a probability of phishing**, and it has not been calibrated.

- Each finding has a fixed weight, from 0 (context only) to 35.
- Each family is capped: sender identity 20, URL deception 40, credential context 25, attachment metadata 35, financial fraud 35. The total is clamped to 100.
- Repeated or overlapping evidence is counted once. There is no correlation bonus.
- `HIGH_RISK` needs a score of at least 60 **and** evidence from at least two families, so one family cannot reach it alone.

| Verdict | When | Meaning |
|---|---|---|
| `HIGH_RISK` | Score 60 or more with two independent families | Strong suspicious evidence; not proof of phishing |
| `SUSPICIOUS` | Score 20 to 59, or 60 or more from one family | Suspicious evidence that needs verification |
| `NO_SIGNIFICANT_SIGNALS` | Score below 20 with sufficient coverage | The checks that ran found nothing significant; not a guarantee |
| `INCOMPLETE` | Coverage was insufficient | No verdict could be reached; the score is shown as unavailable |

`INCOMPLETE` is returned when the score is below 20 and any of these holds: the sender could not be parsed; the body has no readable text and no supported link (a subject line alone is not enough); the message forwards another message, whose content is deliberately not attributed to the sender and therefore not assessed; or the body consists only of quoted lines. An implemented detector that fails to run forces `INCOMPLETE` at any score. Findings are still shown in all of these cases.

The full weight table and rationale are in [docs/scoring-policy.md](docs/scoring-policy.md). The detector contract is in [docs/detection-contract.md](docs/detection-contract.md).

## Optional VirusTotal enrichment

VirusTotal v3 enrichment is an optional backend-only provider, not a sixth deterministic detector family and not part of Method C scoring. It is disabled unless all of these are true: `INBOXGUARDIAN_VIRUSTOTAL_ENABLED` is set to `1`/`true`/`yes`, `VIRUSTOTAL_API_KEY` is present in the backend process environment, and the `/analyze` request includes `"enrichments": {"virustotal": true}`.

When enabled and opted in, the provider extracts at most five unique public domains or public IP addresses from supported email links. For hostnames, subdomain labels are stripped before lookup so tenant or internal labels are not shared; for common country-code second-level suffixes such as `co.uk`, the registered-domain approximation is kept. It sends only that normalized base domain or public IP to VirusTotal over HTTPS using the allowlisted v3 report endpoints. It never sends email bodies, subjects, sender/recipient addresses, full URLs, URL paths, query strings, cookies, tokens, attachment metadata or attachment bytes. Private, loopback, local, reserved and internal-looking destinations are excluded. Results appear in `reputation_context` and in the add-on's separate Reputation context section; they do not change `risk_score`, `verdict`, finding weights, family caps or high-risk independence logic.

VirusTotal context is not a safety certificate: missing reports and zero detections are shown as `UNKNOWN`, not clean. API failures, quota exhaustion, missing keys, timeouts and malformed responses fail closed for enrichment while preserving the original email analysis. Public VirusTotal API use is subject to VirusTotal's terms and noncommercial restrictions; review the current terms before enabling it outside local testing.

The normal Gmail **Analyze Email** action never opts into VirusTotal. After a normal result, the card shows a separate **Check public link reputation with VirusTotal** action with disclosure text; only that action sends the per-analysis opt-in.

## Repository layout

```text
addon/                  Gmail Add-on source (Code.js) and manifest (appsscript.json)
backend/app/            FastAPI app, parser, detectors, engine, scorer
tests/unit/             Backend tests and add-on rendering tests
tests/evaluation/       Runner for the synthetic evaluation
tests/fixtures/         Labeled synthetic evaluation cases and the maximum-risk example fixture
examples/               Demonstration scenarios, Gmail drafts and screenshot placeholders
docs/                   Contracts, policy, security decisions, runbooks, evaluation reports
PROJECT_OBJECTIVE.md    Scope, decisions and session handoff
WBS.md                  Work breakdown and evidence per task
```

## Running it

Commands are for Windows PowerShell, where the project was developed. On macOS or Linux use `python3`, `source .venv/bin/activate` and `export` in place of `py`, the activation script and `$env:`.

### Prerequisites

- Python 3.11 or newer (developed on 3.14)
- Node.js, used by the add-on tests and by `clasp`
- [`clasp`](https://developers.google.com/apps-script/guides/clasp) (`npm install -g @google/clasp`), to sync the add-on source
- An HTTPS tunnel such as [ngrok](https://ngrok.com/), because Apps Script cannot call `localhost`
- A Google account you can use for testing

### 1. Backend

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
$env:PYTHONUTF8 = "1"
py -m pip install -e ".[dev]"
```

Choose a long random token and set it in the shell that will run the backend. Do not put it in any file in the repository.

```powershell
$env:INBOXGUARDIAN_API_TOKEN = "<your-token>"
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

The backend reads the token only from the process environment; it does not load `.env` files. `.env.example` shows the variable name. Without a token the `/analyze` endpoint answers 503.

Check it from a second terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/analyze `
  -Headers @{ "X-InboxGuardian-Token" = "<your-token>" } `
  -ContentType "application/json" `
  -Body '{"schema_version":"1.0","email":{"subject":"Demo","from":"demo@example.test","text_body":"Lunch is at noon."}}'
```

The second command should return `verdict: NO_SIGNIFICANT_SIGNALS` with `risk_score: 0`. Without the header it returns 401.

### 2. HTTPS tunnel

```powershell
ngrok http http://127.0.0.1:8000
```

Note the `https://` forwarding address. It changes each time ngrok starts on a free plan. Stop the tunnel when you finish.

### 3. Gmail Add-on

The author's add-on lives in an existing Apps Script project that is not shared. To run your own copy:

1. Enable the Apps Script API at <https://script.google.com/home/usersettings> and run `clasp login`.
2. Create a standalone project at <https://script.google.com> and copy its Script ID from **Project Settings**.
3. In `addon/`, create a file named `.clasp.json` containing `{"scriptId": "<your-script-id>", "rootDir": ""}`. This file is ignored by Git.
4. From `addon/`, run `clasp push` and accept the prompt to overwrite the manifest.
5. In the Apps Script editor, open **Project Settings > Script Properties** and add:

   | Property | Value |
   |---|---|
   | `INBOXGUARDIAN_BACKEND_URL` | The `https://` tunnel address, without `/analyze` |
   | `INBOXGUARDIAN_API_TOKEN` | The same token the backend was started with |

6. Choose **Deploy > Test deployments** and install the add-on for your own account.
7. Open Gmail with the same account, open a message, open InboxGuardian in the side panel, approve the permission prompt, and click **Analyze Email**.

Steps 2 to 4 describe a fresh project and were not exercised from a clean machine during development; the author's project was connected once and then updated with `clasp push`. Day-to-day restart steps are in [docs/development-startup.md](docs/development-startup.md), and the integration checks in [docs/gmail-integration-runbook.md](docs/gmail-integration-runbook.md).

The add-on requests three scopes: run as a Gmail add-on, read the currently opened message, and make external requests. It cannot read the rest of the mailbox.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Current result on the V1 release candidate (`feature/finish`): **664 passed, 1 warning** (a deprecation notice from the test client). Node.js must be on the path, because the add-on tests run `addon/Code.js` in Node.

- Backend tests cover the parser, each detector with triggering and benign cases, the engine, the scorer, and the API including authentication and error handling.
- Add-on tests run the card-building code against a recording stand-in for CardService and check structure, escaping and the absence of links. They do not test how Gmail draws the card.

## Evaluation

The repository includes 30 labeled synthetic messages: 15 benign and 15 suspicious, across six groups. Labels were fixed before any case was run.

```powershell
.\.venv\Scripts\python.exe tests\evaluation\run_evaluation.py --label "my run" --output docs\evaluation-results-my-run.md
```

| | Original baseline | Current code |
|---|---|---|
| Suspicious messages flagged | 8 of 15 | 8 of 15 |
| Benign messages wrongly flagged | 2 of 15 | 1 of 15 |
| Abstentions (`INCOMPLETE`) | 0 | 0 |

**These numbers are not detection accuracy.** The set is small, synthetic, and was written by someone who had read the detector rules. One false positive was fixed in response to it, so the current figures are not an independent measurement. The value is in the per-case failures, which are analyzed in [docs/evaluation-baseline.md](docs/evaluation-baseline.md). The original run is kept in [docs/evaluation-results.md](docs/evaluation-results.md) and the latest, with all five detector families, in [docs/evaluation-results-bec-detector.md](docs/evaluation-results-bec-detector.md).

### Manual verification in Gmail

The following were checked by hand in a real Gmail account, on the desktop web client, with synthetic test messages: a benign message (0), credential phishing (25, `SUSPICIOUS`), multi-signal phishing (60, `HIGH_RISK`, with the URL finding first), an empty-body message and a forwarded message (both `INCOMPLETE` with no score), the expandable sections, icons, colors and score bar, that hostnames in findings are not clickable, and the "Analysis unavailable" state with the backend stopped.

Not checked by hand: Gmail's dark theme, the mobile app, screen readers, and the fallback shown if a result cannot be displayed.

## Security

**Untrusted input**

- HTML is parsed as inert text with Python's standard library. Scripts and styles are ignored; nothing is rendered or executed.
- Links are parsed, never fetched, expanded or resolved by deterministic analysis. Optional VirusTotal enrichment is the only backend outbound lookup path, and it is disabled unless separately enabled and requested.
- Only attachment names, declared types and sizes are collected, and only names are checked. Attachment content is never read, downloaded or opened.
- Inputs are bounded: 50,000 characters per body, 50 URLs per source, 2,048 characters per URL.
- The add-on escapes every backend and message string before display and creates no clickable links or remote images.

**Authentication and secrets**

- `/analyze` requires a shared token in the `X-InboxGuardian-Token` header, compared in constant time. A missing or wrong token gets 401.
- The token lives in the backend's environment and in Apps Script Script Properties. `.gitignore` excludes `.env` files, `.clasp.json`, key files and `.eml` files.

**Privacy**

- Only the opened message is read, and only when the user clicks the button.
- The backend stores nothing and does not log message content.
- Query strings, URL fragments and numeric codes are removed from the text shown in findings.
- Optional VirusTotal enrichment, when enabled and opted in per request, sends only normalized base public domains or public IP addresses from links. It does not send bodies, subjects, recipients, full URLs, URL paths, query strings, cookies, tokens, subdomain labels or attachment data.

**Known gaps in this prototype**

- One static shared token; no per-user identity, rotation or rate limiting.
- While the tunnel is running, `/health`, `/docs` and `/openapi.json` are reachable without a token.
- No overall request-size cap beyond the per-field limits.
- Bodies longer than 50,000 characters are truncated without notice.
- The add-on cannot tell an empty body from one it failed to retrieve; both yield `INCOMPLETE`.

Decisions are recorded in [docs/security-decisions.md](docs/security-decisions.md).

## Known limitations

- **Keyword rules are brittle.** Paraphrases such as "login details" or "forward me the code" are missed, and some benign sentences still match, for example "you can turn off these security notifications".
- **Link text must contain `http://` or `https://`** to be compared with its destination. A bare domain in link text is not checked.
- **Legitimate tracking redirects are flagged** when the link text shows a URL.
- **No registered-domain logic.** Two-level suffixes such as `.co.il` defeat sender comparison, and sibling subdomains are treated as different hosts.
- **Brand impersonation without a domain** in the display name is not detected, and lookalike domains are not recognized.
- **Forwarded messages are not assessed.** They return `INCOMPLETE` unless other evidence is present. HTML is flattened, so a request quoted inside an HTML blockquote can still be attributed to the sender.
- **English only.** No image or QR-code analysis, and no attachment content analysis.
- **A single weak attachment finding does not change the verdict.** An HTML, SVG, OneNote or macro-enabled file alone scores 10, below the `SUSPICIOUS` threshold, so the verdict stays `NO_SIGNIFICANT_SIGNALS` while the finding is listed.
- **BEC rules match within one sentence.** Each financial rule needs its indicators in the same sentence, so a request split across sentences (for example "buy gift cards" followed by "send me the codes") is missed. Sentences containing "do not / don't" before a payment or send verb are skipped as warnings, which also drops instructions such as "do not call to verify". These are known false negatives; the detector logic is frozen for this release.
- **BEC wording has no history.** The financial detector cannot know whether a bank-detail change is expected, whether a vendor is legitimate, or whether an approval happened outside the message. It only flags suspicious request wording and tells the user to verify through normal finance procedures.
- **VirusTotal enrichment is context, not proof.** It is off by default, rate-limited, limited to public domains/IPs from links, and does not submit URLs or files. A missing report or zero detections does not mean a destination is safe, and a suspicious reputation result does not prove the email is malicious.

## Open decision

[docs/scoring-policy.md](docs/scoring-policy.md) says a clean verdict requires the sender check and at least one body or link check to finish without triggering. The code does not consult detector statuses for that decision: a message with usable content whose URL and credential checks are both inconclusive still gets `NO_SIGNIFICANT_SIGNALS`. This mismatch is documented and deliberately unresolved; neither the policy nor the code has been changed to hide it.

VirusTotal enrichment is exposed in Gmail only through the separate **Check public link reputation with VirusTotal** action. The normal **Analyze Email** button remains local-only for deterministic analysis.

## Demo script (3 to 5 minutes)

Before starting: backend running on the latest code, tunnel up, Script Properties pointing at the current tunnel address, and four synthetic test messages in the inbox.

1. **Benign message.** Click Analyze Email. Point out the verdict wording, the 0/100 index, and the "Not checked" line under Analysis coverage.
2. **Credential phishing.** `SUSPICIOUS`, 25. Open a finding and show that it quotes the request it matched.
3. **Deceptive link with a credential request.** `HIGH_RISK`, 60. The URL finding is first; show the displayed host against the real destination, and that two families were needed for this verdict.
4. **Forwarded message.** `INCOMPLETE`, "Risk score unavailable". Explain why the tool abstains.
5. **Stop the backend and click Analyze again.** "Analysis unavailable", with no verdict.
6. **Close with limits.** Open Additional details, then name two things the tool misses and what would come next.

## Roadmap

In intended order. Attachment metadata checks are implemented and verified in Gmail. Financial-fraud wording checks and the optional VirusTotal enrichment are implemented and covered by automated tests, but have not yet been verified against a live backend running this version:

1. An NLP phishing classifier, evaluated separately before it influences any score.
2. Method C v2 scoring, to be reviewed separately; candidates include very strong single-family evidence and tracking-redirect weighting.
3. Operational review before enabling VirusTotal in any deployed backend: confirm terms, key handling, quota expectations and user-facing consent text.

## Further reading

- [PROJECT_OBJECTIVE.md](PROJECT_OBJECTIVE.md): scope, decisions and development history
- [WBS.md](WBS.md): tasks with evidence for each
- [docs/detection-contract.md](docs/detection-contract.md) and [docs/scoring-policy.md](docs/scoring-policy.md)
- [docs/evaluation-baseline.md](docs/evaluation-baseline.md)
