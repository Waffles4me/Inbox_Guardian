# Examples

This folder will hold screenshots of the InboxGuardian card in Gmail, one per scenario below. **No screenshots have been added yet.** Each section describes what a screenshot should show once it is captured.

## Before you capture anything

- Use **synthetic messages only**, sent from your own test account to itself. Never capture real mail.
- Use reserved example domains such as `example.test` in addresses and links. Do not use real brands, people or companies.
- Before saving, check the whole image for private details: your address, account picture, other messages in the inbox list, tunnel URLs, Script Properties and browser tabs. Crop or redact them.
- Save images in [`screenshots/`](screenshots/) as PNG, using the file names suggested below.
- A screenshot shows what one version of the tool did with one message. It is not evidence of detection accuracy.

## Scenarios

The status column says whether the behaviour exists in the code today. Scores are those produced by the current scoring policy, Method C v1 (see [`docs/scoring-policy.md`](../docs/scoring-policy.md)).

Each scenario keeps three kinds of result apart:

- **Expected result:** what the current code should produce for the described message.
- **Automated (synthetic):** confirmed by a unit test on fabricated input. This is not a Gmail observation.
- **Observed in Gmail:** what a tester actually saw in Gmail, with the analysis version where it is known. Results observed on an older backend do not confirm the current version.

| # | Scenario | Code status | Suggested file |
|---|---|---|---|
| 1 | Benign email | Implemented, checked in Gmail | `01-benign.png` |
| 2 | Suspicious sender identity | Implemented | `02-sender-identity.png` |
| 3 | Deceptive link | Implemented | `03-deceptive-link.png` |
| 4 | Credential phishing | Implemented, checked in Gmail | `04-credential-phishing.png` |
| 5 | Several signals at once | Implemented, checked in Gmail | `05-high-risk.png` |
| 6 | Assessment incomplete | Implemented, checked in Gmail | `06-incomplete.png` |
| 7 | Backend unavailable | Implemented, checked in Gmail | `07-backend-unavailable.png` |
| 8 | Attachments listed and name-only assessed | Implemented, checked in Gmail (PDF, older backend) | `08-attachments-name-only.png` |
| 9 | Suspicious attachment | Implemented; executables tested automatically only (Gmail blocks them) | `09-suspicious-attachment.png` |
| 10 | Payment or invoice fraud | Implemented, not yet checked in Gmail | `10-financial-fraud.png` |
| 11 | Maximum risk (100/100) | Implemented, automated test; not yet checked in Gmail | `11-maximum-risk.png` |

### 1. Benign email

- **Message:** a short, ordinary note such as "Lunch is at noon on Thursday in the usual room." No links, no requests.
- **Expected result:** `NO_SIGNIFICANT_SIGNALS`, risk index 0/100, no findings.
- **The screenshot should show:** the neutral verdict wording, which never says "safe", and the **Analysis coverage** section listing the planned checks that did not run.
- **Observed in Gmail:** 0/100, `NO_SIGNIFICANT_SIGNALS` (manual check, 2026-10-13, earlier dashboard). Not yet re-observed on `engine-0.3.0+scoring-0.3.0`.

**INSERT SCREENSHOT HERE**

### 2. Suspicious sender identity

- **Message:** a sender display name that contains a domain different from the real sending address, for example a display name of `accounts.example.test` on a message sent from another domain. This needs a test account whose display name you can set.
- **Expected result:** `SUSPICIOUS`, 20/100, with the finding "Display name claims a different domain".
- **The screenshot should show:** the finding naming both domains, and that sender evidence alone stays below `HIGH_RISK`.
- **Observed in Gmail:** not yet observed.

**INSERT SCREENSHOT HERE**

### 3. Deceptive link

- **Message:** an HTML link whose visible text shows one address while the real destination is another, for example text `https://accounts.example.test` pointing to `https://accounts.example.test.attacker.test/login`.
- **Expected result:** `SUSPICIOUS`, 35/100, with the finding "Destination host embeds the displayed host as a prefix".
- **The screenshot should show:** the displayed host and the real destination side by side in the finding, and that neither is a clickable link in the card.
- **Observed in Gmail:** not yet observed on its own; see scenario 5.

**INSERT SCREENSHOT HERE**

### 4. Credential phishing

- **Message:** urgent wording that asks the reader to reply with their password and a verification code to avoid account suspension.
- **Expected result:** `SUSPICIOUS`, 25/100, with the finding "Message asks for login secrets". Any code-like number in the quoted text appears as `[redacted-code]`.
- **The screenshot should show:** the finding quoting the request it matched, and the recommended action not to send passwords or codes.
- **Observed in Gmail:** 25/100, `SUSPICIOUS` (manual check, 2026-10-13, earlier dashboard).

**INSERT SCREENSHOT HERE**

### 5. Several signals at once

- **Message:** scenarios 3 and 4 combined: the deceptive link plus the credential request.
- **Expected result:** `HIGH_RISK`, 60/100. The link finding is listed first.
- **The screenshot should show:** that `HIGH_RISK` needs evidence from at least two independent checks, not just a high score.
- **Observed in Gmail:** 60/100, `HIGH_RISK`, with the URL finding first (manual check, 2026-10-13, earlier dashboard).

**INSERT SCREENSHOT HERE**

### 6. Assessment incomplete

- **Message:** a forwarded message, where everything below the "Forwarded message" marker was written by someone else.
- **Expected result:** `INCOMPLETE`, shown as "Risk score unavailable" with no number or bar.
- **The screenshot should show:** the coverage note explaining that forwarded content was not assessed, and that the tool abstains instead of showing a low score.
- **Observed in Gmail:** `INCOMPLETE` with no score, for a forwarded message (manual check, 2026-10-13).

**INSERT SCREENSHOT HERE**

### 7. Backend unavailable

- **Setup:** stop the backend, then click **Analyze Email** again.
- **Expected result:** "Analysis unavailable", with no verdict and no score.
- **The screenshot should show:** that a failure is never presented as a result.
- **Observed in Gmail:** "Analysis unavailable" with no verdict or score (manual check, 2026-10-13).

**INSERT SCREENSHOT HERE**

### 8. Attachments listed and name-only assessed

- **Message:** a benign message with one small `.txt` attachment.
- **Expected result:** the same verdict as without the attachment, plus a coverage line saying only attachment names were checked and content was not inspected.
- **The screenshot should show:** that the tool reports the attachment honestly and does not imply file-content scanning.
- **Observed in Gmail:** with an ordinary PDF instead of a `.txt` file, 0/100 on `engine-0.2.0+scoring-0.2.0`. A 30-attachment message listed 30 with 25 detailed entries.

**INSERT SCREENSHOT HERE**

### 9. Suspicious attachment

- **Message:** a benign file renamed to look like a document but ending in an executable or script extension, for example `invoice.pdf.exe`, created locally and never opened.
- **Expected result:** `SUSPICIOUS`, with an attachment finding based on the filename pattern only.
- **The screenshot should show:** that the finding describes the name pattern, never the file contents, and that the card states no malware analysis was performed.
- **Observed in Gmail:** a `.pdf.exe` file could not be sent, because Gmail blocks executable attachments. A harmless `ig-page.html` scored 10/100 (`NO_SIGNIFICANT_SIGNALS`, a weak indicator) on `engine-0.2.0+scoring-0.2.0`. The executable cases are covered by automated tests only.

**INSERT SCREENSHOT HERE**

### 10. Payment or invoice fraud

- **Message:** one sentence that asks for a payment to new bank details and to skip the usual verification, for example "Send the invoice payment to our new bank account today and skip the usual callback verification." Use invented details that cannot belong to anyone.
- **Expected result:** `SUSPICIOUS`, 25/100, with the finding "Financial verification bypass request", from a backend reporting `engine-0.3.0+scoring-0.3.0`.
- **Known limit:** each financial rule matches within one sentence, so the same request split across several sentences may score 0.
- **Automated (synthetic):** the example sentence scores 25/100, `SUSPICIOUS` (`tests/unit/test_maximum_risk_example.py`).
- **Observed in Gmail:** live BEC tests scored 0/100 because the running backend was the older `engine-0.2.0+scoring-0.2.0`, which has no financial-fraud detector. Not yet observed on `engine-0.3.0+scoring-0.3.0`.

**INSERT SCREENSHOT HERE**

### 11. Maximum risk (100/100)

- **Message:** deceptive links, a credential request, gift-card and payment-bypass wording, and a harmless `ig-page.html` attachment, all synthetic.
- **Expected result:** `HIGH_RISK`, 100/100, from a backend reporting `engine-0.3.0+scoring-0.3.0`.
- **Full instructions, Gmail draft and limits:** [maximum-risk.md](maximum-risk.md).
- **Automated (synthetic):** 100/100, `HIGH_RISK`, for both fixture versions (`tests/unit/test_maximum_risk_example.py`).
- **Observed in Gmail:** not yet run with this draft. The live G13 result below is a separate test.

**INSERT SCREENSHOT HERE**

## Live Gmail observation log

These rows record what a tester saw in Gmail. They are separate from the automated synthetic results above, and one does not stand in for the other.

| Test | Observed | Analysis version | Notes |
|---|---|---|---|
| G13 | 25/100 | Not recorded here | Live observation reported by the tester. This is not the maximum-risk fixture: the fixture's 100/100 is an automated result. Add the message, verdict and screenshot here. |

**INSERT SCREENSHOT HERE**
