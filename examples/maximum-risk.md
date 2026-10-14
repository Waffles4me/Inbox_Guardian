# Maximum-risk demonstration (100/100)

This example shows the highest score Method C v1 can produce: **100/100, `HIGH_RISK`**. It uses only fabricated content: reserved `.test` / `.example` domains and the documentation IP range `192.0.2.0/24`, so no link works and no real organization is named.

A score of 100 is the top of a heuristic risk index, not a certainty that the message is malicious.

## Why 100 is attainable

Method C adds each detector family's points after applying that family's cap, then clamps the total to 100. There is no correlation bonus.

| Family | Cap | Strongest findings used |
|---|---:|---|
| Sender identity | 20 | Display name claims a different domain (20) |
| URL deception | 40 | Destination embeds the displayed host (35), second mismatched link (30), IP-address host (5) |
| Credential context | 25 | Asks for password and code (20), account-suspension threat (10) |
| Attachment metadata | 35 | `invoice.pdf.exe` double extension (30), `setup.msi` executable (25) |
| Financial fraud / BEC | 35 | Gift-card code request (30), verification bypass (25) |
| **Sum of caps** | **155** | Clamped to **100** |

`HIGH_RISK` also requires at least two independent evidence families. The full fixture has five; the Gmail version has three.

Detector rules, weights, caps and thresholds were not changed for this example. The exact inputs are in [`tests/fixtures/examples/maximum_risk.json`](../tests/fixtures/examples/maximum_risk.json) and are checked by [`tests/unit/test_maximum_risk_example.py`](../tests/unit/test_maximum_risk_example.py).

## Two versions

| Version | Where it runs | Families scored (points after caps) | Expected |
|---|---|---|---|
| `five_family_maximum` | Automated test only | 20 + 40 + 25 + 35 + 35 = 155 | 100, `HIGH_RISK`, 5 independent families |
| `gmail_reproducible` | Automated test, and Gmail using the draft below | 0 + 40 + 25 + 10 + 35 = 110 | 100, `HIGH_RISK`, 3 independent families |

Without the HTML attachment, the Gmail version still totals exactly 100 (40 + 25 + 35), with no margin.

### What an email sent to yourself cannot reproduce

- **Sender identity (20 points).** This needs a display name that claims another domain, such as `accounts.example.test <notice@attacker.test>`. A message you send to yourself carries your own name and address. Changing your Gmail display name would work but alters your account, so it is not part of this test.
- **Reply-To mismatch (5 points).** This needs a different Reply-To address, which Gmail only allows through account settings.
- **Executable attachments (up to 35 points).** Gmail blocks `.exe`, `.msi` and similar files, so `invoice.pdf.exe` cannot be sent. The draft uses a harmless `ig-page.html` file instead, which scores 10 as active content.

## Gmail draft

1. Create a local text file named **`ig-page.html`** containing only `<p>InboxGuardian synthetic test page</p>`. Never use a real HTML page.
2. Compose a new message **to yourself**.
3. **Subject:** `Urgent account verification and payment`
4. **Body:** paste the four paragraphs below exactly, keeping each sentence intact. Each BEC rule only matches within a single sentence.

   ```text
   Urgent: your account will be suspended within 12 hours. Reply with your password and the six-digit verification code to keep access.

   Buy five gift cards today and email me the redemption codes; keep this confidential.

   Send the invoice payment to our new bank account today and skip the usual callback verification.

   Review the statement at http://192.0.2.10/statement
   ```

5. Add two links with Gmail's **Insert link** (Ctrl+K). The *Text to display* must differ from the *Web address*:

   | Text to display | Web address |
   |---|---|
   | `https://accounts.example.test` | `https://accounts.example.test.attacker.test/login` |
   | `https://payments.example.test/portal` | `https://login.attacker.test/form` |

6. Attach `ig-page.html`, send the message, open it, and click **Analyze Email**.

The backend must report analysis version `engine-0.3.0+scoring-0.3.0` under **Additional details**. An older backend has no financial-fraud detector and would score lower.

### Expected result

- Verdict **High risk — Treat with caution**, risk index **100/100**, full bar.
- Key findings led by "Destination host embeds the displayed host", followed by credential, financial and attachment findings.
- The attachment coverage line says only names were checked.
- No VirusTotal section unless the separate reputation action is used.

### Observed result

*Not yet run in Gmail.* Record the verdict, score, analysis version and any difference from the expected result here. Do not copy the expected values.

The live G13 test (observed 25/100) is a separate message and is not an observation of this draft. It is recorded in the [live observation log](README.md#live-gmail-observation-log).

---

**INSERT SCREENSHOT HERE**

Suggested file: `screenshots/11-maximum-risk.png` (relative to this folder). Before saving, crop or redact your address, account picture, the inbox list and any tunnel URL.

---
