# InboxGuardian - Attachment Collection Feasibility (WBS 2.5A) and Stage 1

> **Date:** 2026-10-14
> **Status:** Feasibility probe completed by the user in real Gmail; Stage 1 collection implemented on branch `wbs-2.5-stage1` with Method C v1 scoring, not committed, not synchronized to the Apps Script project.
> **Scope:** Attachment **metadata** only (name, declared content type, size). No attachment content is read, and no attachment threat check exists yet.

## 1. How the probe was run

A temporary, separate Apps Script project ("IG Attachment Probe") was installed as a test deployment. It declared only two of the add-on's existing scopes, `gmail.addons.execute` and `gmail.addons.current.message.readonly`, had no network access, logged nothing, and read attachments only after a button press on messages whose subject began with `[IG-PROBE]`. It read `getName()`, `getContentType()` and `getSize()` and nothing else. The InboxGuardian Apps Script project and repository were not changed for the probe. All test messages were synthetic and sent from the user's account to itself.

## 2. Results

Results are as reported by the user. Exact MIME types, counts beyond those stated, and timings were not provided in the handoff and are recorded as **unverified**, not estimated.

| Test | Setup | Reported result | What it establishes |
|---|---|---|---|
| T00 | Subject without the probe marker | PASS - rejected | The subject guard refused the message before any attachment call. |
| T01 | No attachment | PASS - 0 regular, 0 inline | `getAttachments()` runs under the current-message scope and an attachment-free message is observable as zero. |
| T02 | One `.txt` attachment | PASS - 1 regular, metadata shown | **The existing scope is sufficient** for `getAttachments()`, `getName()`, `getContentType()` and `getSize()`: no authorization error and no new consent. Exact type and size values: unverified. |
| T03 | Inline image plus one `.txt` | PASS - 1 regular, at least 1 inline | `includeInlineImages: false` keeps inline images out of the regular list. The exact inline count is unverified. |
| T04 | `.html` and `.svg` | PASS - 2 attachments, HTML and SVG metadata | Gmail delivered both types and exposed their metadata. Declared MIME strings: unverified. |
| T05 | Bidi-override name and Hebrew name | PASS - bidi-control flag and Hebrew code points | Gmail returns a U+202E direction override inside a filename **unchanged**, and decodes Hebrew names to the expected code points. |
| T06 | 200-code-point name | PASS - 200 code points | A 200-code-point name arrives intact. Names over 255 code points could not be produced on Windows and are covered by automated tests only. |
| T07 | One 20 MB attachment | PASS - size and timing observed | Collection completed for a 20 MB attachment. Timing values are unverified, so whether `getAttachments()` loads content at call time remains **unknown**. |
| T08 | 30 attachments | PASS - 30 regular, timing observed | More than 25 attachments occur in practice, so the `TRUNCATED` path is real. Timing values are unverified. |
| T09 | T02 forwarded as an attachment (`.eml`) | **BLOCKED** | How Gmail represents a forwarded message attachment, and whether attachments inside it are listed, was **not established**. |
| T10 | Drive file inserted as a link | PASS - behaviour observed | Reported as passing against the expected result (Drive links are not regular attachments); the observed count was not provided. |

During T04-T10 the separately installed InboxGuardian dashboard generally showed `NO_SIGNIFICANT_SIGNALS` 0/100. That dashboard did not collect attachments at the time, so this says nothing about attachment risk or safety. In T09 it showed `INCOMPLETE`, which is its existing forwarded-content behaviour and is not evidence about the probe.

## 3. Conclusions

1. **No new OAuth scope is needed.** Metadata collection works with `gmail.addons.current.message.readonly` and the event access token.
2. **Inline images and regular attachments can be separated** by the `getAttachments` options.
3. **Filenames carry hostile characters through unchanged**, so names must be treated as untrusted text and flagged, never rendered raw.
4. **Attachment counts above 25 are realistic**; truncation must be explicit.
5. **Open:** forwarded `.eml` attachments (T09), whether large attachments are loaded at call time (T07), and the real time taken for many attachments (T08). The 5-second budget stays provisional.

## 4. Changes to the Stage 1 design justified by the tests and review

- **Clipped names are kept as separate segments.** The backend splits a clipped name at `name_clip.at` into head and tail and never joins them as if they were adjacent in the original. An out-of-range clip position makes the name unavailable rather than guessing a split. `removed_whitespace_only` is kept as metadata only.
- **Character classes are defined as numeric code point ranges** in both `addon/Code.js` and `backend/app/parsing.py`, so neither file contains invisible or direction-control characters itself; a test compares the two range tables.
- **T09 is a documented coverage gap, not a blocker.** Whatever Gmail returns for a forwarded message is reported like any other attachment. Attachments nested inside a forwarded message may not be listed.
- **T10** is reflected in the `NONE` wording: inline images and linked Drive files are not counted.
- **Collection is fail-safe.** An unexpected error anywhere in attachment collection is reported as `UNAVAILABLE` with reason `unexpected_error` and the analysis continues; it is never reported as `NONE`.
- **Validation errors are sanitized.** A rejected request no longer echoes its values (for example an oversized attachment name) in the 422 response.
- No limit changed: 25 transmitted, 100 names examined, 5-second provisional budget, names clipped above 255 code points (64 head, 191 tail).

## 5. Stage 1 contract (implemented locally)

The request stays at `schema_version` `1.0`. `email.attachment_collection` is optional; the existing `attachment_metadata` list keeps its shape and gains optional per-item fields (`name_clip`, `content_type_clipped`, `unavailable_fields`). Older backends ignore all of them.

| Effective state | Meaning | Reported limitation (counts only, never names) |
|---|---|---|
| `COLLECTED` | Every regular attachment's metadata was received | "Attachments: Gmail listed N; they were not assessed because attachment checks are not implemented yet." |
| `NONE` | Gmail listed no regular attachment | "Attachments: Gmail listed none. Inline images and linked Drive files are not counted." |
| `TRUNCATED` | Items omitted (count, read or time limit) or fields clipped or unavailable | "Attachments: Gmail listed N and details for M were received; they were not assessed ..." |
| `UNAVAILABLE` | Collection failed (`collection_error` for a Gmail call, `unexpected_error` for any other failure) | "Attachments: attachment information could not be collected from Gmail, so attachments were not assessed." |
| `UNKNOWN` | Field absent (V1 client), or contradictory or unrecognised metadata | None for a V1 client; "the attachment information received was inconsistent ..." otherwise, plus a parser issue |

The attachment detector remains planned and `NOT_RUN`; the "Not checked: attachments, ..." line is still returned in every state. Collection state never changes a score, verdict, finding or coverage reason, and an empty attachment list is never treated as evidence that a message is harmless.

> **Superseded by WBS 2.5 Stage 2 (branch `wbs-2.5-stage2`):** the table and paragraph above describe Stage 1. Stage 2 runs the attachment detector on this collection state. `COLLECTED` and `TRUNCATED` lines now say that only attachment names were checked and attachment content was not inspected; a V1 client's missing attachment information is named in the "Not checked" line instead of a separate line; other states keep their Stage 1 wording. Names with listed extensions can now change the score. See section 8 of `docs/detection-contract.md`.

## 6. Verification (2026-10-14, branch `wbs-2.5-stage1`, automated only)

Everything below was checked by automated tests and scripts on the branch. **Stage 1 has not been run in the real InboxGuardian add-on**: the source is not synchronized to the Apps Script project, and no Gmail check of the integrated add-on has been made.

| Check | Result |
|---|---|
| Full suite (`pytest -q`) | 430 passed, 1 warning (the existing Starlette/httpx deprecation): the 283 V1 tests and 147 new Stage 1 tests |
| `node --check addon/Code.js` | Passed |
| Frozen 30-case evaluation | Identical to `docs/evaluation-results-post-backend-cleanup.md` in every row and metric (TP 8, FP 1, TN 14, FN 7, 0 abstentions); the fixture SHA-256 of the LF-normalised file is unchanged |
| Legacy requests (no `attachment_collection`) | Responses byte-identical to the V1.0.0 backend for all 30 fixtures |
| New add-on payloads sent to the V1.0.0 backend | 90 requests (30 fixtures x 3 collection shapes, including a 200-attachment clipped worst case) returned 200 with the same response as the legacy request |
| Scores and verdicts | Unchanged for every fixture under every collection state; the attachment detector stays `NOT_RUN` |
| Scopes and manifest | `addon/appsscript.json` unchanged; scorer, engine, detectors, fixtures and evaluation runner unchanged |
| Attachment content | No content method is called (source test plus a fake attachment that fails on any other member) |
| When collection runs | Only through Analyze Email, never on message open |
| Unexpected collection failure | Reported as `UNAVAILABLE` with reason `unexpected_error`, never `NONE`; the analysis and the result or error card still complete; nothing about the failure is logged or sent |
| Validation errors | 422 bodies carry only error locations and types; rejected values, request-derived key names and parser messages are never returned or logged. Unauthenticated invalid requests get 401 (503 if no token is configured) |
| Privacy scan | Only reserved `.test` names in tests; no filenames in responses or logs |

**Not verified and still open:** Gmail behaviour of the integrated add-on; forwarded `.eml` attachments (T09); whether large attachments are loaded at call time (T07); real timings for many attachments (T08); dark theme and mobile rendering of the new coverage line. A body that cannot be decoded as UTF-8 is still rejected by FastAPI itself with a fixed 400 "There was an error parsing the body" before the token check; it reveals nothing that was sent.

## 7. Recommended next steps

1. Review Stage 1.
2. If approved, synchronize `addon/Code.js` with a separately approved `clasp push` and repeat T01, T02, T03 and T08 through the real add-on, checking the attachment line under Analysis coverage.
3. Resolve T09 with one more synthetic forwarded-as-attachment test before any rule depends on nested attachments.
4. Only then design the Stage 2 detector rules and their weights, which need separate approval.
