# requirements checklist

Source reviewed: the private requirements brief (kept local, never committed).

This checklist maps the core requirements to evidence in this repository. A checked box means the evidence exists and was verified as described; it is not a claim about how a reviewer will judge it. Status as of 2026-10-13.

## Objective

- [x] Build a Gmail Add-on that analyzes an opened email.
  - Evidence: `addon/Code.js`, `addon/appsscript.json`; manually verified in a real Gmail account (`WBS.md` 2.13, 3.6).
- [x] Produce a maliciousness score.
  - Evidence: backend `/analyze` returns a 0-100 heuristic risk index; `docs/scoring-policy.md`; `tests/unit/test_scoring.py`.
- [x] Provide a clear, explainable verdict.
  - Evidence: four verdicts with evidence-backed findings and stated limitations; result dashboard in Gmail; `README.md`.

## Evaluation Criteria

Evidence that exists for each criterion. The judgement itself belongs to the reviewer.

- [x] Product thinking: explain chosen MVP scope and omitted features.
  - Evidence: `README.md` (design choices, limitations, roadmap), `PROJECT_OBJECTIVE.md`.
- [x] Creativity: show useful signal design beyond generic keyword matching.
  - Evidence: structural URL deception rules, coverage-aware `INCOMPLETE` verdict, per-family caps and independence requirement; `docs/detection-contract.md`.
- [x] Architecture and design: explain add-on/backend split.
  - Evidence: `README.md` architecture section; `docs/detection-contract.md`.
- [x] Code quality: readable source, structure, tests, minimal dependencies.
  - Evidence: `backend/app/`, `addon/Code.js`, 283 automated tests, three runtime dependencies.
- [x] Security awareness: treat email, attachments, and external responses as untrusted.
  - Evidence: `README.md` security section, `docs/security-decisions.md`, input limits, inert parsing, escaped output, no secrets in Git.
- [ ] Communication: professional root README and interview-ready explanation.
  - Evidence: `README.md` is written. Open: a sanitized screenshot and the demonstration rehearsal.

## Core Task

- [x] Gmail Add-on is the primary product and first user interaction.
- [x] Backend service exists and is called by the add-on.
- [x] Add-on displays score, verdict, and reasoning.
- [x] Scope/capabilities/signals are intentionally chosen and justified.

## Technical Guidelines

- [x] Use Google Workspace APIs for the Gmail Add-on.
  - Evidence: Apps Script CardService, `GmailApp` current-message access, `UrlFetchApp`.
- [x] Backend service is runnable and documented.
  - Evidence: `README.md` setup section; commands checked against a local backend.
- [x] Solution can be deployed to a real Gmail account and demonstrated live.
  - Evidence: installed as an unpublished test deployment in a real account and manually verified. The live interview demonstration itself is still to come.
- [x] Security is first-class: untrusted inputs, secrets, and sensitive data are handled deliberately.

## Deliverables

- [ ] Public Git repository link.
  - The repository exists, but the current local commits have not been pushed. Open until synchronized.
- [x] All add-on source code included.
- [x] All backend source code included.
- [ ] Professional root `README.md`.
  - Written; open until reviewed, committed and published with the repository.
- [x] README explains what the project does, how to run it, and how to assess decisions.

## Interview Demonstration

- [ ] Bring laptop with solution ready to run.
- [ ] Walk through architecture and reasoning.
- [ ] Demonstrate the add-on against a real Gmail account.
- [ ] Discuss trade-offs, limitations, and what would change with more time.

A 3 to 5 minute demo script is in `README.md`. It has not been rehearsed yet.

## Current Status

Implementation and automated tests exist for five detector families on `feature/bec-detector`; manual Gmail verification exists for the first three detector families and the result dashboard on the earlier baseline. Attachment metadata and financial-fraud wording still need real Gmail verification before being claimed in the live add-on. Remaining before submission: add a sanitized screenshot, run the publication review, push the repository, and rehearse the demonstration.
