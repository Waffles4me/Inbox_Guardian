# Assignment Checklist

Source reviewed: `UPWIND_HOME_ASSIGNMENT.md`.

This checklist maps the Upwind assignment requirements to planned evidence in this repository. It is a compliance guide, not proof that implementation is complete.

## Objective

- [ ] Build a Gmail Add-on that analyzes an opened email.
  - Evidence target: `addon/` Apps Script source and live Gmail demo.
- [ ] Produce a maliciousness score.
  - Evidence target: backend `/analyze` response contract, scoring docs, tests.
- [ ] Provide a clear, explainable verdict.
  - Evidence target: result card in Gmail, backend findings schema, README screenshots/description.

## Evaluation Criteria

- [ ] Product thinking: explain chosen MVP scope and omitted features.
  - Evidence target: `README.md`, `PROJECT_OBJECTIVE.md`, `WBS.md`.
- [ ] Creativity: show useful signal design beyond generic keyword matching.
  - Evidence target: detector docs/tests once implemented.
- [ ] Architecture and design: explain add-on/backend split.
  - Evidence target: README architecture section and docs.
- [ ] Code quality: readable source, structure, tests, minimal dependencies.
  - Evidence target: backend/add-on source, automated tests.
- [ ] Security awareness: treat email, attachments, and external responses as untrusted.
  - Evidence target: `docs/security-decisions.md`, validation, request limits, no secrets.
- [ ] Communication: professional root README and interview-ready explanation.
  - Evidence target: `README.md` and demo runbook.

## Core Task

- [ ] Gmail Add-on is the primary product and first user interaction.
- [ ] Backend service exists and is called by the add-on.
- [ ] Add-on displays score, verdict, and reasoning.
- [ ] Scope/capabilities/signals are intentionally chosen and justified.

## Technical Guidelines

- [ ] Use Google Workspace APIs for the Gmail Add-on.
- [ ] Backend service is runnable and documented.
- [ ] Solution can be deployed to a real Gmail account and demonstrated live.
- [ ] Security is first-class: untrusted inputs, secrets, and sensitive data are handled deliberately.

## Deliverables

- [ ] Public Git repository link.
- [ ] All add-on source code included.
- [ ] All backend source code included.
- [ ] Professional root `README.md`.
- [ ] README explains what the project does, how to run it, and how to assess decisions.

## Interview Demonstration

- [ ] Bring laptop with solution ready to run.
- [ ] Walk through architecture and reasoning.
- [ ] Demonstrate the add-on against a real Gmail account.
- [ ] Discuss trade-offs, limitations, and what would change with more time.

## Current Status

The assignment has now been reviewed from `UPWIND_HOME_ASSIGNMENT.md`; WBS 0.1 can be considered complete as a requirements audit. Implementation remains incomplete until the specific evidence items above exist and are verified.
