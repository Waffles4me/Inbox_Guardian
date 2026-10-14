"""Run the synthetic attachment-metadata cases through the parser, engine and Method C scorer.

Usage (from the repository root):

    .\\.venv\\Scripts\\python.exe tests\\evaluation\\run_attachment_evaluation.py
    .\\.venv\\Scripts\\python.exe tests\\evaluation\\run_attachment_evaluation.py --output docs\\evaluation-results-attachments.md

The cases in ``tests/fixtures/evaluation/attachment_cases.json`` are separate from the frozen 30-case set in
``cases.json``, which ``run_evaluation.py`` still evaluates unchanged. Results are reported twice: once by overall
verdict, as in the frozen evaluation, and once by the attachment detector's own status. Neither is a real-world
accuracy measure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_evaluation import (  # noqa: E402
    ENGINE_VERSION,
    LABELS,
    PREDICTED_SUSPICIOUS,
    REPO_ROOT,
    SCORING_VERSION,
    STATUS_CODES,
    ratio,
)
from backend.app.engine import analyze_with_detectors  # noqa: E402
from backend.app.models import EmailPayload  # noqa: E402
from backend.app.scoring import score_engine_result  # noqa: E402

CASES_PATH = REPO_ROOT / "tests" / "fixtures" / "evaluation" / "attachment_cases.json"
REQUIRED_FIELDS = ("id", "group", "label", "description", "rationale", "email", "expected")
FAMILIES = ("sender_identity", "url_deception", "credential_context", "attachment_metadata")


def load_cases() -> tuple[list[dict], str]:
    raw = CASES_PATH.read_bytes()
    cases = json.loads(raw)["cases"]
    return cases, hashlib.sha256(raw).hexdigest()


def validate_cases(cases: list[dict]) -> None:
    seen: set[str] = set()
    for case in cases:
        missing = [field for field in REQUIRED_FIELDS if field not in case]
        if missing:
            raise ValueError(f"{case.get('id', '?')}: missing fields {missing}")
        if case["id"] in seen:
            raise ValueError(f"duplicate case id {case['id']}")
        seen.add(case["id"])
        if case["label"] not in LABELS:
            raise ValueError(f"{case['id']}: unknown label {case['label']}")


def evaluate_case(case: dict) -> dict:
    engine_result = analyze_with_detectors(EmailPayload.model_validate(case["email"]))
    scoring = score_engine_result(engine_result)
    statuses = {result.detector_id: result.status.value for result in engine_result.detector_results}
    attachment = next(result for result in engine_result.detector_results if result.detector_id == "attachment_metadata")
    family = next(family for family in scoring.family_scores if family.detector_id == "attachment_metadata")
    verdict = scoring.verdict
    suspicious = case["label"] == "SUSPICIOUS"

    if verdict == "INCOMPLETE":
        outcome = "ABSTAIN"
    elif verdict in PREDICTED_SUSPICIOUS:
        outcome = "TP" if suspicious else "FP"
    else:
        outcome = "FN" if suspicious else "TN"

    if attachment.status.value in {"INCONCLUSIVE", "NOT_RUN"}:
        detector_outcome = "ABSTAIN"
    elif attachment.status.value == "TRIGGERED":
        detector_outcome = "TP" if suspicious else "FP"
    else:
        detector_outcome = "FN" if suspicious else "TN"

    return {
        "id": case["id"],
        "group": case["group"],
        "label": case["label"],
        "description": case["description"],
        "verdict": verdict,
        "score": None if verdict == "INCOMPLETE" else scoring.risk_score,
        "statuses": {detector_id: statuses.get(detector_id, "MISSING") for detector_id in FAMILIES},
        "attachment_status": attachment.status.value,
        "attachment_findings": [finding.id for finding in attachment.findings],
        "attachment_points": family.capped_points,
        "credited": [
            (item.finding.id, item.effective_contribution)
            for item in scoring.scored_findings
            if item.effective_contribution
        ],
        "independent_families": list(scoring.independent_evidence_families),
        "outcome": outcome,
        "detector_outcome": detector_outcome,
    }


def compute_metrics(rows: list[dict], key: str) -> dict:
    counts = {name: sum(1 for row in rows if row[key] == name) for name in ("TP", "FP", "TN", "FN", "ABSTAIN")}
    return {
        "counts": counts,
        "precision": ratio(counts["TP"], counts["TP"] + counts["FP"]),
        "recall": ratio(counts["TP"], counts["TP"] + counts["FN"]),
        "false_positive_rate": ratio(counts["FP"], counts["FP"] + counts["TN"]),
        "coverage": ratio(len(rows) - counts["ABSTAIN"], len(rows)),
    }


def _metrics_table(title: str, explanation: str, metrics: dict) -> list[str]:
    counts = metrics["counts"]
    return [
        f"## {title}",
        "",
        explanation,
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| True positives | {counts['TP']} |",
        f"| False positives | {counts['FP']} |",
        f"| True negatives | {counts['TN']} |",
        f"| False negatives | {counts['FN']} |",
        f"| Abstentions | {counts['ABSTAIN']} |",
        f"| Precision (TP / (TP + FP)) | {metrics['precision']} |",
        f"| Recall (TP / (TP + FN), abstentions excluded) | {metrics['recall']} |",
        f"| False-positive rate (FP / (FP + TN)) | {metrics['false_positive_rate']} |",
        f"| Assessed-case rate | {metrics['coverage']} |",
        "",
    ]


def render_report(rows: list[dict], fixture_hash: str, label: str | None = None) -> str:
    lines = [
        "# InboxGuardian - Attachment Metadata Synthetic Evaluation",
        "",
        "Generated by `tests/evaluation/run_attachment_evaluation.py`. Do not edit by hand; rerun the script instead.",
        "",
        *([f"- Run: {label}"] if label else []),
        f"- Fixture: `tests/fixtures/evaluation/attachment_cases.json` (SHA-256 `{fixture_hash}`)",
        f"- Engine / scorer: `{ENGINE_VERSION}` / `{SCORING_VERSION}`",
        f"- Cases: {len(rows)} synthetic messages written to exercise the rules. They are not a real-world benchmark, "
        "and these figures say nothing about accuracy on real mail.",
        "",
    ]
    lines += _metrics_table(
        "A. Overall verdict",
        "`HIGH_RISK` and `SUSPICIOUS` count as predicted suspicious, `NO_SIGNIFICANT_SIGNALS` as predicted benign, "
        "`INCOMPLETE` as an abstention.",
        compute_metrics(rows, "outcome"),
    )
    lines += _metrics_table(
        "B. Attachment detector status",
        "`TRIGGERED` counts as predicted suspicious, `NOT_TRIGGERED` as predicted benign, `INCONCLUSIVE` or "
        "`NOT_RUN` as an abstention. A weak finding (10 points) is a detector positive even when the verdict is not.",
        compute_metrics(rows, "detector_outcome"),
    )
    lines += [
        "## Per-case results",
        "",
        "Status codes for sender / URL / credential / attachment: T = triggered, N = not triggered, I = inconclusive, "
        "X = not run.",
        "",
        "| Case | Group | Label | Description | Verdict | Score | S / U / C / A | Credited (points) | Verdict outcome | Detector outcome |",
        "|---|---|---|---|---|---:|---|---|---|---|",
    ]
    for row in rows:
        statuses = " / ".join(STATUS_CODES.get(row["statuses"][family], "?") for family in FAMILIES)
        credited = ", ".join(f"`{finding_id}` +{points}" for finding_id, points in row["credited"]) or "none"
        score = "n/a" if row["score"] is None else str(row["score"])
        lines.append(
            f"| {row['id']} | {row['group']} | {row['label']} | {row['description']} | `{row['verdict']}` | {score} | "
            f"{statuses} | {credited} | {row['outcome']} | {row['detector_outcome']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, help="write the Markdown report to this path as well as stdout")
    parser.add_argument("--label", help="short description of this run, recorded in the report header")
    args = parser.parse_args()

    cases, fixture_hash = load_cases()
    validate_cases(cases)
    rows = [evaluate_case(case) for case in cases]
    report = render_report(rows, fixture_hash, args.label)

    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdout.write(report)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
