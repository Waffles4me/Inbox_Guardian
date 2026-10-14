"""Run the labeled synthetic evaluation set through the existing parser, engine and Method C scorer.

Usage (from the repository root):

    .\\.venv\\Scripts\\python.exe tests\\evaluation\\run_evaluation.py
    .\\.venv\\Scripts\\python.exe tests\\evaluation\\run_evaluation.py --label "after change X" --output docs\\evaluation-results-<name>.md

``docs/evaluation-results.md`` is the original baseline; write later runs to a new file instead of overwriting it.

The runner is read-only with respect to detection: it calls ``analyze_with_detectors`` and
``score_engine_result`` unchanged, performs no network access and only writes the optional report file.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from backend.app.engine import IMPLEMENTATION_VERSION as ENGINE_VERSION  # noqa: E402
from backend.app.engine import analyze_with_detectors  # noqa: E402
from backend.app.models import EmailPayload  # noqa: E402
from backend.app.scoring import IMPLEMENTATION_VERSION as SCORING_VERSION  # noqa: E402
from backend.app.scoring import score_engine_result  # noqa: E402

CASES_PATH = REPO_ROOT / "tests" / "fixtures" / "evaluation" / "cases.json"
LABELS = {"BENIGN", "SUSPICIOUS"}
PREDICTED_SUSPICIOUS = {"HIGH_RISK", "SUSPICIOUS"}
IMPLEMENTED = ("sender_identity", "url_deception", "credential_context", "attachment_metadata", "financial_fraud")
REQUIRED_FIELDS = ("id", "group", "label", "description", "expected_behavior", "rationale", "families", "overlap", "email")
STATUS_CODES = {"TRIGGERED": "T", "NOT_TRIGGERED": "N", "INCONCLUSIVE": "I", "NOT_RUN": "X"}

_HOST_RE = re.compile(r"(?:https?://|@)([A-Za-z0-9.-]+)")


def load_cases() -> tuple[list[dict], str]:
    raw = CASES_PATH.read_bytes()
    cases = json.loads(raw)["cases"]
    return cases, hashlib.sha256(raw).hexdigest()


def validate_cases(cases: list[dict]) -> None:
    """Fail fast if a fixture is malformed or references a non-reserved host."""
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
        email = case["email"]
        text = " ".join(str(email.get(key, "")) for key in ("from", "reply_to", "text_body", "html_body"))
        for host in _HOST_RE.findall(text):
            host = host.rstrip(".").lower()
            if host.endswith(".test"):
                continue
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                raise ValueError(f"{case['id']}: host {host} is not a reserved .test name") from None
            if not any(address in network for network in _DOCUMENTATION_NETWORKS):
                raise ValueError(f"{case['id']}: address {host} is outside the documentation ranges")


_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(block) for block in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def evaluate_case(case: dict) -> dict:
    email = dict(case["email"])
    payload = EmailPayload.model_validate(email)
    engine_result = analyze_with_detectors(payload)
    scoring = score_engine_result(engine_result)
    statuses = {result.detector_id: result.status.value for result in engine_result.detector_results}
    verdict = scoring.verdict

    if verdict == "INCOMPLETE":
        outcome = "ABSTAIN"
    elif verdict in PREDICTED_SUSPICIOUS:
        outcome = "TP" if case["label"] == "SUSPICIOUS" else "FP"
    else:
        outcome = "FN" if case["label"] == "SUSPICIOUS" else "TN"

    return {
        "id": case["id"],
        "group": case["group"],
        "label": case["label"],
        "verdict": verdict,
        "score": None if verdict == "INCOMPLETE" else scoring.risk_score,
        "findings": [(item.finding.id, item.effective_contribution) for item in scoring.scored_findings],
        "statuses": {detector_id: statuses.get(detector_id, "MISSING") for detector_id in IMPLEMENTED},
        "independent_families": list(scoring.independent_evidence_families),
        "coverage_reasons": list(scoring.coverage.reasons),
        "outcome": outcome,
    }


def ratio(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return f"n/a ({numerator}/{denominator})"
    return f"{numerator / denominator:.2f} ({numerator}/{denominator})"


def compute_metrics(rows: list[dict]) -> dict:
    counts = {key: sum(1 for row in rows if row["outcome"] == key) for key in ("TP", "FP", "TN", "FN", "ABSTAIN")}
    total = len(rows)
    assessed = total - counts["ABSTAIN"]
    suspicious_total = sum(1 for row in rows if row["label"] == "SUSPICIOUS")
    return {
        "counts": counts,
        "total": total,
        "assessed": assessed,
        "precision": ratio(counts["TP"], counts["TP"] + counts["FP"]),
        "recall_assessed": ratio(counts["TP"], counts["TP"] + counts["FN"]),
        "recall_all": ratio(counts["TP"], suspicious_total),
        "false_positive_rate": ratio(counts["FP"], counts["FP"] + counts["TN"]),
        "coverage": ratio(assessed, total),
    }


def render_report(rows: list[dict], metrics: dict, fixture_hash: str, label: str | None = None) -> str:
    lines = [
        "# InboxGuardian - Synthetic Evaluation Results",
        "",
        "Generated by `tests/evaluation/run_evaluation.py`. Do not edit by hand; rerun the script instead.",
        "Interpretation, limitations and failure analysis are in `docs/evaluation-baseline.md`.",
        "",
        *([f"- Run: {label}"] if label else []),
        f"- Fixture: `tests/fixtures/evaluation/cases.json` (SHA-256 `{fixture_hash}`)",
        f"- Engine / scorer: `{ENGINE_VERSION}` / `{SCORING_VERSION}`",
        f"- Cases: {metrics['total']} synthetic messages. These are not a real-world benchmark.",
        "",
        "## Per-case results",
        "",
        "Detector status codes: T = triggered, N = not triggered, I = inconclusive, X = not run.",
        "Outcome: TP/FP/TN/FN for assessed cases; ABSTAIN when the verdict is `INCOMPLETE`.",
        "",
        "| Case | Group | Label | Verdict | Score | Sender / URL / Credential / Attachment / Financial | Findings (effective contribution) | Outcome |",
        "|---|---|---|---|---:|---|---|---|",
    ]
    for row in rows:
        findings = ", ".join(f"`{finding_id}` +{points}" for finding_id, points in row["findings"]) or "none"
        statuses = " / ".join(STATUS_CODES.get(row["statuses"][detector_id], "?") for detector_id in IMPLEMENTED)
        score = "n/a" if row["score"] is None else str(row["score"])
        lines.append(
            f"| {row['id']} | {row['group']} | {row['label']} | `{row['verdict']}` | {score} | {statuses} | "
            f"{findings} | {row['outcome']} |"
        )

    counts = metrics["counts"]
    lines += [
        "",
        "## Confusion matrix",
        "",
        "`HIGH_RISK` and `SUSPICIOUS` count as predicted suspicious, `NO_SIGNIFICANT_SIGNALS` as predicted benign, "
        "and `INCOMPLETE` as an abstention.",
        "",
        "| | Predicted suspicious | Predicted benign | Abstained |",
        "|---|---:|---:|---:|",
    ]
    for label in ("SUSPICIOUS", "BENIGN"):
        subset = [row for row in rows if row["label"] == label]
        predicted_suspicious = sum(1 for row in subset if row["outcome"] in {"TP", "FP"})
        predicted_benign = sum(1 for row in subset if row["outcome"] in {"TN", "FN"})
        abstained = sum(1 for row in subset if row["outcome"] == "ABSTAIN")
        lines.append(f"| Labeled {label} | {predicted_suspicious} | {predicted_benign} | {abstained} |")

    lines += [
        "",
        "## Metrics",
        "",
        "| Metric | Value | Denominator |",
        "|---|---|---|",
        f"| True positives | {counts['TP']} | |",
        f"| False positives | {counts['FP']} | |",
        f"| True negatives | {counts['TN']} | |",
        f"| False negatives | {counts['FN']} | |",
        f"| Abstentions | {counts['ABSTAIN']} | |",
        f"| Precision | {metrics['precision']} | TP + FP; abstentions excluded |",
        f"| Recall (assessed cases) | {metrics['recall_assessed']} | TP + FN; abstentions excluded |",
        f"| Recall (all suspicious cases) | {metrics['recall_all']} | all labeled SUSPICIOUS; abstentions count as misses |",
        f"| False-positive rate | {metrics['false_positive_rate']} | FP + TN; abstentions excluded |",
        f"| Coverage (assessed-case rate) | {metrics['coverage']} | all cases |",
        "",
        "## Results by group",
        "",
        "| Group | Cases | Matched label | Mismatched | Abstained |",
        "|---|---:|---:|---:|---:|",
    ]
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row["group"], []).append(row)
    for group, members in groups.items():
        matched = sum(1 for row in members if row["outcome"] in {"TP", "TN"})
        mismatched = sum(1 for row in members if row["outcome"] in {"FP", "FN"})
        abstained = sum(1 for row in members if row["outcome"] == "ABSTAIN")
        lines.append(f"| {group} | {len(members)} | {matched} | {mismatched} | {abstained} |")

    lines += [
        "",
        "## Verdict distribution",
        "",
        "| Verdict | Labeled SUSPICIOUS | Labeled BENIGN |",
        "|---|---:|---:|",
    ]
    for verdict in ("HIGH_RISK", "SUSPICIOUS", "NO_SIGNIFICANT_SIGNALS", "INCOMPLETE"):
        suspicious = sum(1 for row in rows if row["verdict"] == verdict and row["label"] == "SUSPICIOUS")
        benign = sum(1 for row in rows if row["verdict"] == verdict and row["label"] == "BENIGN")
        lines.append(f"| `{verdict}` | {suspicious} | {benign} |")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, help="write the Markdown report to this path as well as stdout")
    parser.add_argument("--label", help="short description of this run, recorded in the report header")
    args = parser.parse_args()

    cases, fixture_hash = load_cases()
    validate_cases(cases)
    rows = [evaluate_case(case) for case in cases]
    report = render_report(rows, compute_metrics(rows), fixture_hash, args.label)

    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdout.write(report)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
