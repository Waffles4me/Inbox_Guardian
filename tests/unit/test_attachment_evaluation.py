"""The synthetic attachment cases produce their recorded detector outcomes, and the frozen 30-case set is untouched."""

import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest


def load_runner(name: str):
    spec = importlib.util.spec_from_file_location(name, Path("tests/evaluation") / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_runner("run_attachment_evaluation")
CASES, _ = runner.load_cases()
FROZEN_CASES_SHA256 = "adb1211a0b08c94274118c151fdb4f608e30efbfa5f78bd71216fdd92eb8380f"


def test_frozen_evaluation_fixture_is_unchanged() -> None:
    raw = Path("tests/fixtures/evaluation/cases.json").read_bytes()

    assert hashlib.sha256(raw).hexdigest() == FROZEN_CASES_SHA256
    assert not any("attachment" in key for case in json.loads(raw)["cases"] for key in case["email"])


def test_attachment_cases_are_well_formed_and_synthetic() -> None:
    runner.validate_cases(CASES)
    hosts = re.findall(r"(?:https?://|@)([A-Za-z0-9.-]+)", json.dumps([case["email"] for case in CASES]))
    assert hosts and all(host.endswith(".test") for host in hosts)
    assert {case["group"] for case in CASES} == {"positive", "benign", "coverage"}


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_attachment_case_matches_its_recorded_outcome(case: dict) -> None:
    row = runner.evaluate_case(case)
    expected = case["expected"]

    assert row["attachment_status"] == expected["attachment_status"]
    assert row["attachment_findings"] == expected["attachment_findings"]
    assert row["attachment_points"] == expected["attachment_points"]


def test_report_renders_both_views() -> None:
    rows = [runner.evaluate_case(case) for case in CASES]
    report = runner.render_report(rows, "test")

    assert "## A. Overall verdict" in report
    assert "## B. Attachment detector status" in report
    assert "not a real-world benchmark" in report
