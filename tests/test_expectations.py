from __future__ import annotations

from pathlib import Path

import pytest

from vcit.core.expectations import Expectation, apply_expectations, classify, load_expectations, should_fail
from vcit.core.model import Case, Finding


def case(status: str, *conditions: str) -> Case:
    return Case(id="m", status=status, findings=[Finding("FAILURE", c, "") for c in conditions])


@pytest.mark.parametrize(
    "status,expect,outcome",
    [
        ("PASSED", None, "pass"),
        ("WARNING", None, "pass"),
        ("REVIEW", None, "pass"),
        ("FAILED", None, "regression"),
        ("TIMEOUT", None, "regression"),
        ("SKIPPED", None, "skipped"),
        ("FAILED", "FAILED", "known-failure"),
        ("INTERRUPTED", "FAILED", "known-failure"),
        ("PASSED", "FAILED", "fixed"),
        ("SKIPPED", "PASSED", "regression"),
        ("SKIPPED", "SKIPPED", "skipped"),
        ("FAILED", "SKIPPED", "regression"),
    ],
)
def test_classify(status, expect, outcome):
    exp = Expectation(expect=expect) if expect else None
    assert classify(case(status), exp)[0] == outcome


def test_new_failure_reason_is_a_regression():
    exp = Expectation(expect="FAILED", conditions=["A"])
    assert classify(case("FAILED", "A"), exp)[0] == "known-failure"
    outcome, note = classify(case("FAILED", "A", "B"), exp)
    assert outcome == "regression" and "B" in note


def test_load_and_glob_lookup(tmp_path: Path):
    (tmp_path / "vp-haip.yaml").write_text(
        """
profile: vp-haip
cases:
  oid4vp-1final-verifier-happy-flow: {expect: FAILED, issue: https://x/1, reason: VP-39}
  "oid4vp-1final-verifier-invalid-*": FAILED
  "oid4vp-1final-verifier-*": {expect: SKIPPED}
"""
    )
    pe = load_expectations(tmp_path)["vp-haip"]
    assert pe.lookup("oid4vp-1final-verifier-happy-flow").issue == "https://x/1"
    assert pe.lookup("oid4vp-1final-verifier-invalid-sd-hash").expect == "FAILED"
    assert pe.lookup("oid4vp-1final-verifier-request-uri-method-post").expect == "SKIPPED"
    assert pe.lookup("other") is None


def test_bad_status_rejected(tmp_path: Path):
    (tmp_path / "x.yaml").write_text("cases: {m: {expect: BROKEN}}")
    with pytest.raises(ValueError, match="BROKEN"):
        load_expectations(tmp_path)


def test_apply_and_should_fail(run, tmp_path: Path):
    (tmp_path / "vp-haip.yaml").write_text(
        "cases:\n  oid4vp-1final-verifier-happy-flow: {expect: FAILED, reason: VP-39}\n"
    )
    apply_expectations(run, load_expectations(tmp_path))
    vp = run.profiles[0]
    outcomes = {c.id: c.outcome for c in vp.cases}
    assert outcomes["oid4vp-1final-verifier-happy-flow"] == "known-failure"
    assert outcomes["oid4vp-1final-verifier-invalid-kb-jwt-signature"] == "regression"
    assert outcomes["oid4vp-1final-verifier-request-uri-method-post"] == "skipped"
    assert vp.cases[0].reason == "VP-39"
    assert should_fail(run, "regression")
    assert not should_fail(run, "never")


def test_profile_error_fails_run(run, tmp_path: Path):
    for p in run.profiles:
        for c in p.cases:
            c.status = "PASSED"
    apply_expectations(run, {})
    assert run.counts()["regression"] == 0
    assert should_fail(run, "regression")  # vci-haip has a setup error


def test_repo_expectations_parse():
    root = Path(__file__).resolve().parents[1]
    load_expectations(root / "expectations")
