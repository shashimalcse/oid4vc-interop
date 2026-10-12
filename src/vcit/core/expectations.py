"""Known-gap baselines and the classifier that turns a status into an outcome.

An expectations file (expectations/<profile>.yaml) looks like:

    profile: vp-haip
    cases:
      oid4vp-1final-verifier-happy-flow:
        expect: FAILED
        issue: https://github.com/example/verifier/issues/123
        reason: "VP-39: direct_post response has no redirect_uri"
        conditions: [VP1FinalEnsureDirectPostResponseHasRedirectUriForHaip]
      "oid4vp-1final-verifier-invalid-*":
        expect: FAILED

Keys are module or check ids; `*` globs are allowed, and an exact key wins over a glob.
`conditions` is optional. When it is given, a failure caused by any other condition counts
as a regression, because the case is now failing for a new reason.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .model import FAIL_STATUSES, PASS_STATUSES, STATUSES, Case, RunResult


@dataclass
class Expectation:
    expect: str
    issue: str | None = None
    reason: str | None = None
    conditions: list[str] = field(default_factory=list)


@dataclass
class ProfileExpectations:
    profile: str
    cases: dict[str, Expectation] = field(default_factory=dict)

    def lookup(self, case_id: str) -> Expectation | None:
        if case_id in self.cases:
            return self.cases[case_id]
        globs = [k for k in self.cases if "*" in k and fnmatch.fnmatchcase(case_id, k)]
        # Prefer the most specific (longest) pattern.
        return self.cases[max(globs, key=len)] if globs else None


def load_expectations(directory: Path) -> dict[str, ProfileExpectations]:
    out: dict[str, ProfileExpectations] = {}
    if not directory.is_dir():
        return out
    for f in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(f.read_text()) or {}
        profile = data.get("profile") or f.stem
        cases = {}
        for key, spec in (data.get("cases") or {}).items():
            spec = {"expect": spec} if isinstance(spec, str) else dict(spec)
            expect = str(spec.get("expect", "")).upper()
            if expect not in STATUSES:
                raise ValueError(f"{f}: case {key!r}: unknown expect status {expect!r}")
            cases[key] = Expectation(
                expect=expect,
                issue=spec.get("issue"),
                reason=spec.get("reason"),
                conditions=list(spec.get("conditions") or []),
            )
        out[profile] = ProfileExpectations(profile=profile, cases=cases)
    return out


def classify(case: Case, exp: Expectation | None) -> tuple[str, str | None]:
    """Return (outcome, note) for a case given its expectation."""
    expected = exp.expect if exp else "PASSED"
    actual = case.status

    if actual in PASS_STATUSES:
        if expected in FAIL_STATUSES:
            return "fixed", f"expected {expected}, now {actual}: update the baseline"
        return "pass", None

    if actual == "SKIPPED":
        if expected in PASS_STATUSES and exp is not None:
            return "regression", f"expected {expected}, now SKIPPED"
        return "skipped", None

    # Failing statuses from here on.
    if exp is None or expected not in FAIL_STATUSES:
        return "regression", f"expected {expected}, now {actual}"
    if exp.conditions:
        new = case.failing_conditions() - set(exp.conditions)
        if new:
            return "regression", "fails for a new reason: " + ", ".join(sorted(new))
    return "known-failure", None


def apply_expectations(run: RunResult, expectations: dict[str, ProfileExpectations]) -> None:
    for profile in run.profiles:
        pe = expectations.get(profile.id)
        for case in profile.cases:
            exp = pe.lookup(case.id) if pe else None
            case.expected = exp.expect if exp else None
            case.issue = exp.issue if exp else None
            case.reason = exp.reason if exp else None
            case.outcome, case.outcome_note = classify(case, exp)


def should_fail(run: RunResult, fail_on: str) -> bool:
    counts = run.counts()
    if fail_on == "never":
        return False
    if fail_on == "any-failure":
        return counts["regression"] + counts["known-failure"] > 0 or any(p.error for p in run.profiles)
    return counts["regression"] > 0 or any(p.error for p in run.profiles)
