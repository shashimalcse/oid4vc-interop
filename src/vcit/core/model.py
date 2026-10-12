"""Result model shared by the runners, the expectations engine and the reports.

`results.json` is a direct serialisation of RunResult and is the source of truth for every
report format.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

# Statuses reported by the conformance suite, plus TIMEOUT/ERROR for our own failures.
PASS_STATUSES = {"PASSED", "WARNING", "REVIEW"}
FAIL_STATUSES = {"FAILED", "INTERRUPTED", "TIMEOUT", "ERROR"}
STATUSES = PASS_STATUSES | FAIL_STATUSES | {"SKIPPED"}

# Outcomes after comparing a status with its expectation.
OUTCOMES = ("regression", "fixed", "known-failure", "pass", "skipped")


@dataclass
class Finding:
    result: str  # FAILURE | WARNING | REVIEW
    condition: str
    message: str
    requirements: list[str] = field(default_factory=list)


@dataclass
class HttpExchange:
    method: str
    url: str
    status: int | None = None
    request: str | None = None  # redacted, truncated body summary
    response: str | None = None


@dataclass
class Step:
    name: str
    status: str
    detail: str = ""
    http: list[HttpExchange] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)  # data: URIs, inlined in the HTML


@dataclass
class Case:
    """One suite module run, or one wallet-interop check."""

    id: str
    status: str
    title: str = ""
    suite_test_id: str | None = None
    suite_log_url: str | None = None
    variant: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    duration_s: float = 0.0
    error: str | None = None
    # Filled in by the expectations engine.
    expected: str | None = None
    issue: str | None = None
    reason: str | None = None
    outcome: str | None = None
    outcome_note: str | None = None

    def failing_conditions(self) -> set[str]:
        return {f.condition for f in self.findings if f.result == "FAILURE"}


@dataclass
class ProfileResult:
    id: str
    title: str
    kind: str  # "suite" | "wallet"
    plan_name: str | None = None
    plan_id: str | None = None
    plan_url: str | None = None
    variant: dict[str, str] = field(default_factory=dict)
    cases: list[Case] = field(default_factory=list)
    error: str | None = None

    def counts(self) -> dict[str, int]:
        c = {o: 0 for o in OUTCOMES}
        for case in self.cases:
            if case.outcome:
                c[case.outcome] += 1
        return c


@dataclass
class RunResult:
    run_id: str
    started_at: str
    finished_at: str | None = None
    target: dict[str, Any] = field(default_factory=dict)
    suite: dict[str, Any] = field(default_factory=dict)
    wallet: dict[str, Any] = field(default_factory=dict)
    profiles: list[ProfileResult] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        total = {o: 0 for o in OUTCOMES}
        for p in self.profiles:
            for k, v in p.counts().items():
                total[k] += v
        return total

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def save(self, path: Path) -> None:
        path.write_text(self.to_json())

    @classmethod
    def load(cls, path: Path) -> "RunResult":
        return run_from_dict(json.loads(path.read_text()))


def _build(cls, data: dict[str, Any]):
    names = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in names})


def run_from_dict(d: dict[str, Any]) -> RunResult:
    profiles = []
    for p in d.get("profiles", []):
        cases = []
        for c in p.get("cases", []):
            steps = [
                _build(Step, {**s, "http": [_build(HttpExchange, h) for h in s.get("http", [])]})
                for s in c.get("steps", [])
            ]
            findings = [_build(Finding, f) for f in c.get("findings", [])]
            cases.append(_build(Case, {**c, "steps": steps, "findings": findings}))
        profiles.append(_build(ProfileResult, {**p, "cases": cases}))
    return _build(RunResult, {**d, "profiles": profiles})
