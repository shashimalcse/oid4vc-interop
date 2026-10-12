"""Runs suite modules one at a time and hands WAITING states to a profile-specific handler.

A module in WAITING needs something from outside the suite: a browser to log in at the authorization server (VCI
plans), a verifier to send its request to the suite's authorize endpoint (VP plans), or a
screenshot uploaded to a placeholder. Profiles supply that as a WaitingHandler.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..core.model import Case, Finding, Step
from .client import SuiteClient, SuiteError

log = logging.getLogger(__name__)

TERMINAL = {"FINISHED", "INTERRUPTED"}


@dataclass
class ModuleContext:
    suite: SuiteClient
    test_id: str
    module: str
    variant: dict[str, str]
    state: dict[str, Any] = field(default_factory=dict)  # latest GET /api/runner/{id}
    steps: list[Step] = field(default_factory=list)
    scratch: dict[str, Any] = field(default_factory=dict)  # per-module handler state

    @property
    def exposed(self) -> dict[str, Any]:
        return self.state.get("exposed") or {}

    @property
    def browser(self) -> dict[str, Any]:
        return self.state.get("browser") or {}

    def pending_urls(self) -> list[str]:
        """Front-channel URLs the suite wants a browser to visit and that are not handled yet."""
        b = self.browser
        done = set(b.get("visited") or []) | set(self.scratch.setdefault("handled_urls", set()))
        return [u for u in (b.get("urls") or []) if u not in done]

    def pending_placeholders(self) -> list[str]:
        if "placeholders" not in self.scratch:
            self.scratch["placeholders"] = set()
        entries = self.suite.log(self.test_id)
        return [
            e["upload"]
            for e in entries
            if e.get("upload") and e["upload"] not in self.scratch["placeholders"]
        ]


class WaitingHandler(Protocol):
    def __call__(self, ctx: ModuleContext) -> bool:
        """Act on a WAITING module. Return True if something was done, False if nothing to do."""
        ...


def _findings(entries: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for e in entries:
        result = e.get("result")
        if result not in ("FAILURE", "WARNING", "REVIEW"):
            continue
        key = (result, e.get("src", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Finding(
                result=result,
                condition=e.get("src", ""),
                message=str(e.get("msg", ""))[:1000],
                requirements=list(e.get("requirements") or []),
            )
        )
    return out


def run_module(
    suite: SuiteClient,
    plan_id: str,
    module: str,
    variant: dict[str, str] | None,
    handler: WaitingHandler | None,
    timeout: float = 300,
) -> Case:
    started = time.monotonic()
    case = Case(id=module, status="ERROR", variant=dict(variant or {}))
    try:
        test_id = suite.create_module(plan_id, module, variant)
    except SuiteError as e:
        case.error = str(e)
        return case

    case.suite_test_id = test_id
    case.suite_log_url = suite.log_url(test_id)
    ctx = ModuleContext(suite=suite, test_id=test_id, module=module, variant=dict(variant or {}))
    deadline = started + timeout
    status = None

    try:
        while time.monotonic() < deadline:
            # /api/runner has the exposed values and browser requests but no status;
            # the status lives in /api/info.
            state = suite.runner_state(test_id)
            status = suite.info(test_id).get("status")
            if state is None and status not in TERMINAL:
                status = "FINISHED"  # no longer running; the result is persisted
            ctx.state = state or {}
            if status in TERMINAL:
                break
            if status == "CONFIGURED":
                suite.start_module(test_id)
                continue
            acted = False
            if status == "WAITING" and handler is not None:
                acted = handler(ctx)
            if not acted:
                suite.wait_state(test_id, sorted(TERMINAL), timeout_ms=2000)
        else:
            case.status = "TIMEOUT"
            case.error = f"module did not finish within {timeout:.0f}s (last status {status})"
            suite.stop_module(test_id)
    except Exception as e:  # handler or transport failure: record it, never abort the whole plan
        log.exception("module %s failed in the harness", module)
        case.status = "ERROR"
        case.error = f"{type(e).__name__}: {e}"
        suite.stop_module(test_id)

    finish = getattr(handler, "finish", None)
    if finish is not None:
        try:
            finish(ctx)
        except Exception as e:
            log.warning("finish hook for %s failed: %s", module, e)

    if status in TERMINAL and case.error is None:
        info = suite.info(test_id)
        result = info.get("result")
        if result:
            case.status = result
        elif info.get("status") == "INTERRUPTED":
            case.status = "INTERRUPTED"

    try:
        case.findings = _findings(suite.log(test_id))
    except SuiteError as e:
        log.warning("could not read log for %s: %s", test_id, e)
    case.steps = ctx.steps
    case.duration_s = round(time.monotonic() - started, 1)
    return case
