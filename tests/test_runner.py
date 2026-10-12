"""The module runner against a scripted fake suite."""

from __future__ import annotations

from vcit.suite.runner import run_module


class FakeSuite:
    def __init__(self, states, result="PASSED", log=None, repeat_last=False):
        self.states = list(states)
        self.repeat_last = repeat_last
        self.result = result
        self._log = log or []
        self.started = False
        self.stopped = False

    def create_module(self, plan_id, module, variant):
        return "t1"

    def log_url(self, tid):
        return f"https://suite/log-detail.html?log={tid}"

    def runner_state(self, tid):
        # The real /api/runner has no status; it is served by info(). Advance the script here.
        if not self.states:
            self.current = {"status": "FINISHED"}
            return None
        s = self.states[0] if self.repeat_last and len(self.states) == 1 else self.states.pop(0)
        self.current = s if isinstance(s, dict) else {"status": s}
        return {k: v for k, v in self.current.items() if k != "status"}

    def start_module(self, tid):
        self.started = True

    def wait_state(self, *a, **kw):
        return None

    def stop_module(self, tid):
        self.stopped = True

    def info(self, tid):
        status = getattr(self, "current", {}).get("status", "CREATED")
        return {"status": status, "result": self.result if status == "FINISHED" else None}

    def log(self, tid):
        return self._log


def test_happy_path_starts_and_hands_waiting_to_handler():
    suite = FakeSuite(
        ["CONFIGURED", {"status": "WAITING", "browser": {"urls": ["https://is/authorize"]}}, "RUNNING", "FINISHED"],
        log=[
            {"result": "FAILURE", "src": "CondA", "msg": "bad", "requirements": ["R1"]},
            {"result": "FAILURE", "src": "CondA", "msg": "dup"},
            {"result": "SUCCESS", "src": "CondB"},
        ],
        result="FAILED",
    )
    seen = []

    def handler(ctx):
        seen.extend(ctx.pending_urls())
        ctx.scratch["handled_urls"].update(ctx.pending_urls())
        return True

    case = run_module(suite, "p", "mod", {"v": "1"}, handler)
    assert suite.started
    assert seen == ["https://is/authorize"]
    assert case.status == "FAILED"
    assert [f.condition for f in case.findings] == ["CondA"]  # deduplicated, SUCCESS dropped
    assert case.suite_log_url.endswith("t1") and case.variant == {"v": "1"}


def test_timeout_stops_module():
    suite = FakeSuite(["WAITING"], repeat_last=True)
    case = run_module(suite, "p", "mod", None, lambda ctx: False, timeout=0.05)
    assert case.status == "TIMEOUT" and suite.stopped


def test_handler_exception_is_recorded_not_raised():
    suite = FakeSuite(["WAITING"])

    def boom(ctx):
        raise RuntimeError("IS down")

    case = run_module(suite, "p", "mod", None, boom)
    assert case.status == "ERROR" and "IS down" in case.error and suite.stopped


def test_finish_hook_runs():
    suite = FakeSuite(["FINISHED"])

    class H:
        finished = False

        def __call__(self, ctx):
            return False

        def finish(self, ctx):
            H.finished = True

    run_module(suite, "p", "mod", None, H())
    assert H.finished
