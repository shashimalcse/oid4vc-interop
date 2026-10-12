"""Profile base classes.

A profile is one selectable unit in the YAML `profiles:` list. Suite profiles wrap one
conformance-suite test plan; the wallet profile drives a real wallet instead.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from ..config import ConfigError, ProfileSelection
from ..core.context import RunContext
from ..core.model import ProfileResult
from ..suite.runner import WaitingHandler, run_module

log = logging.getLogger(__name__)


class Profile(ABC):
    id: ClassVar[str]
    title: ClassVar[str]
    kind: ClassVar[str]

    def __init__(self, ctx: RunContext, selection: ProfileSelection):
        self.ctx = ctx
        self.selection = selection

    def provision(self) -> None:
        """Prepare anything the profile needs before it runs (generic; target setup is a hook)."""

    @abstractmethod
    def run(self) -> ProfileResult: ...

    def new_result(self) -> ProfileResult:
        return ProfileResult(id=self.id, title=self.title, kind=self.kind)


class SuiteProfile(Profile):
    kind = "suite"
    plan_name: ClassVar[str]
    # Variant values the plan pins itself; sent for clarity, never overridable.
    pinned: ClassVar[dict[str, str]] = {}
    # Our defaults for the variants the plan leaves open; the YAML may override these.
    defaults: ClassVar[dict[str, str]] = {}
    module_timeout: ClassVar[float] = 300

    @classmethod
    def effective_variant(cls, overrides: dict[str, str]) -> dict[str, str]:
        unknown = set(overrides) - set(cls.defaults) - set(cls.pinned)
        if unknown:
            raise ConfigError(
                f"profile {cls.id}: unknown variant(s) {', '.join(sorted(unknown))}; "
                f"allowed: {', '.join(sorted(cls.defaults))}"
            )
        clash = {k for k, v in overrides.items() if k in cls.pinned and cls.pinned[k] != v}
        if clash:
            raise ConfigError(
                f"profile {cls.id}: {', '.join(sorted(clash))} pinned by {cls.plan_name}; "
                f"pinned values: {', '.join(f'{k}={cls.pinned[k]}' for k in sorted(clash))}"
            )
        return {**cls.defaults, **overrides, **cls.pinned}

    @property
    def variant(self) -> dict[str, str]:
        return self.effective_variant(self.selection.variants)

    @property
    def alias(self) -> str:
        """Suite test alias; fixed, so the callback URL can be registered ahead of time."""
        return self.ctx.alias(self.id)

    @abstractmethod
    def plan_config(self) -> dict[str, Any]:
        """The configuration JSON posted when creating the plan."""

    @abstractmethod
    def waiting_handler(self) -> WaitingHandler | None: ...

    def run(self) -> ProfileResult:
        result = self.new_result()
        result.plan_name = self.plan_name
        result.variant = self.variant
        suite = self.ctx.suite
        config = {"alias": self.alias, "description": f"vcit {self.ctx.run_id} {self.id}", "publish": "no"}
        config.update(self.plan_config())

        # Values the plan pins itself are not sent; the suite fills them in per module.
        plan_variant = {k: v for k, v in self.variant.items() if k not in self.pinned}
        plan = suite.create_plan(self.plan_name, config, plan_variant)
        result.plan_id = plan["id"]
        result.plan_url = suite.plan_url(plan["id"])

        handler = self.waiting_handler()
        modules = [m for m in plan.get("modules", []) if self.ctx.target.modules.matches(m["testModule"])]
        log.info("%s: plan %s with %d module(s)", self.id, plan["id"], len(modules))
        for i, m in enumerate(modules, 1):
            name = m["testModule"]
            log.info("%s [%d/%d] %s", self.id, i, len(modules), name)
            case = run_module(suite, plan["id"], name, m.get("variant"), handler, self.module_timeout)
            log.info("%s [%d/%d] %s -> %s", self.id, i, len(modules), name, case.status)
            result.cases.append(case)

        try:
            suite.export_plan_html(plan["id"], self.ctx.artifacts / f"suite-{self.id}-{plan['id']}.zip")
        except Exception:
            log.warning("%s: suite export failed", self.id, exc_info=True)
        return result
