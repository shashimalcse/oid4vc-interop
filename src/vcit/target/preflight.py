"""Checks that fail fast, with a clear message, before any test runs."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from ..config.schema import NEEDS_ISSUER, WALLET_PROFILES
from ..core.context import RunContext
from ..profiles import profile_class
from ..profiles.base import SuiteProfile

log = logging.getLogger(__name__)


class PreflightError(RuntimeError):
    pass


def preflight(ctx: RunContext) -> dict[str, Any]:
    t = ctx.target
    ids = {p.id for p in t.profiles}
    facts: dict[str, Any] = {}

    if ids & NEEDS_ISSUER:
        try:
            meta = ctx.issuer.metadata
        except Exception as e:
            raise PreflightError(str(e)) from e
        facts["credential_issuer"] = meta.get("credential_issuer")
        if meta.get("credential_issuer") and meta["credential_issuer"] != t.issuer.credential_issuer:
            log.warning(
                "issuer advertises credential_issuer %s, the target profile says %s",
                meta["credential_issuer"],
                t.issuer.credential_issuer,
            )
        configs = meta.get("credential_configurations_supported") or {}
        if configs and t.issuer.credential_configuration_id not in configs:
            raise PreflightError(
                f"credential_configuration_id {t.issuer.credential_configuration_id!r} is not in the issuer "
                f"metadata (has: {', '.join(sorted(configs)) or 'none'})"
            )

    suite_ids = [i for i in ids if issubclass(profile_class(i), SuiteProfile)]
    if suite_ids:
        ctx.suite.wait_until_ready(timeout=120)
        available = set(ctx.suite.available_plans())
        missing = [profile_class(i).plan_name for i in suite_ids if profile_class(i).plan_name not in available]
        if missing:
            raise PreflightError(f"conformance suite does not offer: {', '.join(missing)}")

    if ids & WALLET_PROFILES:
        for driver in ctx.wallets:
            deadline = time.monotonic() + 30  # a freshly started JVM wallet takes a few seconds
            while True:
                try:
                    driver.health()
                    break
                except httpx.HTTPError as e:
                    if time.monotonic() > deadline:
                        raise PreflightError(f"wallet {driver.name} not reachable at {driver.cfg.url}: {e}") from e
                    time.sleep(2)

    log.info("preflight OK")
    return facts
