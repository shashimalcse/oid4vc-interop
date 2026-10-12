"""Setup/teardown hooks: how a target provisions itself, in any language.

vcit runs the hook command in the target directory, writes a JSON context to its stdin, and
reads JSON from its stdout. Logs belong on stderr. See docs/target-profiles.md.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from typing import Any

from ..constants import ATTESTER_ISSUER, PID_CLAIMS, PID_FORMAT, PID_VCT, WALLET_REDIRECT_URI
from .context import RunContext
from .pki import KeyPair

log = logging.getLogger(__name__)

VCI_PROFILES = ("vci-base", "vci-haip")


class HookError(RuntimeError):
    pass


def _key(kp: KeyPair) -> dict[str, Any]:
    return {"name": kp.name, "kid": kp.kid, "public_jwk": kp.public_jwk(), "cert_pem": kp.cert_pem}


def setup_context(ctx: RunContext) -> dict[str, Any]:
    t, keys = ctx.target, ctx.keys
    ids = [p.id for p in t.profiles]
    return {
        "run_id": ctx.run_id,
        "target": t.name,
        "profiles": ids,
        "suite": {
            "url": t.suite.url,
            "callbacks": {p: ctx.suite_callback(p) for p in ids if p in VCI_PROFILES},
        },
        "wallet": {"redirect_uri": WALLET_REDIRECT_URI},
        "clients": [_key(k) for k in keys.clients],
        "wallet_client": _key(keys.wallet_client),
        "attester": {"issuer": ATTESTER_ISSUER, **_key(keys.attester)},
        "test_ca_pem": keys.pki.ca_pem,
        "suite_credential": {
            "format": PID_FORMAT,
            "vct": PID_VCT,
            "claims": PID_CLAIMS,
            "issuer_cert_pem": keys.suite_signer.cert_pem,
        },
    }


def resolve_command(command: list[str]) -> list[str]:
    """`python` means vcit's own interpreter, so hooks can use vcit's dependencies (httpx...)."""
    return [sys.executable, *command[1:]] if command and command[0] in ("python", "python3") else list(command)


def run_hook(ctx: RunContext, name: str, command: list[str], payload: dict[str, Any]) -> dict[str, Any]:
    log.info("running %s hook: %s", name, " ".join(command))
    try:
        proc = subprocess.run(
            resolve_command(command),
            cwd=ctx.target.directory,
            env=ctx.loaded.env or None,
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=ctx.target.hooks.timeout,
        )
    except FileNotFoundError as e:
        raise HookError(f"{name} hook not runnable: {e}") from e
    except subprocess.TimeoutExpired as e:
        raise HookError(f"{name} hook timed out after {ctx.target.hooks.timeout:.0f}s") from e

    (ctx.artifacts / f"hook-{name}.stderr.log").write_text(proc.stderr)
    for line in proc.stderr.splitlines()[-20:]:
        log.info("[%s] %s", name, line)
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.splitlines()[-10:])
        raise HookError(f"{name} hook exited {proc.returncode}:\n{tail}")
    out = proc.stdout.strip()
    if not out:
        return {}
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        raise HookError(f"{name} hook did not print JSON on stdout: {out[:300]!r}") from e
    if not isinstance(data, dict):
        raise HookError(f"{name} hook must print a JSON object")
    return data


def run_setup(ctx: RunContext) -> dict[str, Any]:
    cmd = ctx.target.hooks.setup
    if not cmd:
        return {}
    output = run_hook(ctx, "setup", cmd, setup_context(ctx))
    ctx.setup_output = output
    (ctx.artifacts / "hook-setup.output.json").write_text(json.dumps(output, indent=2))
    return output


def run_teardown(ctx: RunContext) -> None:
    cmd = ctx.target.hooks.teardown
    if not cmd:
        return
    try:
        run_hook(ctx, "teardown", cmd, {"context": setup_context(ctx), "setup": ctx.setup_output})
    except HookError as e:
        log.warning("%s", e)
