"""vcit: OpenID4VC conformance and wallet interop tests for any issuer and verifier.

  vcit validate    --target DIR    check a target profile, print effective suite variants
  vcit keygen      --target DIR    create a static target's fixed key files, once
  vcit target-info --target DIR    what a static target must register (redirect URIs, keys)
  vcit up/down     --target DIR    start/stop the managed conformance suite and Wallet2
  vcit run         --target DIR    run the selected test profiles, write the HTML report
  vcit report      RUN_DIR         re-render reports from results.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import ConfigError, LoadedTarget, TargetProfile, load_target, redact
from .constants import PID_CLAIMS, PID_VCT, WALLET_REDIRECT_URI
from .core.context import RunContext, new_run_id
from .core.expectations import apply_expectations, load_expectations, should_fail
from .core.model import RunResult
from .profiles import profile_class
from .profiles.base import SuiteProfile
from .report import write_reports

log = logging.getLogger("vcit")

DEFAULT_COMPOSE = Path(__file__).resolve().parents[2] / "docker" / "compose.yaml"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load(args: argparse.Namespace) -> LoadedTarget:
    loaded = load_target(args.target)
    t = loaded.model
    only = getattr(args, "profile", None)
    if only:
        unknown = set(only) - {p.id for p in t.profiles}
        if unknown:
            raise ConfigError(f"--profile {', '.join(sorted(unknown))} not listed in the target's profiles")
        loaded.raw["profiles"] = [p for p in loaded.raw["profiles"] if (p if isinstance(p, str) else p["id"]) in only]
    if getattr(args, "module", None):
        loaded.raw.setdefault("modules", {})["include"] = args.module
    if getattr(args, "fail_on", None):
        loaded.raw.setdefault("report", {})["fail_on"] = args.fail_on
    loaded.model = loaded._validate(loaded.raw)
    return loaded


def cmd_validate(args: argparse.Namespace) -> int:
    loaded = _load(args)
    t = loaded.model
    print(f"target   {t.name}  ({t.directory})")
    if t.issuer:
        print(f"issuer   {t.issuer.credential_issuer}  [{t.issuer.credential_configuration_id}]")
    if t.verifier:
        print(f"verifier triggers: {', '.join(t.verifier.start_presentation)}"
              f"{'; result poll' if t.verifier.result else ''}")
    hooks = [n for n in ("setup", "teardown") if getattr(t.hooks, n)]
    print(f"hooks    {', '.join(hooks) or 'none (static target)'}")
    print(f"suite    {t.suite.url} ({t.suite.mode})   wallet {t.wallet.url} ({t.wallet.mode})")
    for sel in t.profiles:
        cls = profile_class(sel.id)
        if issubclass(cls, SuiteProfile):
            print(f"profile  {sel.id:<15} {cls.plan_name}")
            for k, v in cls.effective_variant(sel.variants).items():
                print(f"           {k}={v}{' (pinned)' if k in cls.pinned else ''}")
        else:
            print(f"profile  {sel.id:<15} {cls.title}")
    if loaded.needs_setup_values and not t.hooks.setup:
        raise ConfigError("target.yaml uses ${setup.*} but defines no setup hook")
    load_expectations(t.path(t.baseline_dir))
    print("target OK")
    return 0


def cmd_target_info(args: argparse.Namespace) -> int:
    """Everything a static target registers once; the same values reach a setup hook."""
    loaded = _load(args)
    t = loaded.model
    ctx = RunContext(loaded, "info", Path(args.out or "out") / "target-info")
    from .core.hooks import setup_context

    info = setup_context(ctx)
    if args.json:
        print(json.dumps(info, indent=2))
        return 0
    print(f"Target {t.name}: register these once (keys under {ctx.artifacts / 'pki'})\n")
    for p, url in info["suite"]["callbacks"].items():
        print(f"  redirect URI for {p:<9} {url}")
    print(f"  Wallet2 redirect URI     {WALLET_REDIRECT_URI}")
    for c in info["clients"] + [info["wallet_client"]]:
        print(f"  client key {c['name']:<14} kid {c['kid']}  (public JWK + cert in pki/)")
    print(f"\n  The verifier must trust the test CA for {PID_VCT} credentials with claims {', '.join(PID_CLAIMS)}:")
    print(f"  {ctx.artifacts / 'pki' / 'ca.crt'}")
    if not t.pki:
        print("\n  Note: without `pki:` in target.yaml the CA and keys change every run; static targets need fixed files.")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    """Create the fixed key files a static target references (pki, clients' jwk_file), once."""
    import tempfile

    from .core.pki import RunPki

    t = _load(args).model
    created = []
    if t.pki and not t.path(t.pki.ca_cert_file).exists():
        with tempfile.TemporaryDirectory() as tmp:
            pki = RunPki.create(Path(tmp), common_name=f"vcit test CA ({t.name})")
            pki.write_ca(t.path(t.pki.ca_cert_file), t.path(t.pki.ca_key_file))
        created += [t.pki.ca_cert_file, t.pki.ca_key_file]
    specs = []
    if t.issuer:
        specs = [(f"client{i + 1}", c) for i, c in enumerate(t.issuer.clients)]
        if t.issuer.wallet_client:
            specs.append(("wallet-client", t.issuer.wallet_client))
    for name, spec in specs:
        if spec.jwk_file and not t.path(spec.jwk_file).exists():
            with tempfile.TemporaryDirectory() as tmp:
                kp = RunPki.create(Path(tmp), "unused").self_signed(name, name)
            path = t.path(spec.jwk_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(kp.private_jwk(), indent=2))
            created.append(spec.jwk_file)
    for c in created:
        print(f"created {c}")
    if not created:
        print("nothing to create: every referenced key file exists")
    return 0


def _compose(args: argparse.Namespace, t: TargetProfile, *extra: str) -> int:
    env = {**os.environ, "SUITE_IMAGE_TAG": t.suite.image_tag, "WALLET2_IMAGE": t.wallet.image}
    cmd = ["docker", "compose", "-f", str(args.compose), "-p", "vcit"]
    if t.suite.mode == "managed":
        cmd += ["--profile", "suite"]
    if t.wallet.mode == "managed" and any(p.id == "wallet-interop" for p in t.profiles):
        cmd += ["--profile", "wallet"]
    cmd += list(extra)
    log.info("$ %s", " ".join(cmd))
    return subprocess.call(cmd, env=env)


def cmd_up(args: argparse.Namespace) -> int:
    loaded = _load(args)
    rc = _compose(args, loaded.model, "up", "-d", "--wait")
    if rc == 0 and loaded.model.suite.mode == "managed":
        RunContext(loaded, "up", Path(".")).suite.wait_until_ready()
        print(f"suite ready at {loaded.model.suite.url}")
    return rc


def cmd_down(args: argparse.Namespace) -> int:
    loaded = _load(args)
    return _compose(args, loaded.model, "down", *(["-v"] if args.volumes else []))


def cmd_run(args: argparse.Namespace) -> int:
    from .core.hooks import HookError, run_setup, run_teardown
    from .target.preflight import PreflightError, preflight

    loaded = _load(args)
    t = loaded.model
    run_id = new_run_id()
    out_dir = Path(args.out or t.report.out_dir) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    ctx = RunContext(loaded, run_id, out_dir)
    run = RunResult(
        run_id=run_id,
        started_at=_now(),
        target={
            "name": t.name,
            "issuer": t.issuer.credential_issuer if t.issuer else None,
            "verifier": ", ".join(t.verifier.start_presentation) if t.verifier else None,
        },
        suite={"url": t.suite.url},
        wallet={"type": t.wallet.type, "url": t.wallet.url, "image": t.wallet.image},
        config=redact(loaded.raw),
    )
    (out_dir / "target.effective.json").write_text(json.dumps(run.config, indent=2))

    def fail_all(message: str) -> None:
        for sel in ctx.target.profiles:
            result = profile_class(sel.id)(ctx, sel).new_result()
            result.error = message
            run.profiles.append(result)

    setup_ran = False
    try:
        try:
            if t.hooks.setup:
                loaded.resolve_setup(run_setup(ctx))
                setup_ran = True
            ctx.facts.update(preflight(ctx))
        except (HookError, ConfigError, PreflightError) as e:
            log.error("%s", e)
            fail_all(f"{type(e).__name__}: {e}")
            return 1
        for sel in ctx.target.profiles:
            profile = profile_class(sel.id)(ctx, sel)
            log.info("=== %s ===", sel.id)
            try:
                profile.provision()
                result = profile.run()
            except Exception as e:
                log.exception("profile %s failed", sel.id)
                result = profile.new_result()
                result.error = f"{type(e).__name__}: {e}"
            run.profiles.append(result)
    finally:
        if setup_ran:
            run_teardown(ctx)
        run.finished_at = _now()
        apply_expectations(run, load_expectations(t.path(t.baseline_dir)))
        paths = write_reports(run, out_dir)
        ctx.close()
        _publish_summary(paths["summary"])
        print(f"report: {paths['html']}")

    return 1 if should_fail(run, ctx.target.report.fail_on) else 0


def cmd_report(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    run = RunResult.load(run_dir / "results.json")
    if args.baseline:
        apply_expectations(run, load_expectations(Path(args.baseline)))
    paths = write_reports(run, run_dir)
    print(f"report: {paths['html']}")
    return 0


def _publish_summary(summary: Path) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a") as f:
            f.write(summary.read_text())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vcit", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def with_target(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        p.add_argument("-t", "--target", required=True, help="target profile directory (holds target.yaml)")
        return p

    p = with_target(sub.add_parser("validate", help="check a target profile"))
    p.add_argument("--profile", action="append")
    p.set_defaults(fn=cmd_validate)

    p = with_target(sub.add_parser("target-info", help="what a static target must register"))
    p.add_argument("--json", action="store_true", help="print the setup-hook context as JSON")
    p.add_argument("--out", help="where to write the generated keys (default: out/target-info)")
    p.set_defaults(fn=cmd_target_info)

    p = with_target(sub.add_parser("keygen", help="create a static target's fixed key files"))
    p.set_defaults(fn=cmd_keygen)

    for name, fn, helptext in (("up", cmd_up, "start managed services"), ("down", cmd_down, "stop them")):
        p = with_target(sub.add_parser(name, help=helptext))
        p.add_argument("--compose", type=Path, default=DEFAULT_COMPOSE)
        if name == "down":
            p.add_argument("--volumes", action="store_true", help="also remove volumes")
        p.set_defaults(fn=fn)

    p = with_target(sub.add_parser("run", help="run the selected test profiles"))
    p.add_argument("--profile", action="append", help="run only this profile (repeatable)")
    p.add_argument("--module", action="append", help="only modules/checks containing this text")
    p.add_argument("--out", help="output directory (default: report.out_dir)")
    p.add_argument("--fail-on", choices=["regression", "any-failure", "never"], help="override report.fail_on")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("report", help="regenerate reports from results.json")
    p.add_argument("run_dir")
    p.add_argument("--baseline", help="baseline directory to re-apply")
    p.set_defaults(fn=cmd_report)

    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        return args.fn(args)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
