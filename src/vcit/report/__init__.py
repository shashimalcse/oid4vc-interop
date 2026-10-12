"""Report writers. The HTML report is primary; JUnit and Markdown exist for CI plumbing."""

from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree as ET

from jinja2 import Environment, PackageLoader, select_autoescape

from .. import __version__
from ..core.model import OUTCOMES, PASS_STATUSES, RunResult

LABELS = {
    "regression": "Regression",
    "fixed": "Fixed",
    "known-failure": "Known failure",
    "pass": "Pass",
    "skipped": "Skipped",
}

_env = Environment(
    loader=PackageLoader("vcit", "report/templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(run: RunResult) -> str:
    totals = run.counts()
    return _env.get_template("report.html.j2").render(
        run=run,
        totals=totals,
        outcomes=OUTCOMES,
        labels=LABELS,
        pass_statuses=PASS_STATUSES,
        profile_errors=sum(1 for p in run.profiles if p.error),
        config_json=json.dumps(run.config, indent=2),
        version=__version__,
    )


def render_junit(run: RunResult) -> str:
    suites = ET.Element("testsuites", name=f"vcit {run.run_id}")
    for p in run.profiles:
        ts = ET.SubElement(suites, "testsuite", name=p.id, tests=str(len(p.cases)))
        failures = skipped = 0
        if p.error:
            tc = ET.SubElement(ts, "testcase", classname=p.id, name="profile-setup")
            ET.SubElement(tc, "error", message=p.error[:500]).text = p.error
            failures += 1
        for c in p.cases:
            tc = ET.SubElement(ts, "testcase", classname=p.id, name=c.id, time=str(c.duration_s))
            text = "\n".join(f"{f.result} {f.condition}: {f.message}" for f in c.findings)
            if c.outcome == "regression":
                failures += 1
                ET.SubElement(tc, "failure", message=(c.outcome_note or c.status)[:500]).text = (
                    (c.error or "") + "\n" + text
                ).strip()
            elif c.outcome in ("skipped", "known-failure"):
                skipped += 1
                msg = c.status if c.outcome == "skipped" else f"known failure: {c.reason or c.status}"
                ET.SubElement(tc, "skipped", message=msg[:500])
            if c.suite_log_url:
                ET.SubElement(tc, "system-out").text = c.suite_log_url
        ts.set("failures", str(failures))
        ts.set("skipped", str(skipped))
    ET.indent(suites)
    return ET.tostring(suites, encoding="unicode", xml_declaration=True)


def render_summary(run: RunResult, html_name: str = "report.html") -> str:
    """Short Markdown for $GITHUB_STEP_SUMMARY. Full detail stays in the HTML report."""
    t = run.counts()
    lines = [
        f"## OpenID4VC interop: {'❌ ' + str(t['regression']) + ' regression(s)' if t['regression'] else '✅ no regressions'}",
        "",
        f"Target `{run.target.get('name', '?')}` · run `{run.run_id}` · full report: `{html_name}` in the run artifacts",
        "",
        "| Profile | " + " | ".join(LABELS[o] for o in OUTCOMES) + " |",
        "|---|" + "---:|" * len(OUTCOMES),
    ]
    for p in run.profiles:
        c = p.counts()
        name = p.title + (" ⚠️ setup error" if p.error else "")
        lines.append(f"| {name} | " + " | ".join(str(c[o]) for o in OUTCOMES) + " |")
    regressions = [(p, c) for p in run.profiles for c in p.cases if c.outcome == "regression"]
    if regressions:
        lines += ["", "### Regressions", ""]
        for p, c in regressions[:50]:
            lines.append(f"- **{p.id}** `{c.id}`: {c.outcome_note or c.status}")
    return "\n".join(lines) + "\n"


def write_reports(run: RunResult, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out_dir / "results.json",
        "html": out_dir / "report.html",
        "junit": out_dir / "junit.xml",
        "summary": out_dir / "summary.md",
    }
    run.save(paths["json"])
    paths["html"].write_text(render_html(run))
    paths["junit"].write_text(render_junit(run))
    paths["summary"].write_text(render_summary(run))
    return paths
