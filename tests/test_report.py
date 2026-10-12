from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from vcit.core.expectations import apply_expectations, load_expectations
from vcit.core.model import RunResult
from vcit.report import render_html, render_junit, render_summary, write_reports


def _classified(run, tmp_path):
    (tmp_path / "vp-haip.yaml").write_text(
        "cases:\n  oid4vp-1final-verifier-happy-flow: {expect: FAILED, issue: 'https://github.com/wso2/product-is/issues/1', reason: 'VP-39'}\n"
    )
    apply_expectations(run, load_expectations(tmp_path))
    return run


def test_html_is_self_contained_and_escaped(run, tmp_path):
    html = render_html(_classified(run, tmp_path))
    # No external resources: every src/href is a data URI, a fragment, or a plain link.
    assert not re.search(r'<(script|link)[^>]+(src|href)="https?://', html)
    assert "&lt;script&gt;" in html  # finding message is escaped
    assert "<script>" in html  # the inline report script only
    assert html.count("<script>") == 1
    for needle in ("vp-haip", "Known failure", "Regression", "VP-39", "profile error", "data:image/png"):
        assert needle in html
    assert "***" in html


def test_junit(run, tmp_path):
    xml = render_junit(_classified(run, tmp_path))
    root = ET.fromstring(xml.split("?>", 1)[1])
    vp = next(s for s in root if s.get("name") == "vp-haip")
    assert vp.get("failures") == "1"  # invalid-kb-jwt-signature is a regression
    assert vp.get("skipped") == "2"  # known failure + skipped
    haip = next(s for s in root if s.get("name") == "vci-haip")
    assert haip.find("testcase/error") is not None


def test_summary(run, tmp_path):
    md = render_summary(_classified(run, tmp_path))
    assert "regression" in md and "| HAIP VP verifier |" in md
    assert "invalid-kb-jwt-signature" in md


def test_write_and_reload_round_trip(run, tmp_path):
    run = _classified(run, tmp_path)
    paths = write_reports(run, tmp_path / "out")
    again = RunResult.load(paths["json"])
    assert again.to_json() == run.to_json()
    assert paths["html"].stat().st_size > 5000
