"""The framework must stay vendor-neutral: product specifics live only in targets/<product>/."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NEUTRAL = ["src", "docs", "docker", "targets/example", "action.yml", ".github", "pyproject.toml"]
VENDOR = re.compile(r"wso2|identity server|asgardeo", re.IGNORECASE)


def test_no_vendor_names_outside_target_profiles():
    offenders = []
    for entry in NEUTRAL:
        path = ROOT / entry
        files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
        for f in files:
            if "__pycache__" in f.parts or f.suffix in {".pyc", ".png", ".zip"}:
                continue
            for n, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if VENDOR.search(line):
                    offenders.append(f"{f.relative_to(ROOT)}:{n}: {line.strip()[:100]}")
    assert not offenders, "vendor names outside targets/:\n" + "\n".join(offenders)
