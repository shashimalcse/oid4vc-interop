"""A small JSONPath subset for pulling values out of verifier responses.

Supported: `$`, `.name`, `['name']`, `[0]`. That covers "where is the request URL in this
JSON", which is all a target profile needs.
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN = re.compile(r"\.([A-Za-z_][A-Za-z0-9_-]*)|\[(\d+)\]|\['([^']*)'\]|\[\"([^\"]*)\"\]")


class JsonPathError(KeyError):
    pass


def jsonpath(data: Any, expr: str) -> Any:
    expr = expr.strip()
    if not expr.startswith("$"):
        raise JsonPathError(f"JSONPath must start with $: {expr!r}")
    pos, cur = 1, data
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            raise JsonPathError(f"unsupported JSONPath syntax at {expr[pos:]!r} in {expr!r}")
        name, index, q1, q2 = m.groups()
        key = name if name is not None else (q1 if q1 is not None else q2)
        try:
            cur = cur[int(index)] if index is not None else cur[key]
        except (KeyError, IndexError, TypeError) as e:
            raise JsonPathError(f"{expr!r} does not match the response") from e
        pos = m.end()
    return cur
