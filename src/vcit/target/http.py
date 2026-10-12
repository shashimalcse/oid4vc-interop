"""Execute an HttpRequest from a target profile, rendering {{ ... }} templates at call time."""

from __future__ import annotations

from typing import Any

import httpx
from jinja2 import Environment, StrictUndefined

from ..config.schema import HttpRequest
from ..core.model import HttpExchange

_jinja = Environment(undefined=StrictUndefined, autoescape=False)


def render(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return _jinja.from_string(value).render(**variables) if "{{" in value else value
    if isinstance(value, dict):
        return {k: render(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, variables) for v in value]
    return value


def execute(req: HttpRequest, variables: dict[str, Any], timeout: float = 60) -> tuple[httpx.Response, HttpExchange]:
    url = render(req.url, variables)
    kwargs: dict[str, Any] = {"headers": render(req.headers, variables)}
    if req.json_body is not None:
        kwargs["json"] = render(req.json_body, variables)
    if req.form is not None:
        kwargs["data"] = render(req.form, variables)
    if req.auth is not None:
        kwargs["auth"] = (req.auth.username, req.auth.password)
    with httpx.Client(verify=req.verify, timeout=timeout) as client:
        r = client.request(req.method.upper(), url, **kwargs)
    body = kwargs.get("json") or kwargs.get("data")
    exchange = HttpExchange(
        req.method.upper(), url, r.status_code, str(body)[:2000] if body else None, r.text[:4000]
    )
    return r, exchange
