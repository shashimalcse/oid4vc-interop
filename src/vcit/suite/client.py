"""Thin synchronous client for the OpenID Foundation conformance suite REST API."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx


class SuiteError(RuntimeError):
    pass


class SuiteClient:
    def __init__(self, base_url: str, token: str | None = None, verify: bool = False, timeout: float = 60):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.base_url = base_url.rstrip("/")
        self.http = httpx.Client(base_url=self.base_url, headers=headers, verify=verify, timeout=timeout)

    def close(self) -> None:
        self.http.close()

    def _check(self, r: httpx.Response, expected: int | tuple[int, ...], label: str) -> httpx.Response:
        ok = (expected,) if isinstance(expected, int) else expected
        if r.status_code not in ok:
            raise SuiteError(f"{label}: HTTP {r.status_code}: {r.text[:500]}")
        return r

    # -- discovery ---------------------------------------------------------------------------

    def wait_until_ready(self, timeout: float = 300) -> None:
        deadline = time.monotonic() + timeout
        last: Exception | str = "no response"
        while time.monotonic() < deadline:
            try:
                r = self.http.get("/api/runner/available")
                if r.status_code == 200:
                    return
                last = f"HTTP {r.status_code}"
            except httpx.HTTPError as e:
                last = e
            time.sleep(3)
        raise SuiteError(f"conformance suite at {self.base_url} not ready after {timeout:.0f}s: {last}")

    def available_plans(self) -> list[str]:
        r = self._check(self.http.get("/api/plan/available"), 200, "list plans")
        return [p["planName"] for p in r.json()]

    def server_info(self) -> dict[str, Any]:
        r = self.http.get("/api/server")
        return r.json() if r.status_code == 200 else {}

    # -- plans and modules -------------------------------------------------------------------

    def create_plan(self, plan_name: str, config: dict[str, Any], variant: dict[str, str]) -> dict[str, Any]:
        r = self.http.post(
            "/api/plan",
            params={"planName": plan_name, "variant": json.dumps(variant)},
            json=config,
        )
        return self._check(r, 201, f"create plan {plan_name}").json()

    def create_module(self, plan_id: str, module: str, variant: dict[str, str] | None) -> str:
        params = {"test": module, "plan": plan_id}
        if variant:
            params["variant"] = json.dumps(variant)
        r = self._check(self.http.post("/api/runner", params=params), 201, f"create module {module}")
        return r.json()["id"]

    def start_module(self, test_id: str) -> None:
        self._check(self.http.post(f"/api/runner/{test_id}"), 200, f"start {test_id}")

    def stop_module(self, test_id: str) -> None:
        self.http.delete(f"/api/runner/{test_id}")

    def runner_state(self, test_id: str) -> dict[str, Any] | None:
        """Live state of a running module (status, exposed values, browser). None once it is gone."""
        r = self.http.get(f"/api/runner/{test_id}")
        return r.json() if r.status_code == 200 else None

    def wait_state(self, test_id: str, states: list[str], timeout_ms: int = 5000) -> str | None:
        try:
            r = self.http.get(
                f"/api/runner/{test_id}/wait-state",
                params={"states": ",".join(states), "timeoutMs": timeout_ms},
                timeout=timeout_ms / 1000 + 10,
            )
        except httpx.TimeoutException:
            return None
        if r.status_code == 200:
            return r.json().get("state")
        return None

    def info(self, test_id: str) -> dict[str, Any]:
        return self._check(self.http.get(f"/api/info/{test_id}"), 200, f"info {test_id}").json()

    def log(self, test_id: str) -> list[dict[str, Any]]:
        return self._check(self.http.get(f"/api/log/{test_id}"), 200, f"log {test_id}").json()

    def mark_visited(self, test_id: str, url: str) -> None:
        self.http.post(f"/api/runner/browser/{test_id}/visit", params={"url": url})

    def upload_image(self, test_id: str, placeholder: str, data_uri: str) -> None:
        r = self.http.post(
            f"/api/log/{test_id}/images/{placeholder}",
            content=data_uri,
            headers={"Content-Type": "text/plain"},
        )
        self._check(r, 200, f"upload image to {placeholder}")

    def export_plan_html(self, plan_id: str, dest: Path) -> None:
        r = self.http.get(f"/api/plan/exporthtml/{plan_id}", timeout=300)
        if r.status_code == 200:
            dest.write_bytes(r.content)

    # -- links for the report -----------------------------------------------------------------

    def log_url(self, test_id: str) -> str:
        return f"{self.base_url}/log-detail.html?log={test_id}"

    def plan_url(self, plan_id: str) -> str:
        return f"{self.base_url}/plan-detail.html?plan={plan_id}"
