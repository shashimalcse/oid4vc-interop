"""Headless browser leg: log in at the issuer's authorization server and follow the redirect.

Used by the suite VCI profiles (the suite hands out an authorize URL and waits for its own
callback) and by the wallet profile (Wallet2 builds the authorize URL; we catch the redirect
to its redirect_uri and hand the code back). The form filler is generic; a target profile can
override the selectors.
"""

from __future__ import annotations

import base64
import logging
import re
from urllib.parse import parse_qs, urlparse
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from playwright.sync_api import Browser, Page, Playwright, sync_playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeout

log = logging.getLogger(__name__)

# Defaults that match most login forms; a target's issuer.login.selectors are tried first.
USERNAME = [
    "#usernameUserInput", "input[name=usernameUserInput]", "input#username:visible",
    "input[name=username]:visible", "input[type=email]:visible", "input[autocomplete=username]",
]
PASSWORD = ["#password", "input[name=password]", "input[type=password]:visible"]
SUBMIT = ["#sign-in-button", "#kc-login", "button[type=submit]", "input[type=submit]"]
CONSENT = ["#approve", "button[value=approve]", "input[value=Allow]", "button[name=accept]", "#consent_select_all"]


@dataclass
class Selectors:
    username: list[str]
    password: list[str]
    submit: list[str]
    consent: list[str]

    @classmethod
    def merged(cls, override=None) -> "Selectors":
        o = override
        return cls(
            username=(o.username if o and o.username else []) + USERNAME,
            password=(o.password if o and o.password else []) + PASSWORD,
            submit=(o.submit if o and o.submit else []) + SUBMIT,
            consent=(o.consent if o and o.consent else []) + CONSENT,
        )


class LoginError(RuntimeError):
    def __init__(self, message: str, screenshot: str | None = None):
        super().__init__(message)
        self.screenshot = screenshot


@dataclass
class LoginResult:
    final_url: str
    screenshots: list[str] = field(default_factory=list)
    trail: list[str] = field(default_factory=list)  # URLs navigated, for the report


def _data_uri(png: bytes) -> str:
    return "data:image/png;base64," + base64.b64encode(png).decode()


def _first(page: Page, selectors: list[str], timeout: float = 0) -> str | None:
    """The first selector with a visible match, waiting up to `timeout` ms for any of them."""
    if timeout:
        try:
            page.wait_for_selector(", ".join(selectors), state="visible", timeout=timeout)
        except PlaywrightTimeout:
            return None
    for s in selectors:
        try:
            if page.locator(s).first.is_visible():
                return s
        except Exception:  # an invalid selector for this page type
            continue
    return None


class Browser:
    """One Chromium instance for the whole run; a fresh context (no cookies) per login."""

    def __init__(self, artifacts: Path, headless: bool = True):
        self.artifacts = artifacts
        self.headless = headless
        self._pw: Playwright | None = None
        self._browser: Browser | None = None

    def _ensure(self) -> Browser:
        if self._browser is None:
            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(headless=self.headless)
        return self._browser

    def close(self) -> None:
        if self._browser:
            self._browser.close()
        if self._pw:
            self._pw.stop()
        self._browser = self._pw = None

    @contextmanager
    def page(self, trace_name: str | None = None) -> Iterator[Page]:
        context = self._ensure().new_context(ignore_https_errors=True)
        if trace_name:
            context.tracing.start(screenshots=True, snapshots=True)
        try:
            yield context.new_page()
        finally:
            if trace_name:
                context.tracing.stop(path=str(self.artifacts / f"trace-{trace_name}.zip"))
            context.close()

    def login(
        self,
        url: str,
        username: str,
        password: str,
        done: Callable[[Page], bool],
        intercept: str | None = None,
        timeout_s: float = 60,
        trace_name: str | None = None,
        selectors=None,
    ) -> LoginResult:
        """Open `url`, log in if asked, approve consent, and stop when `done(page)` is true.

        `intercept` is a URL prefix (a redirect_uri nothing listens on). Navigation to it is
        answered locally and recorded as the final URL instead of being sent to the network.
        """
        result = LoginResult(final_url=url)
        sel = Selectors.merged(selectors)
        with self.page(trace_name) as page:
            caught: list[str] = []
            if intercept:
                pattern = re.compile("^" + re.escape(intercept))

                def answer(route):
                    caught.append(route.request.url)
                    route.fulfill(status=200, content_type="text/html", body="<p>vcit: redirect captured</p>")

                page.route(pattern, answer)
            def record(frame) -> None:
                if frame == page.main_frame:
                    result.trail.append(frame.url)

            page.on("framenavigated", record)

            page.goto(url, wait_until="domcontentloaded", timeout=timeout_s * 1000)
            deadline_ms = timeout_s * 1000
            logged_in = False
            for _ in range(10):
                if caught or done(page):
                    break
                if _looks_like_error(page):
                    shot = _data_uri(page.screenshot(full_page=True))
                    raise LoginError(f"the authorization server showed an error page at {page.url}", shot)
                if not logged_in and _first(page, sel.username + sel.password, timeout=5000):
                    self._fill_login(page, username, password, sel)
                    logged_in = True
                    continue
                consent = _first(page, sel.consent)
                if consent:
                    page.click(consent)
                    page.wait_for_load_state("domcontentloaded")
                    continue
                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except PlaywrightTimeout:
                    pass
                if caught or done(page):
                    break
                if _looks_like_error(page):
                    shot = _data_uri(page.screenshot(full_page=True))
                    raise LoginError(f"the authorization server showed an error page at {page.url}", shot)
            else:
                shot = _data_uri(page.screenshot(full_page=True))
                raise LoginError(f"login flow did not finish (last URL {page.url})", shot)

            if not caught and not done(page):
                page.wait_for_timeout(min(deadline_ms, 2000))
            result.final_url = caught[0] if caught else page.url
            result.screenshots.append(_data_uri(page.screenshot(full_page=True)))
        return result

    @staticmethod
    def _fill_login(page: Page, username: str, password: str, sel: Selectors) -> None:
        user_sel = _first(page, sel.username)
        if user_sel:
            page.fill(user_sel, username)
            # Identifier-first: the password field only appears after "continue".
            if not _first(page, sel.password):
                page.click(_first(page, sel.submit) or sel.submit[-1])
                _first(page, sel.password, timeout=10000)
        pw_sel = _first(page, sel.password, timeout=5000)
        if not pw_sel:
            raise LoginError(f"no password field on {page.url}")
        page.fill(pw_sel, password)
        page.click(_first(page, sel.submit) or sel.submit[-1])
        page.wait_for_load_state("domcontentloaded")

    def render(self, html: str) -> str:
        """Render an HTML snippet to a PNG data URI (evidence images for the suite)."""
        with self.page() as page:
            page.set_viewport_size({"width": 800, "height": 600})
            page.set_content(html)
            return _data_uri(page.screenshot(full_page=True))

    def screenshot(self, url: str) -> str:
        """A screenshot of an arbitrary page (e.g. the error page a negative test expects)."""
        with self.page() as page:
            page.goto(url, wait_until="networkidle", timeout=30000)
            return _data_uri(page.screenshot(full_page=True))


_ERROR_PATHS = ("error.do", "/retry.do", "/error")


def _looks_like_error(page: Page) -> bool:
    """An authorization-server error page (not a redirect that carries a code)."""
    u = urlparse(page.url)
    params = parse_qs(u.query)
    if "code" in params:
        return False
    return "error" in params or any(h in u.path.lower() for h in _ERROR_PATHS)

