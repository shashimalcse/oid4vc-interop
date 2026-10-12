"""The OpenID4VP verifier under test: making it emit a request, and reading its verdict."""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from cryptography import x509

from ..config.schema import PresentationTrigger, VerifierConfig
from ..core.model import HttpExchange
from ..core.pki import cert_pem, decode_jwt, load_cert
from .http import execute
from .jsonpath import jsonpath

log = logging.getLogger(__name__)


class VerifierError(RuntimeError):
    pass


@dataclass
class Presentation:
    wallet_url: str  # openid4vp://?client_id=...&request_uri=... (what a QR code carries)
    session: str | None
    exchanges: list[HttpExchange] = field(default_factory=list)

    @property
    def query(self) -> str:
        return self.wallet_url.split("?", 1)[1] if "?" in self.wallet_url else ""

    def param(self, name: str) -> str | None:
        return parse_qs(self.query).get(name, [None])[0]


@dataclass
class Verdict:
    status: str | None
    ok: bool | None  # None when the target defines no result poll
    body: Any = None
    details: str | None = None


class Verifier:
    def __init__(self, ctx):
        self.ctx = ctx
        if ctx.target.verifier is None:
            raise VerifierError("the target profile has no verifier section")
        self._probe: tuple[x509.Certificate, list[x509.Certificate]] | None = None

    @property
    def cfg(self) -> VerifierConfig:
        return self.ctx.target.verifier

    def close(self) -> None:
        pass

    def _vars(self, **extra: Any) -> dict[str, Any]:
        return {"run_id": self.ctx.run_id, "setup": self.ctx.setup_output, **extra}

    # -- starting a presentation -------------------------------------------------------------

    def start(self, kind: str) -> Presentation:
        trigger = self.cfg.start_presentation.get(kind)  # type: ignore[call-overload]
        if trigger is None:
            raise VerifierError(f"verifier.start_presentation.{kind} is not configured")
        if trigger.http:
            return self._start_http(trigger)
        if trigger.command:
            return self._start_command(trigger)
        return self._start_browser(trigger)

    def _extract(self, trigger: PresentationTrigger, data: Any) -> tuple[str, str | None]:
        url = jsonpath(data, trigger.wallet_url)
        session = str(jsonpath(data, trigger.session)) if trigger.session else None
        if not isinstance(url, str) or "?" not in url:
            raise VerifierError(f"{trigger.wallet_url} gave {url!r}, not an authorization request URL")
        return url, session

    def _start_http(self, trigger: PresentationTrigger) -> Presentation:
        r, ex = execute(trigger.http, self._vars())  # type: ignore[arg-type]
        if r.status_code >= 400:
            raise VerifierError(f"start presentation: HTTP {r.status_code}: {r.text[:500]}")
        try:
            data = r.json()
        except ValueError as e:
            raise VerifierError(f"start presentation: response is not JSON: {r.text[:300]}") from e
        url, session = self._extract(trigger, data)
        return Presentation(url, session, [ex])

    def _start_command(self, trigger: PresentationTrigger) -> Presentation:
        from ..core.hooks import resolve_command

        proc = subprocess.run(
            resolve_command(trigger.command),  # type: ignore[arg-type]
            cwd=self.ctx.target.directory,
            env=self.ctx.loaded.env or None,
            input=json.dumps(self._vars()),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise VerifierError(f"start presentation command exited {proc.returncode}: {proc.stderr[-500:]}")
        out = proc.stdout.strip()
        if out.startswith(("openid4vp:", "https:", "haip:", "eudi-openid4vp:")):
            return Presentation(out.splitlines()[0], None)
        url, session = self._extract(trigger, json.loads(out))
        return Presentation(url, session)

    def _start_browser(self, trigger: PresentationTrigger) -> Presentation:
        b = trigger.browser
        with self.ctx.browser.page() as page:
            page.goto(b.url, wait_until="domcontentloaded")  # type: ignore[union-attr]
            el = page.wait_for_selector(b.selector, timeout=30000)  # type: ignore[union-attr]
            url = el.get_attribute(b.attribute) if el else None  # type: ignore[union-attr]
        if not url:
            raise VerifierError(f"no {b.attribute} on {b.selector} at {b.url}")  # type: ignore[union-attr]
        return Presentation(url, None)

    # -- the signed request and its certificate ------------------------------------------------

    def request_object(self, p: Presentation) -> str:
        """The request object JWT, fetched from request_uri (or inline `request`)."""
        inline = p.param("request")
        if inline:
            return inline
        uri = p.param("request_uri")
        if not uri:
            raise VerifierError(f"no request or request_uri in {p.wallet_url}")
        method = (p.param("request_uri_method") or "get").upper()
        r = httpx.request(method, uri, verify=False, timeout=30)
        r.raise_for_status()
        return r.text.strip()

    def request_certificate(self, kind: str) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Start one throwaway presentation and read the x5c of the signed request."""
        if self._probe is None:
            header, _ = decode_jwt(self.request_object(self.start(kind)))
            chain = [load_cert(c) for c in header.get("x5c") or []]
            if not chain:
                raise VerifierError("the verifier's request object has no x5c header")
            self._probe = (chain[0], chain)
        return self._probe

    def trust_anchor_pem(self, kind: str, required: bool) -> str | None:
        if self.cfg.request_trust_anchor:
            return self.cfg.request_trust_anchor.read()
        _, chain = self.request_certificate(kind)
        last = chain[-1]
        if last.issuer == last.subject:
            return cert_pem(last)  # a self-signed leaf, or a chain that includes its root
        if required:
            raise VerifierError(
                "the request certificate chain ends at a CA vcit cannot see; "
                "set verifier.request_trust_anchor in the target profile"
            )
        return None

    def san_dns(self, kind: str) -> str:
        if self.cfg.client_id:
            return self.cfg.client_id
        leaf, _ = self.request_certificate(kind)
        try:
            san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return san.value.get_values_for_type(x509.DNSName)[0]
        except (x509.ExtensionNotFound, IndexError) as e:
            raise VerifierError("request certificate has no DNS SAN; set verifier.client_id") from e

    # -- the verdict --------------------------------------------------------------------------

    def wait_result(self, session: str | None) -> Verdict:
        poll = self.cfg.result
        if poll is None or session is None:
            return Verdict(None, None)
        deadline = time.monotonic() + poll.timeout
        status, body = None, None
        while time.monotonic() < deadline:
            r, _ = execute(poll.http, self._vars(session=session))
            if r.status_code < 400:
                body = r.json()
                status = str(jsonpath(body, poll.status))
                if status not in poll.pending:
                    break
            time.sleep(1)
        ok = status in poll.success
        details = None
        if ok and poll.details is not None:
            r, _ = execute(poll.details, self._vars(session=session))
            details = r.text
        return Verdict(status, ok, body, details)
