"""OpenID4VP verifier profiles: the conformance suite acts as the wallet against the verifier.

For every module vcit asks the verifier for a new authorization request (the target's
`start_presentation.suite` trigger) and sends its query to the suite's authorize endpoint,
exactly what a wallet would receive from a QR code or deep link. The suite then fetches the
signed request and posts its presentation to the verifier.
"""

from __future__ import annotations

import html
import json
import logging
from typing import Any

from ..core.model import HttpExchange, Step
from ..suite.runner import ModuleContext
from .base import SuiteProfile

log = logging.getLogger(__name__)


class VpBaseProfile(SuiteProfile):
    id = "vp-base"
    title = "Base VP verifier"
    plan_name = "oid4vp-1final-verifier-test-plan"
    defaults = {
        # The suite defaults vp_profile to haip; a base run must say plain_vp explicitly.
        "vp_profile": "plain_vp",
        "credential_format": "sd_jwt_vc",
        "client_id_prefix": "x509_san_dns",
        "request_method": "request_uri_signed",
        "response_mode": "direct_post.jwt",
    }
    requires_trust_anchor = False
    module_timeout = 180

    def provision(self) -> None:
        if self.variant.get("credential_format") != "sd_jwt_vc":
            raise ValueError("only credential_format=sd_jwt_vc is supported for now")

    def plan_config(self) -> dict[str, Any]:
        verifier = self.ctx.verifier
        client: dict[str, Any] = {}
        if self.variant.get("client_id_prefix") == "x509_san_dns":
            client["client_id"] = verifier.san_dns("suite")
        anchor = verifier.trust_anchor_pem("suite", required=self.requires_trust_anchor)
        if anchor:
            client["request_object_trust_anchor_pem"] = anchor
        return {
            "credential": {"signing_jwk": self.ctx.keys.suite_signer.private_jwk(with_x5c=True)},
            "client": client,
        }

    def waiting_handler(self):
        return VpWaitingHandler(self)


class VpHaipProfile(VpBaseProfile):
    id = "vp-haip"
    title = "HAIP VP verifier"
    plan_name = "oid4vp-1final-verifier-haip-test-plan"
    defaults = {"credential_format": "sd_jwt_vc", "response_mode": "direct_post.jwt"}
    pinned = {"vp_profile": "haip", "client_id_prefix": "x509_hash", "request_method": "request_uri_signed"}
    requires_trust_anchor = True


class VpWaitingHandler:
    def __init__(self, profile: VpBaseProfile):
        self.profile = profile
        self.ctx = profile.ctx

    def __call__(self, m: ModuleContext) -> bool:
        if "presentation" not in m.scratch:
            self._start(m)
            return True
        placeholders = m.pending_placeholders()
        if placeholders:
            evidence = self._evidence(m)
            for p in placeholders:
                self.ctx.suite.upload_image(m.test_id, p, evidence)
                m.scratch["placeholders"].add(p)
            m.steps.append(Step("uploaded the verifier's result as evidence", "PASSED", screenshots=[evidence]))
            return True
        return False

    def finish(self, m: ModuleContext) -> None:
        """Record what the verifier concluded, when the target says how to ask."""
        p = m.scratch.get("presentation")
        if p is None or not self._suite_posted(m):
            return  # nothing reached the verifier: there is no verdict to wait for
        verdict = self._verdict(m)
        if verdict.ok is None:
            return
        m.steps.append(
            Step(f"verifier result: {verdict.status}", "PASSED" if verdict.ok else "FAILED", json.dumps(verdict.body)[:2000])
        )

    def _suite_posted(self, m: ModuleContext) -> bool:
        """Whether the suite actually sent a presentation to the verifier's response_uri."""
        try:
            return any(e.get("src") == "CallDirectPostEndpoint" for e in self.ctx.suite.log(m.test_id))
        except Exception:
            return True  # when in doubt, ask the verifier

    def _verdict(self, m: ModuleContext):
        if "verdict" not in m.scratch:
            m.scratch["verdict"] = self.ctx.verifier.wait_result(m.scratch["presentation"].session)
        return m.scratch["verdict"]

    def _start(self, m: ModuleContext) -> None:
        authorize = m.exposed.get("authorization_endpoint")
        if not authorize:
            raise RuntimeError("suite did not expose an authorization_endpoint")
        p = self.ctx.verifier.start("suite")
        m.scratch["presentation"] = p
        r = self.ctx.suite.http.get(f"{authorize}?{p.query}")
        m.steps.append(
            Step(
                "sent the verifier's request to the suite (as a wallet)",
                "PASSED" if r.status_code < 400 else "FAILED",
                p.wallet_url,
                http=p.exchanges + [HttpExchange("GET", f"{authorize}?{p.query}", r.status_code, None, r.text[:2000])],
            )
        )

    def _evidence(self, m: ModuleContext) -> str:
        verdict = self._verdict(m)
        body = (
            "<html><body style='font:14px sans-serif;padding:16px'><h3>Verifier result</h3>"
            f"<pre>{html.escape(json.dumps({'status': verdict.status, 'response': verdict.body}, indent=2))}</pre>"
            "</body></html>"
            if verdict.ok is not None
            else "<html><body style='font:14px sans-serif;padding:16px'><h3>Presentation delivered</h3>"
            "<p>The target profile defines no result poll, so the verifier's verdict is not available.</p></body></html>"
        )
        return self.ctx.browser.render(body)
