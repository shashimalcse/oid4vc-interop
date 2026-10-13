"""OpenID4VCI issuer profiles: the conformance suite acts as the wallet against the issuer."""

from __future__ import annotations

import logging
from typing import Any

from ..browser.login import LoginError
from ..constants import ATTESTER_ISSUER
from ..core.model import Step
from ..suite.runner import ModuleContext
from .base import SuiteProfile

log = logging.getLogger(__name__)

PROOF_TYPE = "jwt"


class VciBaseProfile(SuiteProfile):
    id = "vci-base"
    title = "Base VCI issuer"
    plan_name = "oid4vci-1_0-issuer-test-plan"
    defaults = {
        "fapi_profile": "vci",
        "client_auth_type": "private_key_jwt",
        "sender_constrain": "dpop",
        "fapi_request_method": "unsigned",
        "authorization_request_type": "simple",
        "vci_grant_type": "authorization_code",
        "vci_authorization_code_flow_variant": "wallet_initiated",
        "credential_format": "sd_jwt_vc",
        "vci_credential_encryption": "plain",
        "openid": "plain_oauth",
        "fapi_response_mode": "plain_response",
    }

    def provision(self) -> None:
        if self.variant.get("vci_authorization_code_flow_variant") == "issuer_initiated":
            raise ValueError(
                "issuer_initiated is not supported yet: vcit cannot obtain credential offers generically"
            )
        self.ctx.issuer.login()  # fail early if the target cannot log a user in

    def client_config(self, client_id: str, key) -> dict[str, Any]:
        cfg = self.ctx.target.issuer
        return {
            "client_id": client_id,
            "jwks": key.jwks(private=True),
            "dpop_signing_alg": "ES256",
            "scope": cfg.credential_configuration_id,
        }

    def plan_config(self) -> dict[str, Any]:
        issuer = self.ctx.issuer
        clients = issuer.suite_clients()
        config: dict[str, Any] = {
            "vci": {
                "credential_issuer_url": issuer.credential_issuer,
                "credential_configuration_id": self.ctx.target.issuer.credential_configuration_id,
                "credential_proof_type_hint": PROOF_TYPE,
            },
            "client": self.client_config(*clients[0]),
        }
        if issuer.authorization_server:  # else the suite looks for the credential issuer in authorization_servers
            config["vci"]["authorization_server"] = issuer.authorization_server
        if len(clients) > 1:  # the multiple-clients module needs a second, independent client
            config["client2"] = self.client_config(*clients[1])
        return config

    def waiting_handler(self):
        return VciWaitingHandler(self)


class VciHaipProfile(VciBaseProfile):
    id = "vci-haip"
    title = "HAIP VCI issuer"
    plan_name = "oid4vci-1_0-issuer-haip-test-plan"
    defaults = {
        "credential_format": "sd_jwt_vc",
        "vci_authorization_code_flow_variant": "wallet_initiated",
    }
    pinned = {
        "fapi_profile": "vci_haip",
        "client_auth_type": "client_attestation",
        "sender_constrain": "dpop",
        "fapi_request_method": "unsigned",
        "authorization_request_type": "simple",
        "vci_grant_type": "authorization_code",
        "openid": "plain_oauth",
        "fapi_response_mode": "plain_response",
    }
    module_timeout = 180

    def plan_config(self) -> dict[str, Any]:
        config = super().plan_config()
        for k in ("client", "client2"):
            if k in config:
                config[k].pop("jwks")  # client attestation replaces private_key_jwt
        cfg = self.ctx.target.issuer
        if cfg.credential_trust_anchor is None:
            raise ValueError("vci-haip needs issuer.credential_trust_anchor (the certificate issued credentials chain to)")
        anchor = cfg.credential_trust_anchor.read(self.ctx.target.directory)
        status_anchor = cfg.status_list_trust_anchor.read(self.ctx.target.directory) if cfg.status_list_trust_anchor else anchor
        config["client_attestation"] = {
            "issuer": ATTESTER_ISSUER,
            "attester_jwks": self.ctx.keys.attester.jwks(private=True, with_x5c=True),
        }
        config["credential"] = {"trust_anchor_pem": anchor, "status_list_trust_anchor_pem": status_anchor}
        return config


class VciWaitingHandler:
    """Drives what a WAITING VCI module asks for:

    - a front-channel URL: log in at the authorization server in a headless browser and
      follow the redirect back to the suite callback, whose page reports to the suite;
    - a screenshot placeholder (negative FAPI tests): upload the last page shown.
    """

    def __init__(self, profile: VciBaseProfile):
        self.profile = profile
        self.ctx = profile.ctx

    def __call__(self, m: ModuleContext) -> bool:
        acted = False
        for url in m.pending_urls():
            m.scratch["handled_urls"].add(url)
            self._browse(m, url)
            acted = True

        if m.scratch.get("last_screenshot"):
            for placeholder in m.pending_placeholders():
                self.ctx.suite.upload_image(m.test_id, placeholder, m.scratch["last_screenshot"])
                m.scratch["placeholders"].add(placeholder)
                m.steps.append(Step(f"uploaded screenshot to {placeholder}", "PASSED"))
                acted = True
        return acted

    def _browse(self, m: ModuleContext, url: str) -> None:
        login = self.ctx.issuer.login()
        suite_url = self.ctx.target.suite.url

        def done(page) -> bool:
            return page.url.startswith(suite_url) and page.locator("#submission_complete").count() > 0

        try:
            res = self.ctx.browser.login(
                url, login.username, login.password, done, trace_name=m.test_id, selectors=login.selectors, headers=login.headers
            )
            m.scratch["last_screenshot"] = res.screenshots[-1] if res.screenshots else None
            m.steps.append(Step("browser: login and redirect", "PASSED", res.final_url, screenshots=res.screenshots[-1:]))
        except LoginError as e:
            # Expected in negative tests: the server refuses and shows an error page. The suite decides.
            m.scratch["last_screenshot"] = e.screenshot
            m.steps.append(
                Step("browser: login and redirect", "FAILED", str(e), screenshots=[e.screenshot] if e.screenshot else [])
            )
        self.ctx.suite.mark_visited(m.test_id, url)
