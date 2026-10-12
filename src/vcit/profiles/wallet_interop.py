"""Real-wallet interop: walt.id Wallet2 against the target, issuance then presentation.

Wallet2 gets a credential from the issuer with the authorization-code flow, then presents it
to the verifier (the target's `start_presentation.wallet` trigger). Each step is its own case
in the report; a step that cannot run because an earlier one failed is SKIPPED, so the first
failure is the one that counts.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from ..browser.login import LoginError
from ..constants import WALLET_REDIRECT_URI
from ..core.model import Case, ProfileResult, Step
from ..core.pki import b64url_decode, decode_jwt
from ..target.issuer import IssuerError
from ..target.verifier import VerifierError
from ..wallets import waltid_config
from ..wallets.waltid import WalletError, find_sd_jwt
from .base import Profile

log = logging.getLogger(__name__)


class Blocked(Exception):
    """A step's outcome makes the following steps meaningless."""


def disclosed_claims(sd_jwt: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """(issuer-signed payload, {claim: value} from the disclosures)."""
    parts = sd_jwt.split("~")
    _, payload = decode_jwt(parts[0])
    claims: dict[str, Any] = {}
    for d in parts[1:]:
        if not d or d.count(".") == 2:  # empty tail or a KB-JWT
            continue
        item = json.loads(b64url_decode(d))
        if len(item) == 3:
            claims[item[1]] = item[2]
    return payload, claims


class WalletInteropProfile(Profile):
    id = "wallet-interop"
    title = "Wallet interop (walt.id Wallet2)"
    kind = "wallet"

    def provision(self) -> None:
        self.ctx.issuer.login()
        self.ctx.issuer.wallet_client()
        self._configure_wallet_trust()

    def _configure_wallet_trust(self) -> None:
        w = self.ctx.target.wallet
        anchor = self.ctx.verifier.trust_anchor_pem("wallet", required=True)
        if w.mode != "managed":
            log.warning("wallet.mode is external: make sure Wallet2 trusts the verifier's request certificate and TLS")
            return
        hosts = {self.ctx.issuer.credential_issuer}
        try:
            _, chain = self.ctx.verifier.request_certificate("wallet")
        except VerifierError:
            chain = []
        tls = []
        for url in hosts:
            try:
                tls.append(waltid_config.server_certificate(url))
            except (OSError, ValueError) as e:
                log.info("could not read the TLS certificate of %s: %s", url, e)
        waltid_config.render([anchor] if anchor else [], sorted(set(tls)), w.image)
        waltid_config.restart_managed(w.url)
        log.info("Wallet2 restarted trusting the verifier's request certificate (%d in chain)", len(chain))

    # -- run ------------------------------------------------------------------------------

    def run(self) -> ProfileResult:
        result = self.new_result()
        self.state: dict[str, Any] = {}
        checks: list[tuple[str, Callable[[Case], None]]] = [
            ("wallet.setup", self._setup),
            ("issuance.authorization-url", self._authorization_url),
            ("issuance.login", self._login),
            ("issuance.credential", self._credential),
            ("issuance.stored-credential", self._stored),
            ("presentation.request", self._request),
            ("presentation.submit", self._submit),
            ("presentation.verified", self._verified),
        ]
        # Steps depend on every step before them: with a module filter, run up to the last match.
        wanted = [i for i, (cid, _) in enumerate(checks) if self.ctx.target.modules.matches(cid)]
        checks = checks[: max(wanted) + 1] if wanted else []
        blocked: str | None = None
        for case_id, fn in checks:
            case = Case(id=case_id, status="PASSED")
            started = time.monotonic()
            if blocked:
                case.status = "SKIPPED"
                case.error = f"blocked by {blocked}"
            else:
                try:
                    fn(case)
                except (WalletError, LoginError, Blocked, IssuerError, VerifierError, RuntimeError, KeyError, ValueError) as e:
                    case.status = "FAILED"
                    case.error = f"{type(e).__name__}: {e}"
                    shot = getattr(e, "screenshot", None)
                    if shot:
                        case.steps.append(Step("browser", "FAILED", str(e), screenshots=[shot]))
                    blocked = case_id
                finally:
                    self._flush_http(case)
            case.duration_s = round(time.monotonic() - started, 1)
            result.cases.append(case)
            log.info("%s %s -> %s", self.id, case_id, case.status)
        return result

    def _flush_http(self, case: Case) -> None:
        exchanges = self.ctx.wallet.drain()
        if exchanges:
            case.steps.append(Step("Wallet2 API calls", case.status, http=exchanges))

    def _setup(self, case: Case) -> None:
        w = self.ctx.wallet
        _, key = self.ctx.issuer.wallet_client()
        self.state["wallet_id"] = w.create_wallet()
        self.state["key_id"] = w.import_jwk(self.state["wallet_id"], key.private_jwk())
        case.steps.append(Step("wallet created; client key imported", "PASSED", f"keyId {self.state['key_id']}"))

    def _authorization_url(self, case: Case) -> None:
        client_id, _ = self.ctx.issuer.wallet_client()
        res = self.ctx.wallet.authorization_url(
            self.state["wallet_id"],
            self.ctx.issuer.credential_issuer,
            [self.ctx.target.issuer.credential_configuration_id],
            client_id,
            WALLET_REDIRECT_URI,
        )
        self.state["auth"] = res
        case.steps.append(Step("Wallet2 built the authorization request", "PASSED", res["authorizationUrl"]))

    def _login(self, case: Case) -> None:
        login = self.ctx.issuer.login()
        res = self.ctx.browser.login(
            self.state["auth"]["authorizationUrl"],
            login.username,
            login.password,
            done=lambda page: False,
            intercept=WALLET_REDIRECT_URI,
            trace_name="wallet-login",
            selectors=login.selectors,
        )
        params = parse_qs(urlparse(res.final_url).query)
        case.steps.append(Step("login at the authorization server", "PASSED", " → ".join(res.trail[-4:]),
                               screenshots=res.screenshots[-1:]))
        if "error" in params:
            raise Blocked(f"redirected with error={params['error'][0]}: {params.get('error_description', [''])[0]}")
        if "code" not in params:
            raise Blocked(f"no authorization code in redirect {res.final_url}")
        self.state["code"] = params["code"][0]

    def _credential(self, case: Case) -> None:
        meta = self.ctx.issuer.metadata
        auth = self.state["auth"]
        client_id, _ = self.ctx.issuer.wallet_client()
        body = {
            "code": self.state["code"],
            "codeVerifier": auth["codeVerifier"],
            "credentialIssuer": auth.get("credentialIssuerBaseUrl") or self.ctx.issuer.credential_issuer,
            "credentialEndpoint": meta["credential_endpoint"],
            "credentialConfigurationId": self.ctx.target.issuer.credential_configuration_id,
            "clientId": client_id,
            "redirectUri": WALLET_REDIRECT_URI,
            "keyId": self.state["key_id"],
            "useDpop": True,
        }
        if meta.get("nonce_endpoint"):
            body["nonceEndpoint"] = meta["nonce_endpoint"]
        res = self.ctx.wallet.receive_authorized(self.state["wallet_id"], body)
        ids = res.get("credentialIds") or []
        if not ids:
            raise Blocked(f"Wallet2 stored no credential (deferred: {res.get('deferredTransactionIds')})")
        self.state["credential_id"] = ids[0]

    def _stored(self, case: Case) -> None:
        stored = self.ctx.wallet.get_credential(self.state["wallet_id"], self.state["credential_id"])
        sd_jwt = find_sd_jwt(stored)
        if not sd_jwt:
            raise Blocked("stored credential is not an SD-JWT")
        payload, claims = disclosed_claims(sd_jwt)
        expected = self.ctx.target.issuer.expected_claims
        problems = [
            f"{k}: expected {v!r}, got {claims.get(k, payload.get(k))!r}"
            for k, v in expected.items()
            if claims.get(k, payload.get(k)) != v
        ]
        if "cnf" not in payload:
            problems.append("no cnf claim: the credential is not bound to the wallet key")
        case.steps.append(
            Step("issued SD-JWT VC", "FAILED" if problems else "PASSED",
                 json.dumps({"payload": payload, "disclosed": claims}, indent=2)[:4000])
        )
        if problems:
            raise ValueError("; ".join(problems))

    def _request(self, case: Case) -> None:
        p = self.ctx.verifier.start("wallet")
        self.state["presentation"] = p
        resolved = self.ctx.wallet.resolve_request(self.state["wallet_id"], p.wallet_url)
        case.steps.append(Step("Wallet2 resolved and authenticated the verifier's request", "PASSED",
                               f"client_id {resolved.get('clientId')}", http=p.exchanges))

    def _submit(self, case: Case) -> None:
        res = self.ctx.wallet.present(self.state["wallet_id"], self.state["presentation"].wallet_url)
        if not res.get("transmission_success"):
            raise Blocked(f"Wallet2 could not deliver the presentation: {json.dumps(res)[:800]}")
        case.steps.append(Step("presentation delivered", "PASSED", json.dumps(res.get("verifier_response"))[:800]))

    def _verified(self, case: Case) -> None:
        verdict = self.ctx.verifier.wait_result(self.state["presentation"].session)
        if verdict.ok is None:
            case.status = "SKIPPED"
            case.error = "the target profile defines no verifier.result poll"
            return
        if not verdict.ok:
            raise ValueError(f"verifier concluded {verdict.status}: {json.dumps(verdict.body)[:500]}")
        text = verdict.details or json.dumps(verdict.body)
        missing = [k for k, v in self.ctx.target.issuer.expected_claims.items() if json.dumps(v) not in text]
        case.steps.append(Step("verifier result", "FAILED" if missing else "PASSED", text[:4000]))
        if missing:
            raise ValueError(f"the verifier's result lacks the value(s) of {', '.join(missing)}")
