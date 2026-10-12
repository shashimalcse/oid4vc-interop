"""The OpenID4VCI issuer under test, as described by the target profile."""

from __future__ import annotations

import logging
from functools import cached_property
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config.schema import IssuerConfig, Login
from ..core.pki import KeyPair

log = logging.getLogger(__name__)


class IssuerError(RuntimeError):
    pass


def metadata_urls(credential_issuer: str) -> list[str]:
    """OpenID4VCI §12.2.2 location first, then the path-appended form some issuers serve."""
    u = urlparse(credential_issuer)
    path = u.path.rstrip("/")
    spec = f"{u.scheme}://{u.netloc}/.well-known/openid-credential-issuer{path}"
    legacy = f"{credential_issuer.rstrip('/')}/.well-known/openid-credential-issuer"
    return [spec] if spec == legacy else [spec, legacy]


class Issuer:
    def __init__(self, ctx):
        self.ctx = ctx
        if ctx.target.issuer is None:
            raise IssuerError("the target profile has no issuer section")
        self.http = httpx.Client(verify=self.cfg.tls_verify, timeout=30, follow_redirects=False)

    @property
    def cfg(self) -> IssuerConfig:
        return self.ctx.target.issuer  # re-read: the model is rebuilt after the setup hook

    def close(self) -> None:
        self.http.close()

    @cached_property
    def metadata(self) -> dict[str, Any]:
        errors = []
        for i, url in enumerate(metadata_urls(self.cfg.credential_issuer)):
            try:
                r = self.http.get(url, headers={"Accept": "application/json"})
            except httpx.HTTPError as e:
                errors.append(f"{url}: {e}")
                continue
            if r.status_code == 200:
                if i > 0:
                    log.warning("issuer metadata only at %s, not at the OpenID4VCI §12.2.2 location", url)
                    self.ctx.facts["metadata_location"] = "non-standard"
                return r.json()
            errors.append(f"{url}: HTTP {r.status_code}")
        raise IssuerError("credential issuer metadata not found: " + "; ".join(errors))

    @property
    def credential_issuer(self) -> str:
        return self.metadata.get("credential_issuer") or self.cfg.credential_issuer

    def suite_clients(self) -> list[tuple[str, KeyPair]]:
        if not self.cfg.clients:
            raise IssuerError("issuer.clients is empty: register at least one client (or return it from setup)")
        return [(spec.client_id, self.ctx.keys.clients[i]) for i, spec in enumerate(self.cfg.clients)]

    def wallet_client(self) -> tuple[str, KeyPair]:
        if self.cfg.wallet_client is None:
            raise IssuerError("issuer.wallet_client is required for wallet-interop")
        return self.cfg.wallet_client.client_id, self.ctx.keys.wallet_client

    def public_client(self) -> str:
        if self.cfg.public_client is None:
            raise IssuerError("issuer.public_client is required for wallets that only use public clients (eudi)")
        return self.cfg.public_client.client_id

    def login(self) -> Login:
        if self.cfg.login is None:
            raise IssuerError("issuer.login is required: the authorization-code flow logs a user in")
        return self.cfg.login
