"""One interface over the wallets vcit can drive, so wallet profiles run against each in turn."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx

from ..config.schema import WalletConfig
from ..core.model import HttpExchange
from . import waltid_config
from .waltid import Wallet2Client, WalletError

log = logging.getLogger(__name__)


@dataclass
class Resolved:
    client_id: str | None
    detail: str


@dataclass
class Presented:
    ok: bool
    detail: str
    verifier_status: int | None = None
    verifier_body: str | None = None


class WalletDriver(ABC):
    def __init__(self, cfg: WalletConfig):
        self.cfg = cfg

    @property
    def name(self) -> str:
        return self.cfg.type

    @abstractmethod
    def health(self) -> None: ...

    @abstractmethod
    def configure_trust(self, anchors: list[str], tls_certs: list[str]) -> None:
        """Trust these request-signing anchors (and TLS certificates, where the wallet needs it)."""

    @abstractmethod
    def create_wallet(self) -> str: ...

    @abstractmethod
    def import_key(self, wallet_id: str, private_jwk: dict[str, Any]) -> str: ...

    @abstractmethod
    def import_credential(self, wallet_id: str, raw: str) -> str: ...

    @abstractmethod
    def resolve_request(self, wallet_id: str, request_url: str) -> Resolved: ...

    @abstractmethod
    def present(self, wallet_id: str, request_url: str) -> Presented: ...

    @abstractmethod
    def drain(self) -> list[HttpExchange]: ...

    def close(self) -> None:
        pass


class Wallet2Driver(WalletDriver):
    """walt.id Wallet2 (waltid/wallet-api2)."""

    def __init__(self, cfg: WalletConfig):
        super().__init__(cfg)
        self.client = Wallet2Client(cfg.url)

    def health(self) -> None:
        httpx.get(f"{self.cfg.url}/api.json", timeout=10).raise_for_status()

    def configure_trust(self, anchors: list[str], tls_certs: list[str]) -> None:
        if self.cfg.mode != "managed":
            log.warning("%s is external: make sure it trusts the verifier's request certificate", self.name)
            return
        # Wallet2 reads trust anchors only at startup: render its config, then restart it.
        waltid_config.render(anchors, tls_certs, self.cfg.image)
        waltid_config.restart_managed(self.cfg.url)

    def create_wallet(self) -> str:
        return self.client.create_wallet()

    def import_key(self, wallet_id: str, private_jwk: dict[str, Any]) -> str:
        return self.client.import_jwk(wallet_id, private_jwk)

    def import_credential(self, wallet_id: str, raw: str) -> str:
        return self.client.import_credential(wallet_id, raw, label="vcit test credential").get("id", "")

    def resolve_request(self, wallet_id: str, request_url: str) -> Resolved:
        res = self.client.resolve_request(wallet_id, request_url)
        return Resolved(res.get("clientId"), f"client_id {res.get('clientId')}")

    def present(self, wallet_id: str, request_url: str) -> Presented:
        res = self.client.present(wallet_id, request_url)
        body = res.get("verifier_response")
        return Presented(bool(res.get("transmission_success")), json.dumps(res)[:800], None,
                         json.dumps(body) if body is not None else None)

    def drain(self) -> list[HttpExchange]:
        return self.client.drain()

    def close(self) -> None:
        self.client.close()


class EudiDriver(WalletDriver):
    """vcit's HTTP wrapper around the EUDI reference library eudi-lib-jvm-openid4vp-kt (wallets/eudi)."""

    def __init__(self, cfg: WalletConfig):
        super().__init__(cfg)
        self.http = httpx.Client(base_url=cfg.url, timeout=90)
        self.exchanges: list[HttpExchange] = []

    def _call(self, path: str, body: Any) -> Any:
        r = self.http.post(path, json=body)
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
        shown = {k: ("***" if k in ("jwk", "raw") else v) for k, v in body.items()} if isinstance(body, dict) else body
        self.exchanges.append(HttpExchange("POST", f"{self.cfg.url}{path}", r.status_code,
                                           json.dumps(shown)[:2000], json.dumps(data, indent=2)[:4000]))
        for h in (data.get("http") or []) if isinstance(data, dict) else []:
            # What the wallet itself sent to and got from the verifier.
            self.exchanges.append(HttpExchange(h["method"], h["url"], h["status"], None, h["body"][:4000]))
        if r.status_code >= 400:
            raise WalletError(f"EUDI wallet {path}: HTTP {r.status_code}: {str(data)[:500]}")
        return data

    def health(self) -> None:
        self.http.get("/health").raise_for_status()

    def configure_trust(self, anchors: list[str], tls_certs: list[str]) -> None:
        # Read by the wallet on every request: no restart. TLS is not verified (test wallet).
        target = waltid_config.state_dir() / "eudi" / "anchors.pem"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(a.strip() for a in anchors) + "\n")
        if self.cfg.mode != "managed":
            log.warning("%s is external: point VCIT_TRUST_ANCHORS at %s", self.name, target)

    def create_wallet(self) -> str:
        return self._call("/wallets", {})["walletId"]

    def import_key(self, wallet_id: str, private_jwk: dict[str, Any]) -> str:
        return self._call(f"/wallets/{wallet_id}/keys", {"jwk": private_jwk})["keyId"]

    def import_credential(self, wallet_id: str, raw: str) -> str:
        return self._call(f"/wallets/{wallet_id}/credentials", {"raw": raw})["credentialId"]

    def resolve_request(self, wallet_id: str, request_url: str) -> Resolved:
        res = self._call(f"/wallets/{wallet_id}/presentations/resolve", {"requestUrl": request_url})
        if not res.get("ok"):
            raise WalletError(f"EUDI wallet rejected the request: {res.get('error')}")
        return Resolved(res.get("clientId"), f"client_id {res.get('clientId')}, {res.get('responseMode')}")

    def present(self, wallet_id: str, request_url: str) -> Presented:
        res = self._call(f"/wallets/{wallet_id}/presentations", {"requestUrl": request_url})
        detail = res.get("error") or f"{res.get('outcome')} (verifier HTTP {res.get('verifierStatus')})"
        return Presented(bool(res.get("ok")), detail, res.get("verifierStatus"), res.get("verifierBody"))

    def drain(self) -> list[HttpExchange]:
        out, self.exchanges = self.exchanges, []
        return out

    def close(self) -> None:
        self.http.close()


DRIVERS = {"waltid-wallet2": Wallet2Driver, "eudi": EudiDriver}


def make_driver(cfg: WalletConfig) -> WalletDriver:
    return DRIVERS[cfg.type](cfg)
