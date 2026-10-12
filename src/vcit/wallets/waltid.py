"""walt.id Wallet2 (waltid/wallet-api2) REST client, authorization-code flow only.

Every call is recorded as an HttpExchange (secrets redacted, bodies truncated) so the
wallet profile can show the full trace in the report.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ..core.model import HttpExchange

_SECRET_FIELDS = {"d", "code", "codeVerifier", "accessToken", "access_token", "password", "preAuthorizedCode"}
_SD_JWT = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+~")


class WalletError(RuntimeError):
    def __init__(self, message: str, exchange: HttpExchange | None = None):
        super().__init__(message)
        self.exchange = exchange


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("***" if k in _SECRET_FIELDS else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _summary(body: Any, limit: int = 4000) -> str | None:
    if body is None:
        return None
    text = json.dumps(_redact(body), indent=2) if isinstance(body, (dict, list)) else str(body)
    return text if len(text) <= limit else text[:limit] + "\n… (truncated)"


def find_sd_jwt(value: Any) -> str | None:
    """The first SD-JWT string anywhere in a JSON structure."""
    if isinstance(value, str):
        return value if _SD_JWT.match(value) else None
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        for v in value:
            found = find_sd_jwt(v)
            if found:
                return found
    return None


class Wallet2Client:
    def __init__(self, base_url: str, timeout: float = 90):
        self.base_url = base_url.rstrip("/")
        self.http = httpx.Client(base_url=self.base_url, timeout=timeout)
        self.exchanges: list[HttpExchange] = []

    def close(self) -> None:
        self.http.close()

    def drain(self) -> list[HttpExchange]:
        out, self.exchanges = self.exchanges, []
        return out

    def _call(self, method: str, path: str, body: Any = None, expected: tuple[int, ...] = (200, 201)) -> Any:
        r = self.http.request(method, path, json=body)
        try:
            data = r.json()
        except ValueError:
            data = r.text
        ex = HttpExchange(method, f"{self.base_url}{path}", r.status_code, _summary(body), _summary(data))
        self.exchanges.append(ex)
        if r.status_code not in expected:
            detail = data if isinstance(data, str) else json.dumps(data)[:800]
            raise WalletError(f"Wallet2 {method} {path}: HTTP {r.status_code}: {detail}", ex)
        return data

    # -- wallet and keys ----------------------------------------------------------------------

    def create_wallet(self) -> str:
        return self._call("POST", "/wallet", {})["walletId"]

    def delete_wallet(self, wallet_id: str) -> None:
        self._call("DELETE", f"/wallet/{wallet_id}", expected=(200, 204, 404))

    def import_jwk(self, wallet_id: str, jwk: dict[str, Any]) -> str:
        return self._call("POST", f"/wallet/{wallet_id}/keys/import", {"key": {"type": "jwk", "jwk": jwk}})["keyId"]

    # -- OID4VCI, authorization code ------------------------------------------------------------

    def authorization_url(
        self,
        wallet_id: str,
        credential_issuer: str,
        configuration_ids: list[str],
        client_id: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        """Wallet-initiated: Wallet2 resolves metadata, pushes the request if PAR is required,
        and returns the URL to open plus the PKCE verifier.

        Wallet2 1.1.x takes the issuer and configurations as a credential offer, so vcit passes
        the offer a wallet-initiated flow is equivalent to (authorization_code grant, no
        issuer_state). The configuration's `scope` from the issuer metadata is requested.
        """
        offer = {
            "credential_issuer": credential_issuer,
            "credential_configuration_ids": configuration_ids,
            "grants": {"authorization_code": {}},
        }
        body = {"offerJson": offer, "clientId": client_id, "redirectUri": redirect_uri, "usePkce": True, "useScope": True}
        return self._call("POST", f"/wallet/{wallet_id}/credentials/receive/authorization-url", body)

    def receive_authorized(self, wallet_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", f"/wallet/{wallet_id}/credentials/receive/authorized", body)

    def import_credential(self, wallet_id: str, raw: str, label: str | None = None) -> dict[str, Any]:
        """Store a raw credential; Wallet2 binds it to the wallet key matching its cnf."""
        return self._call("POST", f"/wallet/{wallet_id}/credentials/import", {"rawCredential": raw, "label": label})

    def list_credentials(self, wallet_id: str) -> list[dict[str, Any]]:
        return self._call("GET", f"/wallet/{wallet_id}/credentials")

    def get_credential(self, wallet_id: str, credential_id: str) -> dict[str, Any]:
        return self._call("GET", f"/wallet/{wallet_id}/credentials/{credential_id}")

    # -- OID4VP -------------------------------------------------------------------------------

    def resolve_request(self, wallet_id: str, request_url: str) -> dict[str, Any]:
        return self._call("POST", f"/wallet/{wallet_id}/credentials/present/resolve-request", {"requestUrl": request_url})

    def present(self, wallet_id: str, request_url: str) -> dict[str, Any]:
        return self._call("POST", f"/wallet/{wallet_id}/credentials/present", {"requestUrl": request_url})
