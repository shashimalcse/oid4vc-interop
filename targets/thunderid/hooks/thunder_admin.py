"""ThunderID management API calls used by this target profile's hooks.

ThunderID's management APIs take a bearer token with the `system` scope. It is obtained the way
ThunderID's own integration tests do: authorization code + PKCE on the bootstrapped public CONSOLE
client, with the admin user logged in through the flow-execution API (no browser).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

DEFAULT_OU = "01900000-0000-7000-8000-000000000001"  # bootstrapped Default organization unit
SYSTEM_RESOURCE = "https://localhost:8090/mcp"         # bootstrapped System resource server


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class ThunderAdmin:
    def __init__(self) -> None:
        self.base = os.environ.get("THUNDER_URL", "https://thunder.localtest.me:8090").rstrip("/")
        self.ou = os.environ.get("THUNDER_OU_ID", DEFAULT_OU)
        self.http = httpx.Client(verify=False, timeout=60, follow_redirects=False)
        self.http.headers["Authorization"] = f"Bearer {self._admin_token()}"

    def _admin_token(self) -> str:
        user = os.environ.get("THUNDER_ADMIN_USER", "admin")
        password = os.environ.get("THUNDER_ADMIN_PASSWORD", "admin")
        redirect = f"{self.base}/console"
        verifier = _b64(secrets.token_bytes(32))
        challenge = _b64(hashlib.sha256(verifier.encode()).digest())
        r = self.http.get(f"{self.base}/oauth2/authorize", params={
            "response_type": "code", "client_id": "CONSOLE", "redirect_uri": redirect, "scope": "system",
            "state": "vcit", "resource": os.environ.get("THUNDER_SYSTEM_RESOURCE", SYSTEM_RESOURCE),
            "code_challenge": challenge, "code_challenge_method": "S256",
        })
        if r.status_code not in (302, 303, 307):
            raise RuntimeError(f"authorize: HTTP {r.status_code}: {r.text[:300]}")
        q = parse_qs(urlparse(r.headers["Location"]).query)
        auth_id, execution_id = q["authId"][0], q["executionId"][0]
        step = self._post("/flow/execute", {"executionId": execution_id})
        done = self._post("/flow/execute", {
            "executionId": execution_id, "inputs": {"username": user, "password": password},
            "action": "action_001", "challengeToken": step.get("challengeToken"),
        })
        if done.get("flowStatus") != "COMPLETE" or not done.get("assertion"):
            raise RuntimeError(f"admin login did not complete: {str(done)[:300]}")
        cb = self._post("/oauth2/auth/callback", {"authId": auth_id, "assertion": done["assertion"]})
        code = parse_qs(urlparse(cb["redirect_uri"]).query)["code"][0]
        t = self.http.post(f"{self.base}/oauth2/token", data={
            "grant_type": "authorization_code", "client_id": "CONSOLE", "code": code,
            "redirect_uri": redirect, "code_verifier": verifier,
        })
        if t.status_code != 200:
            raise RuntimeError(f"token: HTTP {t.status_code}: {t.text[:300]}")
        return t.json()["access_token"]

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        r = self.http.post(f"{self.base}{path}", json=body)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"POST {path}: HTTP {r.status_code}: {r.text[:500]}")
        return r.json() if r.content else {}

    def _delete(self, path: str) -> None:
        r = self.http.delete(f"{self.base}{path}")
        if r.status_code not in (200, 204, 404):
            raise RuntimeError(f"DELETE {path}: HTTP {r.status_code}: {r.text[:300]}")

    # -- resources ----------------------------------------------------------------------------

    def create_user(self, username: str, password: str, claims: dict[str, str]) -> str:
        body = {"ouId": self.ou, "type": "Person",
                "attributes": {"username": username, "password": password, **claims}}
        return self._post("/users", body)["id"]

    def delete_user(self, user_id: str) -> None:
        self._delete(f"/users/{user_id}")

    def create_credential_configuration(self, handle: str, vct: str, claims: list[str]) -> dict[str, Any]:
        body = {"handle": handle, "ouId": self.ou, "name": handle, "format": "dc+sd-jwt", "vct": vct,
                "claims": [{"name": c, "displayName": c} for c in claims], "validitySeconds": 86400}
        return self._post("/openid4vci/credential-configurations", body)

    def delete_credential_configuration(self, config_id: str) -> None:
        self._delete(f"/openid4vci/credential-configurations/{config_id}")

    def create_wallet_app(self, name: str, client_id: str, redirect_uris: list[str], public_jwk: dict,
                          scopes: list[str]) -> str:
        """A `wallet` template app (ThunderID issues credentials only to these): private_key_jwt,
        PKCE, PAR and DPoP-bound access tokens."""
        jwks = json.dumps({"keys": [public_jwk]})
        body = {
            "name": name, "ouId": self.ou, "type": "mobile", "template": "wallet",
            "allowedUserTypes": ["Person"],
            "inboundAuthConfig": [{"type": "oauth2", "config": {
                "clientId": client_id, "redirectUris": redirect_uris,
                "grantTypes": ["authorization_code", "refresh_token"], "responseTypes": ["code"],
                "tokenEndpointAuthMethod": "private_key_jwt",
                "certificate": {"type": "JWKS", "value": jwks},
                "pkceRequired": True, "requirePushedAuthorizationRequests": True,
                "dpopBoundAccessTokens": True, "scopes": ["openid", *scopes],
            }}],
        }
        return self._post("/applications", body)["id"]

    def delete_app(self, app_id: str) -> None:
        self._delete(f"/applications/{app_id}")

    def create_presentation_definition(self, handle: str, vct: str, claims: list[str], trust: str | None) -> str:
        body: dict[str, Any] = {"handle": handle, "ouId": self.ou, "name": handle, "vct": vct,
                                "format": "dc+sd-jwt", "mandatoryClaims": claims}
        if trust:
            body.update({"enforceTrustedIssuer": True, "trustedAuthorities": [trust]})
        return self._post("/openid4vp/presentation-definitions", body)["id"]

    def delete_presentation_definition(self, definition_id: str) -> None:
        self._delete(f"/openid4vp/presentation-definitions/{definition_id}")
