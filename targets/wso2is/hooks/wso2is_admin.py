"""WSO2 Identity Server admin REST calls used by this target profile's hooks."""

from __future__ import annotations

import base64
import os
import sys
import time
from typing import Any

import httpx

# Credential claim name -> IS local claim URI, and how SCIM sets the user's value.
CLAIM_URIS = {
    "given_name": "http://wso2.org/claims/givenname",
    "family_name": "http://wso2.org/claims/lastname",
    "email": "http://wso2.org/claims/emailaddress",
}


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class ISAdmin:
    """Talks to `{IS_ADMIN_URL}`, which already carries the /t/{tenant} prefix if any."""

    def __init__(self) -> None:
        self.base = os.environ["IS_ADMIN_URL"].rstrip("/")
        self.http = httpx.Client(
            auth=(os.environ["IS_ADMIN_USER"], os.environ["IS_ADMIN_PASSWORD"]),
            verify=os.environ.get("IS_TLS_VERIFY", "false").lower() == "true",
            timeout=60,
        )

    def _req(self, method: str, path: str, ok: tuple[int, ...] = (200,), **kw: Any) -> httpx.Response:
        r = self.http.request(method, f"{self.base}{path}", **kw)
        if r.status_code not in ok:
            raise RuntimeError(f"{method} {path}: HTTP {r.status_code}: {r.text[:600]}")
        return r

    # -- OID4VCI ------------------------------------------------------------------------------

    def create_vc_template(self, identifier: str, claims: list[str]) -> dict[str, Any]:
        body = {
            "identifier": identifier,
            "displayName": identifier,
            "description": "vcit test credential",
            "format": "dc+sd-jwt",
            "expiresIn": 31536000,
            "claims": [{"name": c, "type": "LOCAL", "claimUri": CLAIM_URIS[c]} for c in claims],
        }
        return self._req("POST", "/api/server/v1/vc-templates", (201,), json=body).json()

    def delete_vc_template(self, template_id: str) -> None:
        self._req("DELETE", f"/api/server/v1/vc-templates/{template_id}", (200, 204, 404))

    def api_resource_id(self, name: str) -> str:
        """IS creates an API resource next to each VC template, asynchronously."""
        for _ in range(15):
            r = self._req("GET", "/api/server/v1/api-resources", params={"filter": f"name eq {name}"})
            res = r.json().get("apiResources") or []
            if res:
                return res[0]["id"]
            time.sleep(1)
        raise RuntimeError(f"no API resource named {name}")

    def create_app(self, name: str, callbacks: list[str], cert_pem: str) -> dict[str, str]:
        """Confidential client: private_key_jwt (ES256), PKCE S256, PAR, DPoP-bound JWT tokens."""
        callback = callbacks[0] if len(callbacks) == 1 else "regexp=(" + "|".join(callbacks) + ")"
        body = {
            "name": name,
            "templateId": "custom-application-oidc",
            "isManagementApp": False,
            "advancedConfigurations": {
                "skipLoginConsent": True,
                "skipLogoutConsent": True,
                "certificate": {"type": "PEM", "value": cert_pem},
            },
            "inboundProtocolConfiguration": {
                "oidc": {
                    "grantTypes": ["authorization_code"],
                    "callbackURLs": [callback],
                    "publicClient": False,
                    "pkce": {"mandatory": True, "supportPlainTransformAlgorithm": False},
                    # The expiry fields are mandatory in practice; without them the API NPEs.
                    "accessToken": {
                        "type": "JWT",
                        "bindingType": "DPoP",
                        "validateTokenBinding": True,
                        "userAccessTokenExpiryInSeconds": 3600,
                        "applicationAccessTokenExpiryInSeconds": 3600,
                        "revokeTokensWhenIDPSessionTerminated": False,
                    },
                    "refreshToken": {"expiryInSeconds": 86400, "renewRefreshToken": True},
                    "clientAuthentication": {
                        "tokenEndpointAuthMethod": "private_key_jwt",
                        "tokenEndpointAuthSigningAlg": "ES256",
                        "tokenEndpointAllowReusePvtKeyJwt": False,
                    },
                    "pushAuthorizationRequest": {"requirePushAuthorizationRequest": True},
                }
            },
        }
        r = self._req("POST", "/api/server/v1/applications", (201,), json=body)
        app_id = r.headers["Location"].rstrip("/").rsplit("/", 1)[-1]
        oidc = self._req("GET", f"/api/server/v1/applications/{app_id}/inbound-protocols/oidc").json()
        return {"id": app_id, "client_id": oidc["clientId"]}

    def authorize_api(self, app_id: str, resource_id: str, scope: str) -> None:
        body = {"id": resource_id, "policyIdentifier": "No Policy", "scopes": [scope]}
        self._req("POST", f"/api/server/v1/applications/{app_id}/authorized-apis", (200, 201, 409), json=body)

    def delete_app(self, app_id: str) -> None:
        self._req("DELETE", f"/api/server/v1/applications/{app_id}", (200, 204, 404))

    def create_user(self, username: str, password: str, claims: dict[str, str]) -> str:
        existing = self._req("GET", "/scim2/Users", params={"filter": f"userName eq {username}"}).json()
        for u in existing.get("Resources") or []:  # left behind by an aborted run
            self.delete_user(u["id"])
        body: dict[str, Any] = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": username,
            "password": password,
            "name": {"givenName": claims.get("given_name", ""), "familyName": claims.get("family_name", "")},
        }
        if "email" in claims:
            body["emails"] = [{"value": claims["email"], "primary": True}]
        r = self._req("POST", "/scim2/Users", (201,), json=body, headers={"Content-Type": "application/scim+json"})
        return r.json()["id"]

    def delete_user(self, user_id: str) -> None:
        self._req("DELETE", f"/scim2/Users/{user_id}", (200, 204, 404))

    def signing_cert_pem(self) -> str:
        """The certificate IS signs credentials with (its primary key, published in the JWKS)."""
        r = self._req("GET", "/oauth2/jwks")
        x5c = next((k["x5c"] for k in r.json().get("keys", []) if k.get("x5c")), None)
        if not x5c:
            raise RuntimeError("IS JWKS has no x5c")
        b64 = x5c[0]
        lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"

    # -- OID4VP -------------------------------------------------------------------------------

    def create_presentation_definition(self, identifier: str, vct: str, claims: list[str]) -> dict[str, Any]:
        body = {
            "identifier": identifier,
            "displayName": identifier,
            "description": "vcit test presentation definition",
            "credentials": [
                {"id": "credential", "type": vct, "format": "dc+sd-jwt",
                 "claims": [{"path": c, "mandatory": True} for c in claims]}
            ],
        }
        return self._req("POST", "/api/server/v1/presentation-definitions", (201,), json=body).json()

    def trust_issuer(self, definition_id: str, issuer: dict[str, str]) -> None:
        self._req(
            "PUT",
            f"/api/server/v1/presentation-definitions/{definition_id}/credentials/credential/issuer-configs",
            (200,),
            json={"issuerConfigs": [issuer]},
        )

    def delete_presentation_definition(self, definition_id: str) -> None:
        self._req("DELETE", f"/api/server/v1/presentation-definitions/{definition_id}", (200, 204, 404))


def b64_pem(pem: str) -> str:
    """The presentation-definition API takes certificates as base64 of the PEM text."""
    return base64.b64encode(pem.encode()).decode()
