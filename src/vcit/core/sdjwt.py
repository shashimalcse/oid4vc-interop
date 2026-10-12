"""Minimal SD-JWT VC issuance, for giving a wallet a test credential without an issuer.

Only what a verifier test needs: flat, selectively disclosable claims, holder binding
(`cnf.jwk`), and an x5c header chaining to the run's test CA (the same trust the
conformance-suite verifier tests use).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .pki import KeyPair, b64url, cert_b64der


def _json_b64(value: Any) -> str:
    return b64url(json.dumps(value, separators=(",", ":")).encode())


def sign_es256(header: dict[str, Any], payload: dict[str, Any], key: ec.EllipticCurvePrivateKey) -> str:
    signing_input = f"{_json_b64(header)}.{_json_b64(payload)}"
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{signing_input}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def disclosure_digest(disclosure: str) -> str:
    return b64url(hashlib.sha256(disclosure.encode("ascii")).digest())


def issue_sd_jwt_vc(
    signer: KeyPair,
    holder_jwk: dict[str, Any],
    vct: str,
    claims: dict[str, Any],
    issuer: str,
    include_sd_alg: bool = True,
    lifetime_s: int = 86400,
) -> str:
    """`issuer-jwt~disclosure~...~` with every claim selectively disclosable."""
    disclosures = [_json_b64([b64url(secrets.token_bytes(16)), name, value]) for name, value in claims.items()]
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": issuer,
        "iat": now,
        "exp": now + lifetime_s,
        "vct": vct,
        "cnf": {"jwk": {k: v for k, v in holder_jwk.items() if k in ("kty", "crv", "x", "y")}},
        "_sd": sorted(disclosure_digest(d) for d in disclosures),
    }
    if include_sd_alg:
        payload["_sd_alg"] = "sha-256"
    header = {"alg": "ES256", "typ": "dc+sd-jwt", "x5c": [cert_b64der(c) for c in (signer.chain or [signer.cert])]}
    return sign_es256(header, payload, signer.key) + "~" + "~".join(disclosures) + "~"
