from __future__ import annotations

import base64
import json

import pytest

from vcit.config import ConfigError
from vcit.core.pki import b64url
from vcit.profiles import profile_class
from vcit.profiles.vci import VciBaseProfile, VciHaipProfile
from vcit.profiles.vp import VpBaseProfile, VpHaipProfile
from vcit.profiles.wallet_interop import disclosed_claims


def test_registry_covers_every_profile_id():
    from vcit.config import PROFILE_IDS

    for pid in PROFILE_IDS:
        assert profile_class(pid).id == pid


def test_base_variant_defaults_and_override():
    v = VciBaseProfile.effective_variant({"credential_format": "mdoc"})
    assert v["credential_format"] == "mdoc" and v["client_auth_type"] == "private_key_jwt"


def test_unknown_variant_rejected():
    with pytest.raises(ConfigError, match="unknown variant"):
        VciBaseProfile.effective_variant({"nonsense": "x"})


def test_pinned_variant_cannot_change():
    with pytest.raises(ConfigError, match="pinned"):
        VciHaipProfile.effective_variant({"client_auth_type": "private_key_jwt"})
    # Restating a pinned value is fine.
    assert VciHaipProfile.effective_variant({"client_auth_type": "client_attestation"})["fapi_profile"] == "vci_haip"


def test_vp_base_is_explicitly_plain_vp():
    # The suite defaults vp_profile to haip; the base profile must not inherit that.
    assert VpBaseProfile.effective_variant({})["vp_profile"] == "plain_vp"
    v = VpHaipProfile.effective_variant({})
    assert v["client_id_prefix"] == "x509_hash" and v["request_method"] == "request_uri_signed"


def _disclosure(name, value):
    return b64url(json.dumps(["salt", name, value]).encode())


def test_disclosed_claims():
    header = b64url(json.dumps({"alg": "ES256"}).encode())
    payload = b64url(json.dumps({"vct": "x", "iss": "https://is", "cnf": {"jwk": {}}}).encode())
    sd_jwt = f"{header}.{payload}.sig~{_disclosure('given_name', 'Ada')}~{_disclosure('email', 'a@x')}~"
    p, claims = disclosed_claims(sd_jwt)
    assert p["vct"] == "x" and claims == {"given_name": "Ada", "email": "a@x"}


def test_find_sd_jwt_nested():
    from vcit.wallets.waltid import find_sd_jwt

    token = "aaa.bbb.ccc~ddd~"
    assert find_sd_jwt({"credential": {"raw": [1, {"data": token}]}}) == token
    assert find_sd_jwt({"x": "aaa.bbb.ccc"}) is None


def test_wallet_redaction():
    from vcit.wallets.waltid import _summary

    text = _summary({"key": {"jwk": {"kty": "EC", "d": "secret"}}, "code": "abc", "clientId": "c"})
    assert "secret" not in text and "abc" not in text and '"clientId": "c"' in text


def test_b64_pem_for_issuer_config():
    pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
    assert base64.b64decode(base64.b64encode(pem.encode())).decode() == pem


def test_issued_sd_jwt_vc_round_trip(tmp_path):
    import hashlib

    from vcit.core.pki import RunPki, decode_jwt, load_cert
    from vcit.core.sdjwt import issue_sd_jwt_vc

    pki = RunPki.create(tmp_path, "ca")
    signer = pki.issue("signer", "signer")
    holder = pki.self_signed("holder", "holder")
    sd_jwt = issue_sd_jwt_vc(signer, holder.public_jwk(), "urn:eudi:pid:1", {"given_name": "Erika"}, "https://iss")
    payload, claims = disclosed_claims(sd_jwt)
    assert claims == {"given_name": "Erika"} and payload["_sd_alg"] == "sha-256"
    assert payload["cnf"]["jwk"]["x"] == holder.public_jwk()["x"] and "d" not in payload["cnf"]["jwk"]
    disclosure = sd_jwt.split("~")[1]
    assert b64url(hashlib.sha256(disclosure.encode()).digest()) in payload["_sd"]
    header, _ = decode_jwt(sd_jwt.split("~")[0])
    assert header["typ"] == "dc+sd-jwt" and load_cert(header["x5c"][0]) == signer.cert
    # signature verifies with the signer's public key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from vcit.core.pki import b64url_decode

    h, p, sig = sd_jwt.split("~")[0].split(".")
    raw = b64url_decode(sig)
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    signer.cert.public_key().verify(der, f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256()))
