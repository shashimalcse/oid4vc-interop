from __future__ import annotations

import json

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from vcit.core.pki import RunPki, b64url, decode_jwt, load_cert, x509_hash


def test_issued_leaf_chains_to_ca_and_excludes_anchor(tmp_path):
    pki = RunPki.create(tmp_path, "test CA")
    leaf = pki.issue("signer", "signer", san_dns=["verifier.example"])
    leaf.cert.verify_directly_issued_by(pki.ca.cert)
    jwk = leaf.private_jwk(with_x5c=True)
    assert len(jwk["x5c"]) == 1  # HAIP: the trust anchor is never in x5c
    assert load_cert(jwk["x5c"][0]) == leaf.cert
    san = leaf.cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == ["verifier.example"]
    ca_bc = pki.ca.cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert ca_bc.ca and not leaf.cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert (tmp_path / "signer.crt").exists() and (tmp_path / "ca.crt").exists()


def test_jwk_round_trip(tmp_path):
    kp = RunPki.create(tmp_path, "ca").self_signed("client", "client")
    jwk = kp.private_jwk()
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256" and jwk["kid"] == "client-es256" and "d" in jwk
    pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(__import__("vcit.core.pki", fromlist=["b64url_decode"]).b64url_decode(jwk["x"]), "big"),
        int.from_bytes(__import__("vcit.core.pki", fromlist=["b64url_decode"]).b64url_decode(jwk["y"]), "big"),
        ec.SECP256R1(),
    )
    assert pub == kp.key.public_key().public_numbers()
    assert "d" not in kp.jwks(private=False)["keys"][0]


def test_decode_jwt_and_x509_hash(tmp_path):
    token = ".".join(
        [b64url(json.dumps({"alg": "none"}).encode()), b64url(json.dumps({"a": 1}).encode()), ""]
    )
    assert decode_jwt(token) == ({"alg": "none"}, {"a": 1})
    kp = RunPki.create(tmp_path, "ca").ca
    h = x509_hash(kp.cert)
    assert len(h) == 43 and "=" not in h
