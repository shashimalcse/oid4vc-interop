"""Per-run test PKI: one EC P-256 root CA plus the leaf keys and certificates profiles need.

Everything is generated fresh for each run and written under out/<run>/artifacts/pki so a
failing run can be reproduced by hand. None of it is a secret worth protecting.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Header and payload of a compact JWS, without verifying it."""
    header, payload, *_ = token.split(".")
    return json.loads(b64url_decode(header)), json.loads(b64url_decode(payload))


def cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def cert_b64der(cert: x509.Certificate) -> str:
    """Standard base64 DER, as used in x5c."""
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def load_cert(data: str | bytes) -> x509.Certificate:
    """A certificate from PEM, or from base64 DER as found in x5c."""
    if isinstance(data, str):
        data = data.strip().encode()
    if data.startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(base64.b64decode(data))


def x509_hash(cert: x509.Certificate) -> str:
    """OpenID4VP x509_hash client identifier value: base64url SHA-256 of the leaf DER."""
    return b64url(hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest())


def _int_bytes(n: int) -> bytes:
    return n.to_bytes(32, "big")


@dataclass
class KeyPair:
    name: str
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate
    chain: list[x509.Certificate] = field(default_factory=list)  # leaf first, root excluded

    kid_override: str | None = None

    @property
    def kid(self) -> str:
        return self.kid_override or f"{self.name}-es256"

    def public_jwk(self) -> dict[str, Any]:
        nums = self.key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(_int_bytes(nums.x)),
            "y": b64url(_int_bytes(nums.y)),
            "kid": self.kid,
            "alg": "ES256",
            "use": "sig",
        }

    def private_jwk(self, with_x5c: bool = False) -> dict[str, Any]:
        jwk = self.public_jwk()
        jwk["d"] = b64url(_int_bytes(self.key.private_numbers().private_value))
        if with_x5c:
            jwk["x5c"] = [cert_b64der(c) for c in (self.chain or [self.cert])]
        return jwk

    def jwks(self, private: bool = True, with_x5c: bool = False) -> dict[str, Any]:
        return {"keys": [self.private_jwk(with_x5c) if private else self.public_jwk()]}

    @property
    def cert_pem(self) -> str:
        return cert_pem(self.cert)


@dataclass
class RunPki:
    directory: Path
    ca: KeyPair

    @classmethod
    def create(cls, directory: Path, common_name: str) -> "RunPki":
        directory.mkdir(parents=True, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        cert = (
            _builder(name, name, key.public_key(), days=30)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
            )
            .add_extension(ski, critical=False)
            .sign(key, hashes.SHA256())
        )
        pki = cls(directory=directory, ca=KeyPair("ca", key, cert))
        pki._save(pki.ca)
        return pki

    @classmethod
    def load(cls, directory: Path, cert_file: Path, key_file: Path) -> "RunPki":
        """A fixed CA from files (static targets configure trust in it once)."""
        directory.mkdir(parents=True, exist_ok=True)
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("the test CA key must be an EC key")
        pki = cls(directory=directory, ca=KeyPair("ca", key, cert))
        pki._save(pki.ca)
        return pki

    def issue(
        self,
        name: str,
        common_name: str,
        san_dns: list[str] | None = None,
        san_uri: list[str] | None = None,
        eku: list[x509.ObjectIdentifier] | None = None,
    ) -> KeyPair:
        """A CA-issued leaf. Its chain is [leaf] (the anchor stays out of x5c, as HAIP requires)."""
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        b = (
            _builder(subject, self.ca.cert.subject, key.public_key(), days=7)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca.key.public_key()), critical=False
            )
        )
        names: list[x509.GeneralName] = [x509.DNSName(d) for d in san_dns or []]
        names += [x509.UniformResourceIdentifier(u) for u in san_uri or []]
        if names:
            b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        cert = b.sign(self.ca.key, hashes.SHA256())
        kp = KeyPair(name, key, cert, chain=[cert])
        self._save(kp)
        return kp

    def self_signed(self, name: str, common_name: str) -> KeyPair:
        """A self-signed key and certificate, e.g. an OAuth client's private_key_jwt key."""
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = _builder(subject, subject, key.public_key(), days=7).sign(key, hashes.SHA256())
        kp = KeyPair(name, key, cert)
        self._save(kp)
        return kp

    def write_ca(self, cert_file: Path, key_file: Path) -> None:
        """Persist the CA so a static target can configure trust in it once."""
        cert_file.parent.mkdir(parents=True, exist_ok=True)
        cert_file.write_text(self.ca.cert_pem)
        key_file.write_bytes(
            self.ca.key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )

    @property
    def ca_pem(self) -> str:
        return self.ca.cert_pem

    def _save(self, kp: KeyPair) -> None:
        (self.directory / f"{kp.name}.crt").write_text(kp.cert_pem)
        (self.directory / f"{kp.name}.jwk.json").write_text(json.dumps(kp.private_jwk(True), indent=2))


CLIENT_AUTH_EKU = [ExtendedKeyUsageOID.CLIENT_AUTH]


def keypair_from_jwk(name: str, jwk: dict[str, Any]) -> KeyPair:
    """A KeyPair from a private EC P-256 JWK (a statically registered client key)."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" not in jwk:
        raise ValueError(f"{name}: expected a private EC P-256 JWK")
    d = int.from_bytes(b64url_decode(jwk["d"]), "big")
    key = ec.derive_private_key(d, ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = _builder(subject, subject, key.public_key(), days=7).sign(key, hashes.SHA256())
    kp = KeyPair(name, key, cert)
    kp.kid_override = jwk.get("kid")
    return kp


def _builder(subject: x509.Name, issuer: x509.Name, public_key, days: int) -> x509.CertificateBuilder:
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
    )
