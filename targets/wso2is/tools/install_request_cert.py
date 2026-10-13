"""Replace the super tenant's OID4VP request-signing key with a CA-issued one.

IS signs OpenID4VP request objects with the primary keystore's EC entry (`wso2carbon_ec` by
default) and copies that entry's certificate chain into `x5c`. The pack ships a self-signed
certificate named `carbon.super`. This tool installs a P-256 key with a certificate issued by the
given CA, with SAN DNS = the public hostname. The chain holds the leaf only, so `x5c` never
carries the trust anchor (HAIP).

    python targets/wso2is/tools/install_request_cert.py \
        --pack ~/product-is/modules/distribution/target/wso2is-7.4.0-SNAPSHOT \
        --host your-public-host.example.com \
        --ca-cert targets/wso2is/keys/test-ca.crt --ca-key targets/wso2is/keys/test-ca.key

The keystore is backed up next to itself first. Restart IS afterwards.
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


def issue(ca_cert: x509.Certificate, ca_key, host: str, days: int) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def keytool(*args: str) -> None:
    subprocess.run(["keytool", *args], check=True, capture_output=True, text=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pack", required=True, type=Path, help="IS_HOME")
    ap.add_argument("--host", required=True, help="public hostname IS advertises (SAN DNS)")
    ap.add_argument("--ca-cert", required=True, type=Path)
    ap.add_argument("--ca-key", required=True, type=Path)
    ap.add_argument("--keystore", default="repository/resources/security/wso2carbon.p12")
    ap.add_argument("--storepass", default="wso2carbon", help="keystore (and key) password")
    ap.add_argument("--alias", default="wso2carbon_ec", help="the primary keystore's EC key alias")
    ap.add_argument("--days", type=int, default=365)
    args = ap.parse_args()

    store = (args.pack / args.keystore).resolve()
    if not store.exists():
        print(f"keystore not found: {store}", file=sys.stderr)
        return 1
    ca_cert = x509.load_pem_x509_certificate(args.ca_cert.read_bytes())
    ca_key = serialization.load_pem_private_key(args.ca_key.read_bytes(), password=None)
    key, cert = issue(ca_cert, ca_key, args.host, args.days)

    backup = store.with_name(f"{store.name}.{dt.datetime.now():%Y%m%d-%H%M%S}.bak")
    shutil.copy2(store, backup)
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "entry.p12"
        # Leaf only: no CA certificates in the entry, so IS sends x5c = [leaf].
        src.write_bytes(pkcs12.serialize_key_and_certificates(
            args.alias.encode(), key, cert, None,
            serialization.BestAvailableEncryption(args.storepass.encode()),
        ))
        try:
            keytool("-delete", "-alias", args.alias, "-keystore", str(store),
                    "-storepass", args.storepass, "-storetype", "PKCS12")
        except subprocess.CalledProcessError:
            pass  # no existing entry
        keytool("-importkeystore", "-noprompt",
                "-srckeystore", str(src), "-srcstoretype", "PKCS12", "-srcstorepass", args.storepass,
                "-srcalias", args.alias,
                "-destkeystore", str(store), "-deststoretype", "PKCS12", "-deststorepass", args.storepass,
                "-destalias", args.alias, "-destkeypass", args.storepass)
        (Path(tmp) / "leaf.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"installed {args.alias}: CN={args.host}, issued by {ca_cert.subject.rfc4514_string()}")
    print(f"backup: {backup}")
    print("restart IS to load it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
