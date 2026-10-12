"""Render Wallet2's configuration and JVM truststore, and restart a managed Wallet2.

Wallet2 reads its x509 trust anchors (for verifying signed OID4VP requests) only from
wallet-service.conf at startup, and uses the JVM truststore for TLS. Both depend on
the target under test, so vcit writes them into the state directory that docker/compose.yaml
mounts, then restarts the container.
"""

from __future__ import annotations

import logging
import os
import shutil
import ssl
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

STORE_PASSWORD = "changeit"  # matches JAVA_TOOL_OPTIONS in docker/compose.yaml
REPO_ROOT = Path(__file__).resolve().parents[3]


def state_dir() -> Path:
    return Path(os.environ.get("VCIT_STATE_DIR") or REPO_ROOT / ".vcit")


def render(trust_anchors: list[str], tls_certs: list[str], wallet_image: str) -> Path:
    base = state_dir() / "wallet2"
    conf, trust = base / "config", base / "trust"
    conf.mkdir(parents=True, exist_ok=True)
    trust.mkdir(parents=True, exist_ok=True)

    anchors = ",\n".join(f'    """{pem.strip()}"""' for pem in trust_anchors)
    (conf / "wallet-service.conf").write_text(
        'publicBaseUrl = "http://localhost:7006"\n'
        "# Rendered by vcit. No attestationConfig: Wallet2 would prefer attestation-based\n"
        "# client authentication over private_key_jwt whenever an issuer advertises it.\n"
        "clientIdTrust {\n"
        f"  x509TrustAnchors = [\n{anchors}\n  ]\n"
        "  trustedVerifierAttestationIssuers = []\n"
        "  preRegisteredClients {}\n"
        "}\n"
    )
    # In-memory stores: every run creates its own wallet, nothing needs to persist.
    (conf / "_features.conf").write_text("enabledFeatures = []\ndisabledFeatures = [auth]\n")
    (conf / "web.conf").write_text('webHost = "0.0.0.0"\nwebPort = 7006\n')

    store = trust / "truststore.p12"
    store.unlink(missing_ok=True)
    if not tls_certs:
        # The JVM needs a readable truststore file; a placeholder keeps TLS to public CAs failing
        # loudly rather than silently, so collect the target's certificates whenever possible.
        log.warning("no TLS certificate collected; Wallet2 trusts only a placeholder certificate")
        tls_certs = [_placeholder_cert()]
    for i, pem in enumerate(tls_certs):
        (trust / f"tls-{i}.pem").write_text(pem)
        _keytool(trust, f"tls-{i}.pem", f"target-tls-{i}", wallet_image)
    return base


def ensure_default(wallet_image: str) -> None:
    """Before the first start: a valid config and truststore, so the container can boot."""
    base = state_dir() / "wallet2"
    if not (base / "config" / "wallet-service.conf").exists() or not (base / "trust" / "truststore.p12").exists():
        render([], [], wallet_image)


def _placeholder_cert() -> str:
    import tempfile

    from ..core.pki import RunPki

    with tempfile.TemporaryDirectory() as tmp:
        return RunPki.create(Path(tmp), "vcit placeholder").ca_pem


def _keytool(trust: Path, pem_name: str, alias: str, wallet_image: str) -> None:
    args = [
        "-importcert", "-noprompt", "-storetype", "PKCS12", "-storepass", STORE_PASSWORD,
        "-alias", alias, "-file", pem_name, "-keystore", "truststore.p12",
    ]
    local = shutil.which("keytool") or (
        str(Path(os.environ["JAVA_HOME"]) / "bin" / "keytool") if os.environ.get("JAVA_HOME") else None
    )
    if local and Path(local).exists():
        subprocess.run([local, *args], cwd=trust, check=True, capture_output=True)
        return
    # No local JDK: borrow keytool from the Wallet2 image (a JVM image).
    subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "keytool", "-v", f"{trust}:/w", "-w", "/w", wallet_image, *args],
        check=True,
        capture_output=True,
    )


def server_certificate(url: str) -> str:
    """The TLS leaf certificate a server presents, as PEM (no verification)."""
    u = urlparse(url)
    if not u.hostname:
        raise ValueError(f"no host in {url}")
    return ssl.get_server_certificate((u.hostname, u.port or 443))


def restart_managed(wallet_url: str, compose_file: Path | None = None, timeout: float = 120) -> None:
    compose = compose_file or REPO_ROOT / "docker" / "compose.yaml"
    subprocess.run(
        ["docker", "compose", "-f", str(compose), "-p", "vcit", "--profile", "wallet", "restart", "wallet2"],
        check=True,
        capture_output=True,
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{wallet_url}/api.json", timeout=5).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(2)
    raise RuntimeError(f"Wallet2 did not come back at {wallet_url} within {timeout:.0f}s")
