"""Per-run state shared by all profiles."""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import cached_property
from pathlib import Path
from typing import Any

from ..config import LoadedTarget, TargetProfile
from ..suite.client import SuiteClient
from .pki import KeyPair, RunPki, keypair_from_jwk

log = logging.getLogger("vcit")


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


@dataclass
class RunKeys:
    """Every key the run uses. Made before the setup hook, which may need to register them."""

    pki: RunPki
    clients: list[KeyPair]  # the suite's client and client2 at the issuer
    wallet_client: KeyPair  # Wallet2's client at the issuer
    attester: KeyPair  # signs wallet attestations in the HAIP VCI plan
    suite_signer: KeyPair  # signs the PID the suite presents to verifiers

    @classmethod
    def create(cls, target: TargetProfile, directory: Path, run_id: str) -> "RunKeys":
        if target.pki:
            pki = RunPki.load(directory, target.path(target.pki.ca_cert_file), target.path(target.pki.ca_key_file))
        else:
            pki = RunPki.create(directory, common_name=f"vcit test CA {run_id}")

        def client(name: str, spec) -> KeyPair:
            if spec is not None and spec.jwk_file:
                return keypair_from_jwk(name, json.loads(target.path(spec.jwk_file).read_text()))
            return pki.self_signed(name, f"vcit {name}")

        specs = target.issuer.clients if target.issuer else []
        return cls(
            pki=pki,
            clients=[client(f"client{i + 1}", specs[i] if i < len(specs) else None) for i in range(2)],
            wallet_client=client("wallet-client", target.issuer.wallet_client if target.issuer else None),
            attester=pki.issue("attester", "vcit wallet attester"),
            suite_signer=pki.issue("suite-pid-issuer", "vcit PID issuer"),
        )


@dataclass
class RunContext:
    loaded: LoadedTarget
    run_id: str
    out_dir: Path
    facts: dict[str, Any] = field(default_factory=dict)  # discovered values, e.g. issuer metadata
    setup_output: dict[str, Any] = field(default_factory=dict)

    @property
    def target(self) -> TargetProfile:
        return self.loaded.model

    @property
    def artifacts(self) -> Path:
        p = self.out_dir / "artifacts"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def alias(self, profile_id: str) -> str:
        """Fixed per test profile, so static targets can register the suite callback once."""
        return f"{self.target.suite.alias_prefix}-{profile_id}"

    def suite_callback(self, profile_id: str) -> str:
        return f"{self.target.suite.url}/test/a/{self.alias(profile_id)}/callback"

    @cached_property
    def keys(self) -> RunKeys:
        return RunKeys.create(self.target, self.artifacts / "pki", self.run_id)

    @cached_property
    def suite(self) -> SuiteClient:
        return SuiteClient(self.target.suite.url, self.target.suite.token)

    @cached_property
    def issuer(self):
        from ..target.issuer import Issuer

        return Issuer(self)

    @cached_property
    def verifier(self):
        from ..target.verifier import Verifier

        return Verifier(self)

    @cached_property
    def wallet(self):
        from ..wallets.waltid import Wallet2Client

        return Wallet2Client(self.target.wallet.url)

    @cached_property
    def browser(self):
        from ..browser.login import Browser

        return Browser(self.artifacts)

    def close(self) -> None:
        for attr in ("browser", "suite", "wallet", "issuer", "verifier"):
            if attr in self.__dict__:
                try:
                    self.__dict__[attr].close()
                except Exception:  # best effort on shutdown
                    log.debug("closing %s failed", attr, exc_info=True)
