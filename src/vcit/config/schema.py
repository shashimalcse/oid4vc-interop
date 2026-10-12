"""Target profile schema: one `target.yaml` describes a system under test and how to run it.

A target has an `issuer` (OpenID4VCI) and/or a `verifier` (OpenID4VP) section, optional
setup/teardown hooks that provision it, and run options (which test profiles, suite, wallet,
report). Nothing in here is specific to any product.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PROFILE_IDS = ("vci-base", "vci-haip", "vp-base", "vp-haip", "wallet-vp", "wallet-interop")
ProfileId = Literal["vci-base", "vci-haip", "vp-base", "vp-haip", "wallet-vp", "wallet-interop"]

class ConfigError(ValueError):
    pass


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# -- building blocks ------------------------------------------------------------------------


class BasicAuth(_Model):
    username: str
    password: str


class HttpRequest(_Model):
    """An HTTP call. String fields may use {{ session }} / {{ run_id }} at call time."""

    method: str = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: Any = Field(None, alias="json")
    form: dict[str, str] | None = None
    auth: BasicAuth | None = None
    verify: bool = False

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class BrowserTrigger(_Model):
    """Open a page and read the openid4vp:// request from a link (or any attribute)."""

    url: str
    selector: str = "a[href^='openid4vp://']"
    attribute: str = "href"


class PresentationTrigger(_Model):
    """How to make a verifier produce an authorization request (what a QR code would carry).

    Exactly one of http / command / browser. `wallet_url` and `session` are JSONPath
    expressions into the HTTP response or the command's JSON output. A command that prints a
    bare URL needs neither.
    """

    http: HttpRequest | None = None
    command: list[str] | None = None
    browser: BrowserTrigger | None = None
    wallet_url: str = "$.wallet_url"
    session: str | None = None

    @model_validator(mode="after")
    def _one_kind(self) -> "PresentationTrigger":
        kinds = [k for k in ("http", "command", "browser") if getattr(self, k) is not None]
        if len(kinds) != 1:
            raise ValueError("a presentation trigger needs exactly one of: http, command, browser")
        return self


class ResultPoll(_Model):
    """Optional: ask the verifier what it concluded about a presentation."""

    http: HttpRequest
    status: str  # JSONPath to the status value
    success: list[str]
    pending: list[str] = Field(default_factory=list)
    details: HttpRequest | None = None  # fetched after success; claim values are looked for here
    timeout: float = 30


class LoginSelectors(_Model):
    username: list[str] | None = None
    password: list[str] | None = None
    submit: list[str] | None = None
    consent: list[str] | None = None


class Login(_Model):
    """Credentials for the issuer's login page; the form filler is generic."""

    username: str
    password: str
    selectors: LoginSelectors = LoginSelectors()


class ClientSpec(_Model):
    """An OAuth client registered at the issuer for private_key_jwt.

    `jwk_file` holds the private key for a statically registered client. Without it vcit
    generates a key per run and hands the public half to the setup hook to register.
    """

    client_id: str
    jwk_file: Path | None = None


class Pem(_Model):
    """A PEM given inline or as a file."""

    pem: str | None = None
    file: Path | None = None

    @model_validator(mode="after")
    def _one(self) -> "Pem":
        if (self.pem is None) == (self.file is None):
            raise ValueError("give exactly one of pem or file")
        return self

    def read(self) -> str:
        return self.pem if self.pem is not None else Path(self.file).read_text()  # type: ignore[arg-type]


# -- issuer / verifier ----------------------------------------------------------------------


class IssuerConfig(_Model):
    credential_issuer: str
    credential_configuration_id: str
    clients: list[ClientSpec] = Field(default_factory=list, max_length=2)  # suite: client, client2
    wallet_client: ClientSpec | None = None  # Wallet2's client for wallet-interop
    login: Login | None = None
    expected_claims: dict[str, Any] = Field(default_factory=dict)
    # Certificates the suite uses to check issued credentials (required by the HAIP plan).
    credential_trust_anchor: Pem | None = None
    status_list_trust_anchor: Pem | None = None
    tls_verify: bool = False

    @field_validator("credential_issuer")
    @classmethod
    def _strip_issuer(cls, v: str) -> str:
        return v.rstrip("/")


class VerifierConfig(_Model):
    # `suite`: request for the test PID (presented by the conformance suite in vp-*, and by
    # Wallet2 in wallet-vp); `wallet`: request for the issuer's credential that Wallet2 holds
    # after wallet-interop issuance.
    start_presentation: dict[Literal["suite", "wallet"], PresentationTrigger]
    result: ResultPoll | None = None
    # CA of the certificate the verifier signs requests with; derived from x5c when omitted.
    request_trust_anchor: Pem | None = None
    # client_id value for x509_san_dns; derived from the request certificate when omitted.
    client_id: str | None = None


class Hooks(_Model):
    setup: list[str] | None = None
    teardown: list[str] | None = None
    timeout: float = 300


class PkiConfig(_Model):
    """A fixed test CA for static targets, so the verifier's trust is configured once."""

    ca_cert_file: Path
    ca_key_file: Path


# -- run options --------------------------------------------------------------------------


class SuiteConfig(_Model):
    mode: Literal["external", "managed"] = "managed"
    url: str = "https://localhost.emobix.co.uk:8443"
    token: str | None = None
    image_tag: str = "latest"
    alias_prefix: str = Field("vcit", pattern=r"^[a-z][a-z0-9-]{0,20}$")

    @field_validator("url")
    @classmethod
    def _strip_url(cls, v: str) -> str:
        return v.rstrip("/")


class WalletConfig(_Model):
    type: Literal["waltid-wallet2"] = "waltid-wallet2"
    mode: Literal["external", "managed"] = "managed"
    url: str = "http://localhost:7006"
    image: str = "waltid/wallet-api2:1.1.1"

    @field_validator("url")
    @classmethod
    def _strip_url(cls, v: str) -> str:
        return v.rstrip("/")


class ProfileSelection(_Model):
    id: ProfileId
    variants: dict[str, str] = Field(default_factory=dict)


class ModuleFilter(_Model):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)

    def matches(self, name: str) -> bool:
        if self.include and not any(s in name for s in self.include):
            return False
        return not any(s in name for s in self.exclude)


class ReportConfig(_Model):
    out_dir: Path = Path("out")
    fail_on: Literal["regression", "any-failure", "never"] = "regression"


NEEDS_ISSUER = {"vci-base", "vci-haip", "wallet-interop"}
NEEDS_VERIFIER = {"vp-base", "vp-haip", "wallet-vp", "wallet-interop"}
WALLET_PROFILES = {"wallet-vp", "wallet-interop"}


class TargetProfile(_Model):
    name: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    description: str = ""
    env_files: list[Path] = Field(default_factory=list)  # loaded if present, before ${ENV} substitution
    issuer: IssuerConfig | None = None
    verifier: VerifierConfig | None = None
    hooks: Hooks = Hooks()
    pki: PkiConfig | None = None
    baseline_dir: Path = Path("baseline")
    profiles: list[ProfileSelection]
    modules: ModuleFilter = ModuleFilter()
    suite: SuiteConfig = SuiteConfig()
    wallet: WalletConfig = WalletConfig()
    report: ReportConfig = ReportConfig()

    # Set by the loader, not by the file.
    directory: Path = Field(default=Path("."), exclude=True)

    @field_validator("profiles", mode="before")
    @classmethod
    def _normalise_profiles(cls, v: Any) -> Any:
        if not isinstance(v, list) or not v:
            raise ValueError("at least one profile must be selected")
        return [{"id": p} if isinstance(p, str) else p for p in v]

    @model_validator(mode="after")
    def _consistent(self) -> "TargetProfile":
        ids = [p.id for p in self.profiles]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"profiles listed more than once: {', '.join(dupes)}")
        if set(ids) & NEEDS_ISSUER and self.issuer is None:
            raise ValueError(f"profiles {sorted(set(ids) & NEEDS_ISSUER)} need an issuer section")
        if set(ids) & NEEDS_VERIFIER and self.verifier is None:
            raise ValueError(f"profiles {sorted(set(ids) & NEEDS_VERIFIER)} need a verifier section")
        if self.verifier:
            want = {"suite"} if set(ids) & {"vp-base", "vp-haip", "wallet-vp"} else set()
            if "wallet-interop" in ids:
                want.add("wallet")
            missing = want - set(self.verifier.start_presentation)
            if missing:
                raise ValueError(f"verifier.start_presentation needs: {', '.join(sorted(missing))}")
        return self

    def profile(self, profile_id: str) -> ProfileSelection | None:
        return next((p for p in self.profiles if p.id == profile_id), None)

    def path(self, p: Path) -> Path:
        """A path from the file, relative to the target directory."""
        return p if p.is_absolute() else (self.directory / p).resolve()
