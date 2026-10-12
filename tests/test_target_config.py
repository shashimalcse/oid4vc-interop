from __future__ import annotations

from pathlib import Path

import pytest

from vcit.config import ConfigError, load_target
from vcit.config.loader import lookup, substitute_setup

ROOT = Path(__file__).resolve().parents[1]

MINIMAL = """
name: demo
env_files: [local.env]
issuer:
  credential_issuer: ${ISSUER:-https://issuer.example/}
  credential_configuration_id: "${setup.config_id}"
  clients:
    - client_id: "${setup.clients.0.id}"
  login:
    username: u
    password: ${PASS}
verifier:
  start_presentation:
    suite:
      http:
        method: POST
        url: https://verifier.example/start
        auth: {username: a, password: b}
      wallet_url: $.url
profiles:
  - vci-base
  - {id: vp-base, variants: {response_mode: direct_post}}
hooks:
  setup: [python, hooks/setup.py]
"""


def target(tmp_path: Path, text: str = MINIMAL, env_file: str | None = None) -> Path:
    (tmp_path / "target.yaml").write_text(text)
    if env_file is not None:
        (tmp_path / "local.env").write_text(env_file)
    return tmp_path


def test_load_with_env_file_and_defaults(tmp_path):
    loaded = load_target(target(tmp_path, env_file="export PASS='s3cret'\n# comment\n"), env={})
    t = loaded.model
    assert t.issuer.credential_issuer == "https://issuer.example"  # trailing slash stripped
    assert t.issuer.login.password == "s3cret"
    assert t.directory == tmp_path.resolve()
    assert loaded.needs_setup_values
    assert loaded.env["PASS"] == "s3cret"


def test_process_env_overrides_env_file(tmp_path):
    loaded = load_target(target(tmp_path, env_file="PASS=file"), env={"PASS": "process"})
    assert loaded.model.issuer.login.password == "process"


def test_missing_env_is_reported(tmp_path):
    with pytest.raises(ConfigError, match="PASS"):
        load_target(target(tmp_path), env={})


def test_resolve_setup_values(tmp_path):
    loaded = load_target(target(tmp_path), env={"PASS": "x"})
    t = loaded.resolve_setup({"config_id": "Badge", "clients": [{"id": "c-1"}]})
    assert t.issuer.credential_configuration_id == "Badge"
    assert t.issuer.clients[0].client_id == "c-1"


def test_missing_setup_value_is_reported(tmp_path):
    loaded = load_target(target(tmp_path), env={"PASS": "x"})
    with pytest.raises(ConfigError, match="setup.clients.0.id"):
        loaded.resolve_setup({"config_id": "Badge"})


def test_lone_setup_reference_keeps_json_type():
    out = substitute_setup({"a": "${setup.n}", "b": "x-${setup.n}"}, {"n": 3}, set())
    assert out == {"a": 3, "b": "x-3"}
    assert lookup({"l": [{"k": "v"}]}, "l.0.k") == "v"


def test_profiles_need_their_sections(tmp_path):
    text = MINIMAL[: MINIMAL.index("verifier:")] + MINIMAL[MINIMAL.index("profiles:"):]
    with pytest.raises(ConfigError, match="verifier section"):
        load_target(target(tmp_path, text), env={"PASS": "x"})


def test_wallet_interop_needs_wallet_trigger(tmp_path):
    text = MINIMAL.replace("  - vci-base\n", "  - wallet-interop\n")
    with pytest.raises(ConfigError, match="start_presentation needs: wallet"):
        load_target(target(tmp_path, text), env={"PASS": "x"})


def test_trigger_needs_exactly_one_kind(tmp_path):
    text = MINIMAL.replace("      wallet_url: $.url", "      command: [echo, x]\n      wallet_url: $.url")
    with pytest.raises(ConfigError, match="exactly one of"):
        load_target(target(tmp_path, text), env={"PASS": "x"})


def test_unknown_key_rejected(tmp_path):
    with pytest.raises(ConfigError, match="bogus"):
        load_target(target(tmp_path, MINIMAL + "bogus: 1\n"), env={"PASS": "x"})


@pytest.mark.parametrize("name", ["example", "wso2is"])
def test_shipped_targets_are_valid(name):
    env = {
        "IS_PUBLIC_URL": "https://is.example/t/x", "IS_ADMIN_URL": "https://localhost:9443/t/x",
        "IS_ADMIN_USER": "admin@x", "IS_ADMIN_PASSWORD": "admin",
    }
    loaded = load_target(ROOT / "targets" / name, env=env)
    assert loaded.model.name == name
