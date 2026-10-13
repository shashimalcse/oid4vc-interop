"""Hooks, triggers and JSONPath against fakes: no network, no docker."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest
import respx

from vcit.config import load_target
from vcit.core.context import RunContext
from vcit.core.hooks import HookError, run_setup, run_teardown, setup_context
from vcit.target.jsonpath import JsonPathError, jsonpath
from vcit.target.verifier import Verifier

TARGET = """
name: fake
issuer:
  credential_issuer: https://issuer.example
  credential_configuration_id: "${setup.config_id}"
  clients:
    - client_id: "${setup.client_id}"
  login: {username: u, password: p}
verifier:
  start_presentation:
    suite:
      http:
        method: POST
        url: https://verifier.example/sessions
        json: {run: "{{ run_id }}", definition: "${setup.config_id}"}
      wallet_url: $.data.links[0]
      session: $.data.id
    wallet:
      command: [python, hooks/start.py]
  result:
    http: {url: "https://verifier.example/sessions/{{ session }}"}
    status: $.state
    success: [ok]
    pending: [waiting]
    timeout: 5
hooks:
  setup: [python, hooks/setup.py]
  teardown: [python, hooks/teardown.py]
profiles: [vci-base, vp-base, wallet-interop]
"""

SETUP = """
import json, sys
ctx = json.load(sys.stdin)
print("provisioning", ctx["run_id"], file=sys.stderr)
json.dump({"config_id": "Badge", "client_id": "c1", "seen_callbacks": ctx["suite"]["callbacks"]}, sys.stdout)
"""

TEARDOWN = """
import json, sys, pathlib
payload = json.load(sys.stdin)
pathlib.Path("teardown.json").write_text(json.dumps(payload["setup"]))
"""

START = """
import json, sys
vars = json.load(sys.stdin)
print(json.dumps({"wallet_url": "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fv%2Fr%2F" + vars["run_id"]}))
"""


@pytest.fixture
def ctx(tmp_path: Path) -> RunContext:
    (tmp_path / "target.yaml").write_text(TARGET)
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    (hooks / "setup.py").write_text(SETUP)
    (hooks / "teardown.py").write_text(TEARDOWN)
    (hooks / "start.py").write_text(START)
    loaded = load_target(tmp_path, env={"PATH": "/usr/bin:/bin"})
    return RunContext(loaded, "20261012-000000-abcd", tmp_path / "out")


def test_setup_context_lists_what_to_register(ctx):
    c = setup_context(ctx)
    assert c["suite"]["callbacks"] == {"vci-base": "https://localhost.emobix.co.uk:8443/test/a/vcit-vci-base/callback"}
    assert c["wallet"]["redirect_uri"].startswith("https://")
    assert len(c["clients"]) == 2 and "d" not in c["clients"][0]["public_jwk"]
    assert "BEGIN CERTIFICATE" in c["test_ca_pem"]
    assert c["suite_credential"]["vct"] == "urn:eudi:pid:1"


def test_setup_and_teardown_hooks(ctx, tmp_path):
    out = run_setup(ctx)
    assert out["config_id"] == "Badge"
    t = ctx.loaded.resolve_setup(out)
    assert t.issuer.clients[0].client_id == "c1"
    assert "provisioning" in (ctx.artifacts / "hook-setup.stderr.log").read_text()
    run_teardown(ctx)
    assert json.loads((tmp_path / "teardown.json").read_text())["client_id"] == "c1"


def test_failing_hook_reports_stderr(ctx, tmp_path):
    (tmp_path / "hooks" / "setup.py").write_text("import sys; print('admin API said no', file=sys.stderr); sys.exit(3)")
    with pytest.raises(HookError, match="admin API said no"):
        run_setup(ctx)


def test_hook_must_print_json(ctx, tmp_path):
    (tmp_path / "hooks" / "setup.py").write_text("print('not json')")
    with pytest.raises(HookError, match="did not print JSON"):
        run_setup(ctx)


@respx.mock
def test_http_trigger_and_result_poll(ctx):
    ctx.loaded.resolve_setup(run_setup(ctx))
    start = respx.post("https://verifier.example/sessions").mock(
        return_value=httpx.Response(200, json={"data": {"id": "s-1", "links": ["openid4vp://?client_id=v&request_uri=https%3A%2F%2Fv%2Fr"]}})
    )
    respx.get("https://verifier.example/sessions/s-1").mock(
        side_effect=[httpx.Response(200, json={"state": "waiting"}), httpx.Response(200, json={"state": "ok"})]
    )
    v = Verifier(ctx)
    p = v.start("suite")
    assert p.session == "s-1" and p.param("request_uri") == "https://v/r"
    sent = json.loads(start.calls.last.request.content)
    assert sent == {"run": ctx.run_id, "definition": "Badge"}  # {{ run_id }} and ${setup.*} rendered
    verdict = v.wait_result(p.session)
    assert verdict.ok and verdict.status == "ok"


def test_command_trigger(ctx):
    p = Verifier(ctx).start("wallet")
    assert p.wallet_url.endswith(ctx.run_id) and p.session is None


def test_jsonpath():
    data = {"a": {"b": [{"c": 1}, {"d-e": 2}]}}
    assert jsonpath(data, "$.a.b[0].c") == 1
    assert jsonpath(data, "$['a']['b'][1]['d-e']") == 2
    assert jsonpath(data, "$") == data
    with pytest.raises(JsonPathError):
        jsonpath(data, "$.a.x")
    with pytest.raises(JsonPathError):
        jsonpath(data, "a.b")


def test_python_hook_uses_vcit_interpreter():
    from vcit.core.hooks import resolve_command

    assert resolve_command(["python", "x.py"]) == [sys.executable, "x.py"]
    assert resolve_command(["node", "x.js"]) == ["node", "x.js"]


@respx.mock
def test_eudi_driver_issuance_round_trip():
    from vcit.config.schema import WalletConfig
    from vcit.wallets.driver import EudiDriver

    d = EudiDriver(WalletConfig(type="eudi"))
    respx.post("http://localhost:7007/wallets/w1/issuance/authorize").mock(
        return_value=httpx.Response(200, json={"ok": True, "sessionId": "s1", "authorizationUrl": "https://as/authorize?x=1"}))
    done = respx.post("http://localhost:7007/wallets/w1/issuance/complete").mock(
        return_value=httpx.Response(200, json={"ok": True, "credentialIds": ["c1"], "credentials": ["a.b.c~d~"]}))
    iss = d.start_issuance("w1", "k", {"credential_issuer": "https://is"}, "Badge", "public-client", "https://cb")
    assert iss.authorization_url.startswith("https://as/")
    ids = d.complete_issuance("w1", iss, "https://cb?code=abc&state=st&iss=https%3A%2F%2Fas")
    sent = json.loads(done.calls.last.request.content)
    assert sent == {"sessionId": "s1", "code": "abc", "state": "st", "iss": "https://as"}
    assert ids == ["c1"] and d.credential("w1", "c1") == "a.b.c~d~"
    assert d.client_auth == "public"


def test_login_error_page_detection():
    from unittest.mock import MagicMock

    from vcit.browser.login import _looks_like_error

    for url, want in [("https://t/gate/error?errorCode=invalid_request", True),
                      ("https://wallet.vcit.invalid/cb?code=abc&state=s", False),
                      ("https://is/authenticationendpoint/oauth2_error.do?oauthErrorCode=x", True),
                      ("https://t/gate/signin?authId=1&executionId=2", False)]:
        page = MagicMock()
        page.url = url
        assert _looks_like_error(page) is want, url


@pytest.mark.parametrize("servers, configured, want", [
    (None, None, None),                                          # no list: the issuer is its own AS
    (["https://issuer.example"], None, None),                    # the issuer itself
    (["https://as.example/oauth2/token"], None, "https://as.example/oauth2/token"),
    (["https://a", "https://b"], "https://b/", "https://b"),
])
def test_authorization_server_selection(ctx, servers, configured, want):
    from vcit.target.issuer import Issuer

    issuer = Issuer(ctx)
    meta = {"credential_issuer": "https://issuer.example"}
    if servers is not None:
        meta["authorization_servers"] = servers
    issuer.__dict__["metadata"] = meta
    ctx.target.issuer.authorization_server = configured
    assert issuer.authorization_server == want


def test_authorization_server_ambiguous(ctx):
    from vcit.target.issuer import Issuer, IssuerError

    issuer = Issuer(ctx)
    issuer.__dict__["metadata"] = {"credential_issuer": "https://issuer.example",
                                   "authorization_servers": ["https://a", "https://b"]}
    with pytest.raises(IssuerError, match="issuer.authorization_server"):
        issuer.authorization_server
