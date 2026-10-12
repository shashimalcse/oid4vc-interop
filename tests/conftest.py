from __future__ import annotations

import pytest

from vcit.core.model import Case, Finding, HttpExchange, ProfileResult, RunResult, Step

# 1x1 transparent PNG
PNG = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)


def sample_run() -> RunResult:
    """A run covering every status and outcome, used by the report tests."""
    vp = ProfileResult(
        id="vp-haip",
        title="HAIP VP verifier",
        kind="suite",
        plan_name="oid4vp-1final-verifier-haip-test-plan",
        plan_id="AbCd123",
        plan_url="https://suite/plan-detail.html?plan=AbCd123",
        variant={"credential_format": "sd_jwt_vc", "response_mode": "direct_post.jwt"},
        cases=[
            Case(
                id="oid4vp-1final-verifier-happy-flow",
                status="FAILED",
                suite_test_id="t1",
                suite_log_url="https://suite/log-detail.html?log=t1",
                findings=[
                    Finding(
                        "FAILURE",
                        "VP1FinalEnsureDirectPostResponseHasRedirectUriForHaip",
                        "direct_post response has no redirect_uri",
                        ["HAIP-5.1"],
                    )
                ],
                duration_s=12.3,
            ),
            Case(
                id="oid4vp-1final-verifier-invalid-kb-jwt-signature",
                status="FAILED",
                findings=[Finding("FAILURE", "EnsureHttpStatusCodeIs4xx", "verifier returned 200 <script>")],
            ),
            Case(id="oid4vp-1final-verifier-request-uri-method-post", status="SKIPPED"),
            Case(id="oid4vp-1final-verifier-minimal-cnf-jwk", status="PASSED"),
        ],
    )
    wallet = ProfileResult(
        id="wallet-interop",
        title="Wallet interop (walt.id Wallet2)",
        kind="wallet",
        cases=[
            Case(
                id="issuance.authorize",
                status="PASSED",
                steps=[
                    Step(
                        "login at IS",
                        "PASSED",
                        "redirected with code",
                        http=[HttpExchange("GET", "https://is/oauth2/authorize?x=1", 302)],
                        screenshots=[PNG],
                    )
                ],
            ),
            Case(id="issuance.credential", status="FAILED", error="HTTP 400 invalid_proof"),
        ],
    )
    broken = ProfileResult(id="vci-haip", title="HAIP VCI issuer", kind="suite", error="SuiteError: HTTP 500")
    return RunResult(
        run_id="20261009-120000-abcd",
        started_at="2026-10-09T12:00:00+00:00",
        finished_at="2026-10-09T12:20:00+00:00",
        target={"base_url": "https://is.vcit.local:9443", "version": "7.4.0-SNAPSHOT", "tenant": "carbon.super"},
        suite={"url": "https://localhost.emobix.co.uk:8443"},
        wallet={"type": "waltid-wallet2", "image": "waltid/wallet-api2:1.1.1"},
        profiles=[vp, wallet, broken],
        config={"target": {"admin": {"username": "admin", "password": "***"}}},
    )


@pytest.fixture
def run() -> RunResult:
    return sample_run()
