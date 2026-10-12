# vcit: OpenID4VC conformance and wallet interop tests

Test any OpenID4VCI credential issuer and OpenID4VP verifier with one command, and get one HTML
report. vcit combines two kinds of evidence:

- **Spec conformance:** the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
  plays the wallet against your issuer or verifier.
- **Real-wallet interop:** real wallet stacks talk to your issuer and verifier. Each wallet you list
  runs the wallet profiles, and the report shows them side by side:
  - [walt.id Wallet2](https://docs.walt.id/community-stack/wallet2/getting-started) (`waltid-wallet2`);
  - the EUDI reference library [eudi-lib-jvm-openid4vp-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt) (`eudi`).
    It runs as a small HTTP wallet in [wallets/eudi](wallets/eudi), built by `vcit up`.

| Test profile | What runs | Against |
|---|---|---|
| `vci-base` | suite `oid4vci-1_0-issuer-test-plan` | issuer |
| `vci-haip` | suite `oid4vci-1_0-issuer-haip-test-plan` | issuer |
| `vp-base` | suite `oid4vp-1final-verifier-test-plan` (`vp_profile=plain_vp`) | verifier |
| `vp-haip` | suite `oid4vp-1final-verifier-haip-test-plan` | verifier |
| `wallet-vp` | each wallet presents a test PID (signed by the run's test CA) | verifier |
| `wallet-interop` | Wallet2: issuance, then presentation (EUDI issuance to come) | issuer + verifier |

## Target profiles

The framework holds no product-specific code. A system under test is described by a **target
profile**, a directory under `targets/`:

```
targets/<name>/
  target.yaml     issuer endpoints and clients, how to make the verifier emit a request,
                  hooks, and which test profiles to run
  baseline/       known failures, one file per test profile (vp-base.yaml, ...)
  hooks/          optional setup/teardown programs that provision the target per run
```

| Target | What it shows |
|---|---|
| [`targets/example`](targets/example/target.yaml) | A static target (no hooks). Fill in your URLs and clients. |
| [`targets/wso2is`](targets/wso2is/README.md) | A target provisioned per run by hooks calling the product's admin APIs. |

A vendor creates a target profile, records its current state as the baseline, and runs vcit in CI.
Any new failure is a regression. See [docs/target-profiles.md](docs/target-profiles.md).

## Quick start

```bash
uv venv && uv pip install -e '.[dev]'
.venv/bin/playwright install chromium
.venv/bin/vcit validate --target targets/example      # effective suite variants per profile
.venv/bin/vcit up       --target targets/example      # conformance suite (+ Wallet2) in docker
.venv/bin/vcit run      --target targets/example --profile vp-base
open out/<run-id>/report.html
```

Other commands and flags:
- `vcit keygen` creates the fixed key files a static target references.
- `vcit target-info` prints what to register at your issuer and verifier: redirect URIs, client keys, the test CA.
- `--module happy-flow` filters modules or checks.
- `--fail-on never` keeps the exit code at 0.
- `vcit report out/<run-id> --baseline targets/<name>/baseline` re-renders a report.

### Hostnames

The suite and Wallet2 run in containers, while vcit and its headless browser run on the host. The
issuer and verifier must be reachable **under the same URL from both**: a public URL (a tunnel
works), `host.docker.internal`, or a service on the `vcit_default` compose network with a matching
`/etc/hosts` entry.

## Reading the report

Each module or check gets one of these outcomes, decided by its status and the target's `baseline/<profile>.yaml`:

| Outcome | Meaning |
|---|---|
| Pass | passed (or WARNING/REVIEW) |
| Known failure | failed, and the baseline expects it; shows the reason and issue link |
| Regression | failed when it was expected to pass, or failed on a condition the baseline does not list. **Fails CI** |
| Fixed | passed although the baseline expects a failure; update the baseline |
| Skipped | the suite skipped it, or an earlier wallet step failed |

```yaml
# targets/<name>/baseline/vp-haip.yaml
cases:
  oid4vp-1final-verifier-happy-flow:
    expect: FAILED
    issue: https://github.com/example/verifier/issues/12
    reason: "direct_post response has no redirect_uri"
    conditions: [VP1FinalEnsureDirectPostResponseHasRedirectUriForHaip]   # optional; any other failing condition is a regression
  "oid4vp-1final-verifier-invalid-*": FAILED                               # globs allowed
```

## GitHub Action

```yaml
- uses: shashimalcse/oid4vc-interop@main
  with:
    target: targets/my-product        # a path in your repository
    profiles: vp-haip wallet-interop  # optional
```

The Action installs vcit and Chromium, starts the suite and Wallet2, runs the profiles, uploads
`report.html`, `results.json`, `junit.xml` and traces as the `vcit-report` artifact, and writes a
summary to the job page. See [docs/ci.md](docs/ci.md).

## Layout

```
src/vcit/
  cli.py        validate | keygen | target-info | up | down | run | report
  config/       target.yaml schema, ${ENV} and ${setup.*} substitution
  core/         run context and keys, hooks, PKI, results model, baselines
  target/       generic issuer (metadata, clients) and verifier (http/command/browser triggers, result poll)
  profiles/     vci.py (base+HAIP), vp.py (base+HAIP), wallet_interop.py
  suite/        conformance-suite API client and module runner
  wallets/      walt.id Wallet2 client and its trust configuration
  browser/      generic login-form filler (Playwright)
  report/       HTML (primary), JUnit, Markdown summary
targets/        target profiles
docker/         compose.yaml: conformance suite + Wallet2
docs/           target profiles, hooks, CI
```
