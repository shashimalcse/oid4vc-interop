# Writing a target profile

A target profile tells vcit three things:
1. where your issuer and verifier are;
2. how to make your verifier produce an authorization request;
3. optionally, how to provision your system for a run.

It uses only standard OpenID4VC interfaces plus your own HTTP calls or programs. vcit never
imports code from a target.

## `target.yaml`

```yaml
name: my-product                      # [A-Za-z0-9_.-]
description: ...
env_files: [local.env]                # optional KEY=VALUE files, loaded if present (process env wins)

issuer:                               # needed by vci-base, vci-haip, wallet-interop
  credential_issuer: https://issuer.example/oid4vci
  credential_configuration_id: EmployeeBadge
  authorization_server: https://as.example  # optional; defaults to the only entry of authorization_servers
  clients:                            # up to 2 suite clients (the second enables the multiple-clients module)
    - client_id: suite-client-1
      jwk_file: keys/client1.jwk.json # optional private EC P-256 JWK; generated per run otherwise
  wallet_client:                      # private_key_jwt client for wallet-interop (Wallet2)
    client_id: wallet
    jwk_file: keys/wallet-client.jwk.json
  public_client:                      # public client for wallet-interop (the EUDI wallet: no private_key_jwt)
    client_id: wallet-public
  login:                              # a user for the authorization-code flow
    username: test-user
    password: ...
    selectors:                        # optional: tried before the built-in defaults
      username: ["#email"]
      password: ["#pass"]
      submit: ["#login"]
      consent: ["#allow"]
    headers:                          # optional extra HTTP headers for the login browser,
      ngrok-skip-browser-warning: "1" #   e.g. to skip a tunnel's interstitial page
  expected_claims: {given_name: Ada}  # wallet-interop asserts these in the issued credential
  credential_trust_anchor: {file: ca.pem}   # vci-haip: what issued credentials chain to
  status_list_trust_anchor: {pem: "..."}    # vci-haip: defaults to credential_trust_anchor
  tls_verify: false

verifier:                             # needed by vp-base, vp-haip, wallet-interop
  start_presentation:
    suite: <trigger>                  # vp-*: a request for the PID the suite presents
    wallet: <trigger>                 # wallet-interop: a request for the issuer's credential
  result:                             # optional: lets vcit read the verifier's verdict
    http: {url: "https://verifier.example/sessions/{{ session }}"}
    status: $.status                  # JSONPath
    success: [VERIFIED]
    pending: [ACTIVE]
    details: {url: ".../{{ session }}/result"}   # optional; wallet-interop looks for expected_claims here
    timeout: 30
  request_trust_anchor: {file: verifier-ca.pem}  # optional; derived from the request's x5c otherwise
  client_id: verifier.example.com                # optional x509_san_dns value; derived from the certificate

hooks:                                # optional; see below
  setup: [python, hooks/setup.py]
  teardown: [python, hooks/teardown.py]
  timeout: 300

pki:                                  # optional fixed test CA (static targets); `vcit keygen` creates it
  ca_cert_file: keys/test-ca.crt
  ca_key_file: keys/test-ca.key

baseline_dir: baseline
profiles: [vp-base, {id: vp-haip, variants: {credential_format: sd_jwt_vc}}]
modules: {include: [], exclude: []}
suite: {mode: managed, url: https://localhost.emobix.co.uk:8443, alias_prefix: vcit}
wallets:                              # wallet-* profiles run once per wallet
  - type: waltid-wallet2              # defaults: http://localhost:7006, waltid/wallet-api2:1.1.1
  - type: eudi                        # defaults: http://localhost:7007, vcit/eudi-wallet:dev (wallets/eudi)
    # mode: external, url: ...        # a wallet you run yourself
report: {out_dir: ./out, fail_on: regression}
```

Substitution:

| Syntax | Resolved | From |
|---|---|---|
| `${VAR}`, `${VAR:-default}` | at load | the environment and `env_files` |
| `${setup.path.to.value}` | after the setup hook | its JSON output; a lone reference keeps the JSON type |
| `{{ session }}`, `{{ run_id }}` | at call time | inside HTTP requests |

Quote values that start with `${`, for example `"${ISSUER_URL}/oid4vci"`; YAML flow mappings cannot hold them unquoted.

## Presentation triggers

A trigger makes the verifier emit the authorization request a wallet would get from a QR code or
deep link: `openid4vp://?client_id=...&request_uri=...`. Use exactly one kind.

```yaml
# HTTP: call your API, then extract with JSONPath ($.a.b, $['a'], $.list[0])
suite:
  http:
    method: POST
    url: https://verifier.example/api/sessions
    headers: {X-Api-Key: "${KEY}"}
    json: {definition: pid}           # or form: {...}
    auth: {username: ..., password: ...}
  wallet_url: $.request_url
  session: $.id                       # optional; passed to result polling as {{ session }}

# Command: a program that prints a URL, or JSON (read with wallet_url / session)
suite:
  command: [python, hooks/start_presentation.py]

# Browser: a page that shows the request as a link
suite:
  browser:
    url: https://verifier.example/login
    selector: "a[href^='openid4vp://']"
    attribute: href
```

## Hooks contract

A hook is any program. vcit runs it from the target directory with the environment (including
`env_files`) and writes a JSON document to its stdin. In a hook command, `python` means vcit's own
interpreter, so a hook can use `httpx`. A hook writes its logs to stderr; they are saved under
`artifacts/hook-<name>.stderr.log`.

The **setup** hook's stdin carries everything that has to be registered at the target for this run:

```json
{
  "run_id": "20261012-063528-be42",
  "target": "my-product",
  "profiles": ["vci-base", "vp-base"],
  "suite": {"url": "https://localhost.emobix.co.uk:8443",
            "callbacks": {"vci-base": "https://localhost.emobix.co.uk:8443/test/a/vcit-vci-base/callback"}},
  "wallet": {"redirect_uri": "https://wallet.vcit.invalid/cb"},
  "clients": [{"name": "client1", "kid": "client1-es256", "public_jwk": {}, "cert_pem": "..."}, {}],
  "wallet_client": {"name": "wallet-client", "kid": "...", "public_jwk": {}, "cert_pem": "..."},
  "attester": {"issuer": "https://attester.vcit.invalid", "public_jwk": {}, "cert_pem": "..."},
  "test_ca_pem": "...",
  "suite_credential": {"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1",
                       "claims": ["given_name", "family_name"], "issuer_cert_pem": "..."}
}
```

What the target has to do with these values:
- Register `suite.callbacks` and `wallet.redirect_uri` as redirect URIs.
- For wallet-interop, register two wallet clients with `wallet.redirect_uri`: a `private_key_jwt` client
  with the `wallet_client` key (Wallet2), and a public client (the EUDI wallet).
- Register the clients for `private_key_jwt`, using `public_jwk` or `cert_pem`.
- Make the verifier request `suite_credential` and trust `test_ca_pem`. The suite signs the PID with
  a key whose x5c chains to that CA; the CA itself is not in x5c.
- For vci-haip, trust the `attester`.

The hook prints one JSON object on stdout. `target.yaml` reads it as `${setup.*}`.

A hook that only provisions part of a run should still print every key `target.yaml` references,
with a placeholder value for the parts it skipped.

The **teardown** hook receives `{"context": <the setup context>, "setup": <the setup output>}`. It
runs after the profiles, and only if setup succeeded.

A failed hook (non-zero exit, or output that is not JSON) stops the run, and the report shows its
stderr. A setup hook that fails half way should clean up after itself.

## Static targets (no hooks)

1. Reference fixed files under `pki:` and in each client's `jwk_file`, then run `vcit keygen --target DIR`.
2. Run `vcit target-info --target DIR` and register what it prints. Suite aliases are fixed per test
   profile (`vcit-<profile>`), so the callback URLs never change.
3. Record a baseline: run once, copy the observed failures into `baseline/`, then keep running.

## Baselines

`baseline/<profile>.yaml` lists expected statuses per module or check. See the README. Start by
running with `--fail-on never`, read the report, and write down what you accept as known
failures, each with a reason and, ideally, an issue link. Add `conditions` to pin the reason. A
case that then fails for a different reason shows up as a regression.
