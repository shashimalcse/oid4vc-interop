# Target profile: ThunderID

ThunderID as an OpenID4VCI issuer and an OpenID4VP verifier. It runs as a container on the vcit
Docker network, and `hooks/` provisions every run through ThunderID's management APIs.

```bash
vcit keygen --target targets/thunderid       # once: the fixed test CA ThunderID's verifier trusts
vcit up     --target targets/thunderid       # conformance suite + wallets
targets/thunderid/docker/up.sh               # ThunderID at https://thunder.localtest.me:8090
vcit run    --target targets/thunderid --profile vp-haip
```

See [CONFIGURATION.md](CONFIGURATION.md) for how it is set up and why.

## What the hooks create

The admin token comes from the bootstrapped CONSOLE client with `scope=system`, using authorization
code + PKCE and a flow-API login (no browser).

| For | Created |
|---|---|
| vci-*, wallet-interop | a credential configuration `vcit-<run>-badge` (`dc+sd-jwt`; given_name, family_name, email) and a Person user with those attributes |
| vci-* | two `wallet`-template apps: `private_key_jwt` with the vcit client JWKs, PKCE, PAR required, DPoP-bound tokens; redirect URIs are the suite callbacks |
| wallet-interop | a `wallet`-template app for Wallet2, and a presentation definition for the issued credential |
| vp-*, wallet-vp | a presentation definition for the test PID (`urn:eudi:pid:1`; given_name, family_name) with `enforceTrustedIssuer` against the `vcit` trust anchor |

Presentations start with `POST /openid4vp/initiate`, and the verdict comes from
`GET /openid4vp/status/{txn}`. Its `result_token` carries the verified claims.

## Baseline (ThunderID 1.0.1, 2026-10-12)

- **vp-base / vp-haip:**
  - Verification is correct. Happy flows end COMPLETED, and every negative module is rejected for
    the injected flaw: KB-JWT signature, issuer signature, sd_hash, nonce, aud, and `iat` in the past
    and in the future.
  - Remaining failures:
    - the request object is signed with a self-signed certificate;
    - HAIP: the `direct_post` response has no `redirect_uri`.
- **wallet-vp:** both wallets refuse the request object because it has no `aud`. Wallet2 and the
  EUDI library both expect `https://self-issued.me/v2`; the suite does not check this.
- **wallet-interop:** both wallets stop at PAR (`invalid_target`, the same scope/resource gap).
  With `THUNDER_DEFAULT_RESOURCE_SERVER=1` (an opt-in workaround: the hook sets a per-run
  `defaultResourceServer`, then restores it), both wallets complete issuance, including PAR, the
  gate login, DPoP, the proof, and a credential with `cnf` and the expected claims. They then stop
  at presentation on the missing `aud`.
- **Discoverability:** a per-app PAR requirement isn't visible in the AS metadata, so wallets skip
  PAR and are refused. This target sets `oauth.par.require_par: true` so that
  `require_pushed_authorization_requests` is advertised.
- **vci-base:**
  - PAR fails with `invalid_target`: the advertised credential scope needs a `resource` or a
    server-wide `defaultResourceServer`.
  - The metadata `claims` uses the pre-final shape (already fixed on main).
