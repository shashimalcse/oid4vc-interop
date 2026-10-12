# Configuring WSO2 Identity Server for vcit

This guide prepares a WSO2 IS instance for the `wso2is` target profile. The setup hook provisions
everything per run: the VC template, test user, OAuth apps and presentation definitions. You only
configure the server itself, a tenant, and the tenant's verifier settings.

## 1. Product version

- WSO2 IS **7.4.0** or later (7.4.0-SNAPSHOT built from product-is master works). It needs the
  identity-openid4vc modules for both issuance and presentation, **1.1.16 or later**.
- Check that the pack has the presentation modules:
  ```bash
  ls <IS_HOME>/repository/components/plugins | grep openid4vc.presentation
  ```
  You should see `presentation.common`, `.core`, `.verification`, `.authenticator` and `.endpoint`.
  If you don't, the pack predates OID4VP: rebuild product-is, or apply a newer identity-openid4vc build.

## 2. `deployment.toml`

```toml
[server]
hostname = "your-public-host.example.com"   # the name wallets and the suite will use
base_path = "https://$ref{server.hostname}"  # behind a TLS-terminating tunnel/proxy on 443
# offset = 10                                # optional; or start with -DportOffset=10

[transport.https.properties]
proxyPort = 443                              # only when behind a proxy/tunnel on 443

# Turns on the OpenID4VP verifier. It is off by default.
[openid4vp]
enabled = true

# Needed until the product includes wso2/carbon-identity-framework#8341: lets tenant URLs
# (/t/<tenant>/oid4vp/...) reach the OID4VP webapp.
[tenant_context.rewrite]
custom_webapps = ["/oid4vp/"]
```

Restart IS after changing it. OID4VCI needs no `deployment.toml` entry.

## 3. One URL for everyone

The conformance suite and the wallets run in Docker; vcit and its headless browser run on the host.
**IS must be reachable at the same URL from both sides**, and that URL must be what IS advertises
(`hostname`/`base_path`), because it appears in issuer metadata, `request_uri`, `response_uri` and
credential `iss` values.

- **Tunnel (simplest).** For example ngrok, forwarding to the IS HTTPS port, including any offset:
  ```bash
  ngrok http https://localhost:9453 --url=https://your-name.ngrok-free.dev
  ```
  Use that host as `[server] hostname` with `proxyPort = 443`.
- **CI.** Build an image with `docker/build.sh <pack-dir>`. It sets the hostname to `is.vcit.local`
  and enables OID4VP. Run it on the `vcit_default` network and map `is.vcit.local` to 127.0.0.1 on the
  runner. See the header of `docker/build.sh`.

Check from the host:

```bash
curl -s https://your-public-host/t/<tenant>/oid4vci/.well-known/openid-credential-issuer
```

The `credential_issuer` in the response must start with your public URL.

## 4. Tenant and admin user

The profile works per tenant; `carbon.super` works too, by leaving out `/t/<tenant>`.

1. Create a tenant (Console → Root organization → Tenants), e.g. `mytenant` with admin `admin@mytenant`.
2. Copy `local.env.example` to `local.env` (it is gitignored) and fill it in:
   ```env
   IS_PUBLIC_URL=https://your-public-host/t/mytenant   # what the suite and wallets use
   IS_ADMIN_URL=https://localhost:9443/t/mytenant      # where vcit calls admin APIs (host-local is fine)
   IS_ADMIN_USER=admin@mytenant
   IS_ADMIN_PASSWORD=...
   TEST_USER_PASSWORD=Vcit-Test-Pass-1                 # for the user the hook creates
   ```
   With a port offset, `IS_ADMIN_URL` uses the offset port (e.g. `https://localhost:9453/...`).

The admin user needs rights to manage applications, users, VC templates, presentation definitions,
OID4VP sessions and server configs. The tenant admin has all of them.

## 5. Verifier settings (per tenant)

The OID4VP verifier's `client_id` prefix and response mode are tenant configuration, managed with
the server-configs API. They are not in `deployment.toml`.

```bash
# read
curl -sk -u "$IS_ADMIN_USER:$IS_ADMIN_PASSWORD" "$IS_ADMIN_URL/api/server/v1/configs/openid4vp"

# set (send both fields: a field you leave out may fall back to its default)
curl -sk -u "$IS_ADMIN_USER:$IS_ADMIN_PASSWORD" -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"clientIdScheme":"x509_hash","responseMode":"direct_post.jwt"}' \
  "$IS_ADMIN_URL/api/server/v1/configs/openid4vp"
```

| Field | Values | Default when unset |
|---|---|---|
| `clientIdScheme` | `x509_san_dns`, `x509_hash` | `x509_san_dns` |
| `responseMode` | `direct_post`, `direct_post.jwt` | `direct_post.jwt` |

**Match the test profile you run:**

| Test profile | Required tenant setting | Why |
|---|---|---|
| `vp-haip` | `x509_hash` + `direct_post.jwt` | pinned by the HAIP plan |
| `vp-base` | whatever `target.yaml` selects for `vp-base` (`client_id_prefix`, `response_mode` variants) | the suite rejects a request whose prefix or mode differs from the plan variant |
| `wallet-vp`, `wallet-interop` | `x509_hash` recommended | with `x509_san_dns`, the request certificate's SAN is the tenant name, which does not match the `response_uri` host, so spec-strict wallets (e.g. the EUDI library) refuse |

If you change the tenant setting, update the `vp-base` variants in `target.yaml` to match:

```yaml
profiles:
  - id: vp-base
    variants: {client_id_prefix: x509_hash, response_mode: direct_post.jwt}
```

## 6. What the hooks configure for you

You do not create any of these by hand. `hooks/setup.py` makes them per run, named
`vcit-<run>-…`, and `hooks/teardown.py` deletes them:

| For | Created through the admin APIs |
|---|---|
| vci-*, wallet-interop | VC template (`dc+sd-jwt`; given_name, family_name, email) and its API resource; a SCIM test user with those claims |
| vci-* | two OAuth apps: `private_key_jwt` (ES256), PKCE S256, PAR required, DPoP-bound JWT access tokens; redirect URIs are the suite callbacks |
| wallet-interop | an OAuth app for Wallet2, and a presentation definition for the issued credential, trusted by IS's signing certificate |
| vp-*, wallet-vp | a presentation definition for the test PID (`urn:eudi:pid:1`: given_name, family_name), trusting the run's test CA via `x5c` |

If a run is killed before teardown, delete leftovers named `vcit-*` in the Console: applications,
VC templates, presentation definitions and users.

## 7. Request-signing certificate (known limitation)

IS signs OID4VP requests with the tenant's EC key. Its certificate is self-signed, with CN and SAN DNS
set to the tenant name. Two consequences:

- `ValidateRequestObjectSignatureAgainstX5cHeader` fails in every vp-* module ("leaf certificate
  must not be self-signed"). This is recorded in `baseline/`.
- For `wallet-vp`, vcit makes the wallets trust that self-signed certificate directly, so trust is
  not what blocks them.

A CA-issued request certificate is needed for HAIP certification. We have not yet verified a
supported way to configure one per tenant.

## 8. Check the setup

```bash
# from the repository root
.venv/bin/vcit validate --target targets/wso2is          # config and effective suite variants
.venv/bin/vcit up       --target targets/wso2is          # conformance suite + wallets
.venv/bin/vcit run      --target targets/wso2is --profile vp-haip
```

Preflight stops early with a clear message if the issuer metadata, suite or wallets are unreachable.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Metadata works on the public URL but 404s on `IS_ADMIN_URL` | `IS_ADMIN_URL` points at a different IS or port. Check the port offset, and which process the tunnel forwards to. |
| Admin calls return 401 | Use the tenant admin (`admin@<tenant>`) with tenant URLs; the super admin cannot call `/t/<tenant>/api/...` |
| `presentation-definitions` or `oid4vp` URLs return 404 | `[openid4vp] enabled = true` or the `[tenant_context.rewrite]` entry is missing, or the pack lacks the presentation modules |
| vp-* modules all fail on `ValidateResponseMode`, and the suite never posts | the tenant `responseMode` is `direct_post`, but the plan uses `direct_post.jwt` (section 5) |
| The suite reports a client_id prefix mismatch | the tenant `clientIdScheme` differs from the plan variant (section 5) |
| Wallet2 gets `406 Not Acceptable` fetching `request_uri` | a known IS behaviour: the request endpoint only serves `Accept: application/oauth-authz-req+jwt`. Recorded in `baseline/wallet-vp.yaml`. |
| The EUDI wallet refuses with "`response_uri` host doesn't match" | the tenant is on `x509_san_dns`; switch to `x509_hash` (section 5) |
