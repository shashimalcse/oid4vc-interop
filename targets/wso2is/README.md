# Target profile: WSO2 Identity Server

WSO2 IS 7.4+ as an OpenID4VCI issuer and an OpenID4VP verifier. All five test profiles are
configured.

## What the hooks do

`hooks/setup.py` uses the IS admin REST APIs (`hooks/wso2is_admin.py`) to create, for each run, only
what the selected profiles need:

| For | Created |
|---|---|
| vci-*, wallet-interop | a VC template `vcit-<run>-EmployeeBadge` (`dc+sd-jwt`, claims given_name/family_name/email) and a SCIM user with those claims |
| vci-* | two OAuth apps, `private_key_jwt` (ES256), PKCE S256, PAR, DPoP-bound JWT tokens; redirect URIs are the suite callbacks; subscribed to the template's API resource |
| wallet-interop | a third app for Wallet2, and a presentation definition for the issued credential (vct = template identifier, issuer trusted by its signing certificate) |
| vp-* | a presentation definition for the suite's `urn:eudi:pid:1` PID, trusting the vcit test CA (`x5c`) |

`hooks/teardown.py` deletes all of it. Presentations are started with
`POST {IS_ADMIN_URL}/oid4vp/verification-sessions`, and the verdict is read from `.../{id}/status`.

## Running it

1. Configure IS as described in **[CONFIGURATION.md](CONFIGURATION.md)**: `deployment.toml`, one
   public URL, the tenant, and the tenant's OID4VP verifier settings.
2. `cp local.env.example local.env`, then fill in the URLs. Both URLs include `/t/<tenant>`.
3. From the repository root:
   ```bash
   vcit up  --target targets/wso2is
   vcit run --target targets/wso2is --profile vp-haip
   ```

## Baseline

`baseline/` holds the known gaps. Bracketed numbers refer to the gap analysis behind this profile.
`vp-base.yaml` is the run observed on 2026-10-12 (IS 7.4.0-SNAPSHOT, identity-openid4vc 1.1.16).
The other files are predictions from code reading; replace them with observed results after their
first run.
