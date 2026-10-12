# Configuring ThunderID for vcit

`docker/up.sh` does everything below for a local run. This page explains each setting, so you
can reproduce it on another deployment, e.g. a CI service container or a remote instance.

## 1. Version

ThunderID **1.0.1** or later (`ghcr.io/thunder-id/thunderid:1.0.1`). It includes the OpenID4VCI
issuer (`/openid4vci/*`, `/.well-known/openid-credential-issuer`) and the OpenID4VP verifier
(`/openid4vp/*`). Main adds the OID4VCI 1.0-final `claims` array format in issuer metadata
(d124d591e). To use a newer image, set `THUNDER_IMAGE`.

## 2. One URL for everyone

The suite and the wallets run in containers; vcit and its browser run on the host. ThunderID uses
**`https://thunder.localtest.me:8090`**:
- on the host, `*.localtest.me` resolves to 127.0.0.1 in public DNS;
- in Docker, the container joins the `vcit_default` network with the alias `thunder.localtest.me`.

`up.sh` issues a TLS certificate for that name. The certificate from setup only names `localhost`.

## 3. `docker/deployment.yaml`

This is the default deployment.yaml with three vcit changes:

```yaml
server:
  hostname: "0.0.0.0"
  public_url: "https://thunder.localtest.me:8090"   # issuer, request_uri and response_uri are built from it

openid4vp:
  client_id_scheme: "x509_hash"     # the request certificate's SAN is "localhost", so x509_san_dns
                                     # would not match the response_uri host and wallets refuse
  trusted_anchors:
    - name: "vcit"
      cert_file: "config/vcit/test-ca.crt"   # the vcit test CA; mounted by up.sh
```

- **Trust anchors are static configuration** (there's no API), so the vcit test CA must be fixed.
  `vcit keygen --target targets/thunderid` writes `keys/test-ca.{crt,key}` (gitignored), and the
  `pki:` section of `target.yaml` makes every run sign with that CA.
- Setup also loads the anchor, so `up.sh` mounts it for setup and for the server.
- The verifier only accepts `direct_post.jwt`. The `vp-base` variants in `target.yaml` are set to
  `x509_hash` + `direct_post.jwt` to match.

## 4. Admin access

`up.sh` runs `./setup.sh --admin-username admin --admin-password $THUNDER_ADMIN_PASSWORD` (default
`admin`) on the first start. The hooks log in as that admin through the CONSOLE client. To use
another instance or other credentials, set them in `local.env` (see `local.env.example`):

```env
THUNDER_URL=https://thunder.localtest.me:8090
THUNDER_ADMIN_USER=admin
THUNDER_ADMIN_PASSWORD=admin
```

## 5. Things ThunderID requires that vcit sets up

| Requirement | How it's met |
|---|---|
| Credentials are issued only to apps with template `wallet` or `wallet-embedded` | the hooks create `wallet`-template apps |
| private_key_jwt `aud` must equal the issuer (`https://thunder.localtest.me:8090`) | the suite and Wallet2 send the AS issuer |
| Presentation definitions trust issuers only by `x5c` chain, and only with `enforceTrustedIssuer` | the suite's and vcit's PID signer certificates chain to the vcit test CA |

## 6. Reset

```bash
docker rm -f vcit-thunderid
docker volume rm vcit-thunderid-db vcit-thunderid-certs vcit-thunderid-secrets
rm -rf targets/thunderid/.state
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| Setup fails with `failed to load trust anchor "vcit"` | `keys/test-ca.crt` is missing; run `vcit keygen --target targets/thunderid` |
| Hooks fail at `admin login did not complete` | wrong admin password; the volumes keep the first setup's password |
| PAR returns `invalid_target ... no default resource server` | a known ThunderID gap (see baseline). `PUT /server-config/defaultResourceServer` can work around it, but that changes token audiences server-wide |
| Wallets refuse the request: `aud` missing | a known gap (see baseline) |
