# Running vcit in CI

## GitHub Action

```yaml
jobs:
  oid4vc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Start or point at your issuer/verifier here. It must be reachable from the runner VM
      # and from containers on the `vcit_default` network under the same URL.
      - uses: shashimalcse/oid4vc-interop@main
        with:
          target: targets/my-product
          profiles: vp-base vp-haip wallet-interop   # optional
          fail-on: regression                         # default
        env:
          MY_PRODUCT_ADMIN_PASSWORD: ${{ secrets.ADMIN_PASSWORD }}   # anything target.yaml reads as ${VAR}
```

| Input | Default | |
|---|---|---|
| `target` | (required) | target profile directory |
| `profiles` | target.yaml's list | space-separated |
| `modules` | all | space-separated substrings |
| `fail-on` | `regression` | `regression`, `any-failure` or `never` |
| `artifact-name` | `vcit-report` | |

The `report-dir` output points at `report.html`, `results.json` and `junit.xml`.

**Running your product as a container next to the suite.** Start it before the vcit step on the
network `vcit_default`, with a network alias, and add that alias to `/etc/hosts` on the runner:

```yaml
- run: |
    docker network create vcit_default || true
    docker run -d --network vcit_default --network-alias issuer.ci.local -p 8443:8443 my/product:pr
    echo "127.0.0.1 issuer.ci.local" | sudo tee -a /etc/hosts
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | no regressions (with `fail-on: regression`) |
| `1` | a regression, a profile error, or a failed setup/preflight |
| `2` | invalid target profile |
