#!/usr/bin/env bash
# Build a WSO2 IS image from an extracted product pack, for CI runs of this target profile.
#
#   targets/wso2is/docker/build.sh ~/product-is/modules/distribution/target/wso2is-7.4.0-SNAPSHOT [tag]
#
# The pack's deployment.toml is patched so that IS:
#   - advertises https://is.vcit.local:9443. Run the container on the `vcit_default` network
#     with that alias and map is.vcit.local to 127.0.0.1 on the host, so the host (browser,
#     vcit) and the containers (suite, Wallet2) reach IS under the same name;
#   - has the OID4VP verifier enabled (off by default in 7.4.0).
#
#   docker run -d --name vcit-is --network vcit_default --network-alias is.vcit.local -p 9443:9443 vcit/wso2is:local
set -euo pipefail

pack=${1:?usage: build.sh <extracted-pack-dir> [image-tag]}
tag=${2:-vcit/wso2is:local}
here=$(cd "$(dirname "$0")" && pwd)
ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT

cp -R "$pack" "$ctx/wso2is"
toml="$ctx/wso2is/repository/conf/deployment.toml"

# [server] hostname -> is.vcit.local; drop base_path/proxy ports from local tunnel setups.
perl -0pi -e 's/^hostname\s*=.*$/hostname = "is.vcit.local"/m; s/^base_path\s*=.*\n//m; s/^proxyPort\s*=.*\n//mg' "$toml"
if ! grep -q '^\[openid4vp\]' "$toml"; then
  printf '\n[openid4vp]\nenabled = true\n' >> "$toml"
fi

cp "$here/Dockerfile" "$ctx/Dockerfile"
docker build -t "$tag" "$ctx"
echo "built $tag"
