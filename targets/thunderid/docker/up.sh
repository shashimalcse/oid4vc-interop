#!/usr/bin/env bash
# Run ThunderID for vcit on the vcit docker network, reachable as https://thunder.localtest.me:8090
# from the host and from the suite/wallet containers.
#
#   vcit keygen --target targets/thunderid     # once: the fixed test CA ThunderID trusts
#   vcit up     --target targets/thunderid     # suite + wallets (creates the vcit network)
#   targets/thunderid/docker/up.sh             # this script
#
# Env: THUNDER_IMAGE (default ghcr.io/thunder-id/thunderid:1.0.1), THUNDER_ADMIN_PASSWORD (default admin).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
target=$(cd "$here/.." && pwd)
state="$target/.state"
image=${THUNDER_IMAGE:-ghcr.io/thunder-id/thunderid:1.0.1}
password=${THUNDER_ADMIN_PASSWORD:-admin}
host=thunder.localtest.me
name=vcit-thunderid

[ -f "$target/keys/test-ca.crt" ] || { echo "missing keys/test-ca.crt: run 'vcit keygen --target targets/thunderid'"; exit 1; }
docker network inspect vcit_default >/dev/null 2>&1 || { echo "no vcit_default network: run 'vcit up --target targets/thunderid' first"; exit 1; }

mkdir -p "$state/tls" "$state/vcit"
cp "$target/keys/test-ca.crt" "$state/vcit/test-ca.crt"
if [ ! -f "$state/tls/server.cert" ]; then
  # The setup script's certificate only names localhost; issue one for the shared hostname.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -subj "/CN=$host" -addext "subjectAltName=DNS:$host,DNS:localhost,IP:127.0.0.1" \
    -keyout "$state/tls/server.key" -out "$state/tls/server.cert" >/dev/null 2>&1
fi

volumes=(-v vcit-thunderid-db:/opt/thunderid/database
         -v vcit-thunderid-certs:/opt/thunderid/config/certs
         -v vcit-thunderid-secrets:/opt/thunderid/config/secrets
         -v "$here/deployment.yaml:/opt/thunderid/deployment.yaml:ro"
         -v "$state/vcit:/opt/thunderid/config/vcit:ro")

if ! docker volume inspect vcit-thunderid-db >/dev/null 2>&1; then
  echo "first run: ThunderID setup (admin user 'admin')"
  if ! docker run --rm "${volumes[@]}" "$image" ./setup.sh --admin-username admin --admin-password "$password"; then
    docker volume rm vcit-thunderid-db vcit-thunderid-certs vcit-thunderid-secrets >/dev/null 2>&1 || true
    echo "setup failed"; exit 1
  fi
fi

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --network vcit_default --network-alias "$host" -p 8090:8090 \
  "${volumes[@]}" \
  -v "$state/tls/server.cert:/opt/thunderid/config/certs/server.cert:ro" \
  -v "$state/tls/server.key:/opt/thunderid/config/certs/server.key:ro" \
  "$image" >/dev/null

for _ in $(seq 1 60); do
  if curl -sk -o /dev/null -w '%{http_code}' "https://$host:8090/.well-known/openid-credential-issuer" | grep -q 200; then
    echo "ThunderID ready at https://$host:8090"
    exit 0
  fi
  sleep 2
done
echo "ThunderID did not come up; see: docker logs $name"
exit 1
