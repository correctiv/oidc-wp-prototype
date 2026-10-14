#!/usr/bin/env bash
# Fetches an IdP's JWKS and writes one RSA public key as PEM, the form HAProxy's jwt_verify needs.
#
#   scripts/fetch-idp-key.sh <jwks-url> [kid] > haproxy/idp-public.pem
#
# Without a kid, the first RS256 signing key is used. HAProxy verifies against exactly one key, so
# during a key rotation the config needs a second jwt_verify attempt with the previous key.
set -euo pipefail
url=${1:?usage: fetch-idp-key.sh <jwks-url> [kid]}
kid=${2:-}
curl -fsS "$url" | node -e '
  const [kid] = process.argv.slice(1);
  const { createPublicKey } = require("node:crypto");
  const jwks = JSON.parse(require("fs").readFileSync(0, "utf8"));
  const keys = jwks.keys.filter((k) => k.kty === "RSA" && (k.use ?? "sig") === "sig" && (!k.alg || k.alg === "RS256"));
  const key = kid ? keys.find((k) => k.kid === kid) : keys[0];
  if (!key) { console.error(`no matching RSA signing key (available kids: ${jwks.keys.map((k) => k.kid).join(", ")})`); process.exit(1); }
  console.error(`using kid ${key.kid}`);
  process.stdout.write(createPublicKey({ key, format: "jwk" }).export({ type: "spki", format: "pem" }));
' "$kid"
