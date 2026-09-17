#!/usr/bin/env bash
# Generates the demo signing key pair of the IdP: the private key and certificate go into the
# Keycloak realm import, the public key is what HAProxy verifies id_tokens with.
# Demo material only. In production the IdP owns its keys and HAProxy receives the public key
# through whatever key-distribution process the infrastructure team runs.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
openssl genrsa -traditional -out "$tmp/key.pem" 2048 2>/dev/null
openssl req -new -x509 -key "$tmp/key.pem" -days 3650 -subj "/CN=example-idp-demo" -out "$tmp/cert.pem" 2>/dev/null
openssl rsa -in "$tmp/key.pem" -pubout -out haproxy/idp-public.pem 2>/dev/null
python3 - "$tmp/key.pem" "$tmp/cert.pem" <<'PY'
import json, sys, re
strip = lambda pem: re.sub(r'-----[A-Z ]+-----|\s', '', open(pem).read())
p = 'keycloak/realm-example.json'
realm = json.load(open(p))
providers = realm.setdefault('components', {}).setdefault('org.keycloak.keys.KeyProvider', [])
providers[:] = [c for c in providers if c.get('name') != 'rsa-demo']
providers.append({
    "name": "rsa-demo",
    "providerId": "rsa",
    "subComponents": {},
    "config": {
        "privateKey": [strip(sys.argv[1])],
        "certificate": [strip(sys.argv[2])],
        "priority": ["100"],
        "enabled": ["true"],
        "active": ["true"],
        "algorithm": ["RS256"],
        "keyUse": ["SIG"],
    },
})
json.dump(realm, open(p, 'w'), indent=2, ensure_ascii=False)
open(p, 'a').write('\n')
PY
rm -rf "$tmp"
echo "wrote haproxy/idp-public.pem and the rsa-demo key provider in keycloak/realm-example.json"
