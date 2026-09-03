#!/usr/bin/env bash
# Demonstrates the security and caching properties of the prototype against the running stack.
#
#   scripts/demo.sh                 # curl checks + login/logout flows
#   scripts/demo.sh --with-refresh  # additionally silent refresh (briefly restarts the auth service with a 5s JWT)
set -uo pipefail
cd "$(dirname "$0")/.."

EDGE=${EDGE_URL:-http://www.localhost:8000}
pass=0; fail=0

check() { # label expected actual
  if [[ "$3" == $2 ]]; then echo "✅ $1: $3"; ((pass++)); else echo "❌ $1: '$3' (expected '$2')"; ((fail++)); fi
}
header() { local name=$1; shift; curl -s -o /dev/null -D - "$@" | tr -d '\r' | grep -i "^${name}:" | head -1 | sed 's/^[^:]*: *//'; }
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "━━━ Edge: cache and header hygiene ━━━"
docker compose exec -T varnish varnishadm ban "req.url ~ ." >/dev/null
check "1. First request is a MISS"                    "MISS" "$(header x-cache "$EDGE/")"
check "   Role without a cookie"                      "none" "$(header x-example-role "$EDGE/")"
check "2. Second request is a HIT"                    "HIT"  "$(header x-cache "$EDGE/")"
check "3. Forged X-Example-Role is ignored"           "none" "$(header x-example-role -H 'X-Example-Role: full' "$EDGE/")"
check "   ... and hits the same cache entry"          "none|*" "$(header x-cache-key -H 'X-Example-Role: full' "$EDGE/")"
check "4. Bogus session cookie yields none"           "none" "$(header x-example-role -b 'example_session=abc.def.ghi' "$EDGE/")"
check "   ... without a redirect"                     "200"  "$(status -b 'example_session=abc.def.ghi' "$EDGE/")"
check "5. No Set-Cookie on a cached page"             ""     "$(header set-cookie "$EDGE/")"
check "6. Assets do not vary by role"                 "-|*"  "$(header x-cache-key "$EDGE/wp-includes/css/dist/block-library/style.min.css")"
check "7. /wp-admin/ bypasses the cache"              "BYPASS(path)" "$(header x-cache "$EDGE/wp-admin/")"
check "   /wp-login.php bypasses the cache"           "BYPASS(path)" "$(header x-cache "$EDGE/wp-login.php")"
check "8. Start page for none shows the login hint"   "1" "$(curl -s "$EDGE/" | grep -c 'You are not logged in')"
check "   ... and no full-only content"               "0" "$(curl -s "$EDGE/" | grep -c 'Level full only')"

echo; echo "━━━ OIDC flow ━━━"
LOGIN_LOC=$(header location "$EDGE/auth/login?return=/members/")
check "9. /auth/login redirects to the IdP"          "http://auth.localhost:8080/realms/example/protocol/openid-connect/auth?*" "$LOGIN_LOC"
check "    ... with PKCE S256"                        "*code_challenge_method=S256*" "$LOGIN_LOC"
check "    ... with scope=openid only"                "*scope=openid&*" "$LOGIN_LOC"
check "    ... and no-store"                          "no-store" "$(header cache-control "$EDGE/auth/login")"
check "    ... uncached via the auth backend"         "BYPASS(auth)" "$(header x-cache "$EDGE/auth/login")"
# The return path is signed into the example_auth cookie; external targets must become "/".
RT=$(header set-cookie "$EDGE/auth/login?return=https://evil.example" | sed 's/^example_auth=//; s/;.*//' | cut -d. -f2 | python3 -c "import base64,json,sys; t=sys.stdin.read().strip(); print(json.loads(base64.urlsafe_b64decode(t + '=' * (-len(t) % 4)))['returnTo'])")
check "10. Open redirects are neutralised"            "/"    "$RT"

echo
for u in anna ben carla; do node scripts/login-flow.mjs login "$u" || ((fail++)); done
node scripts/login-flow.mjs logout anna || ((fail++))

echo; echo "━━━ Varnish counters ━━━"
docker compose exec -T varnish varnishstat -1 -f MAIN.cache_hit -f MAIN.cache_miss -f MAIN.s_pass -f MAIN.n_object | awk '{printf "  %-18s %s\n", $1, $2}'

if [[ "${1:-}" == "--with-refresh" ]]; then
  echo; echo "━━━ Silent refresh (auth service briefly running with SESSION_TTL_SECONDS=5) ━━━"
  SESSION_TTL_SECONDS=5 docker compose up -d auth >/dev/null 2>&1; sleep 3
  node scripts/login-flow.mjs refresh anna --wait 7 || ((fail++))
  node scripts/login-flow.mjs refresh-fail ben --wait 7 || ((fail++))
  docker compose up -d auth >/dev/null 2>&1
  echo "(auth service restarted with the normal TTL)"
fi

echo; echo "curl checks: $pass passed, $fail failed (login flows: see ✅/❌ above)"
[[ $fail -eq 0 ]]
