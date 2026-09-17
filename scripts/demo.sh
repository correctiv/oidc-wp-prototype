#!/usr/bin/env bash
# Demonstrates the security and caching properties of the prototype against the running stack.
#
#   scripts/demo.sh                 # curl checks + login/logout flows
#   scripts/demo.sh --with-refresh  # additionally silent refresh (shortens the id_token lifetime in Keycloak for a moment)
set -uo pipefail
cd "$(dirname "$0")/.."

SITE=${SITE_URL:-http://www.example.localhost:8000}
COMMUNITY=${COMMUNITY_URL:-http://community.example.localhost:8001}
KC=${KC_URL:-http://auth.example.localhost:8080}
pass=0; fail=0

check() { # label expected actual
  if [[ "$3" == $2 ]]; then echo "✅ $1: $3"; ((pass++)); else echo "❌ $1: '$3' (expected '$2')"; ((fail++)); fi
}
header() { local name=$1; shift; curl -s -o /dev/null -D - "$@" | tr -d '\r' | grep -i "^${name}:" | head -1 | sed 's/^[^:]*: *//'; }
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
kc_token() { curl -s -d "client_id=admin-cli&username=admin&password=${KC_ADMIN_PASSWORD:-admin}&grant_type=password" "$KC/realms/master/protocol/openid-connect/token" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"; }
kc_set_token_lifespan() { curl -s -o /dev/null -X PUT -H "Authorization: Bearer $(kc_token)" -H "Content-Type: application/json" -d "{\"accessTokenLifespan\": $1}" "$KC/admin/realms/example"; }

echo "━━━ HAProxy + Varnish: cache and header hygiene ━━━"
docker compose exec -T varnish varnishadm ban "req.url ~ ." >/dev/null
check "1. First request is a MISS"                    "MISS" "$(header x-cache "$SITE/")"
check "   Role without a cookie"                      "none" "$(header x-example-role "$SITE/")"
check "2. Second request is a HIT"                    "HIT"  "$(header x-cache "$SITE/")"
check "3. Forged X-Example-Role is ignored"           "none" "$(header x-example-role -H 'X-Example-Role: full' "$SITE/")"
check "   ... and hits the same cache entry"          "none|*" "$(header x-cache-key -H 'X-Example-Role: full' "$SITE/")"
check "4. Bogus login cookie yields none"             "none" "$(header x-example-role -b 'example_login=abc.def.ghi' "$SITE/")"
check "   ... without a redirect"                     "200"  "$(status -b 'example_login=abc.def.ghi' "$SITE/")"
check "   Self-signed HS256 token yields none"        "none" "$(header x-example-role -b "example_login=$(node -e "import('jose').then(async j=>{const k=new TextEncoder().encode('x'.repeat(32));console.log(await new j.SignJWT({example_role:'full',iss:'http://auth.example.localhost:8080/realms/example',aud:'community-app'}).setProtectedHeader({alg:'HS256'}).setExpirationTime('1h').sign(k))})" 2>/dev/null || echo bad)" "$SITE/")"
check "5. No Set-Cookie on a cached page"             ""     "$(header set-cookie "$SITE/")"
check "6. Assets do not vary by role"                 "-|*"  "$(header x-cache-key "$SITE/wp-includes/css/dist/block-library/style.min.css")"
check "7. /wp-admin/ bypasses the cache"              "BYPASS(path)" "$(header x-cache "$SITE/wp-admin/")"
check "   /wp-login.php bypasses the cache"           "BYPASS(path)" "$(header x-cache "$SITE/wp-login.php")"
check "8. Start page for none shows the login hint"   "1" "$(curl -s "$SITE/" | grep -c 'You are not logged in')"
check "   ... and no full-only content"               "0" "$(curl -s "$SITE/" | grep -c 'Level full only')"
check "   Login link points at the community app"     "$COMMUNITY/auth/login?return=*" "$(curl -s "$SITE/" | grep -oE 'href="[^"]*auth/login[^"]*"' | head -1 | sed 's/href="//; s/"$//; s/&amp;/\&/g')"

echo; echo "━━━ Community app: OIDC flow ━━━"
LOGIN_LOC=$(header location "$COMMUNITY/auth/login?return=$SITE/members/")
check "9. /auth/login redirects to the IdP"           "$KC/realms/example/protocol/openid-connect/auth?*" "$LOGIN_LOC"
check "    ... with PKCE S256"                        "*code_challenge_method=S256*" "$LOGIN_LOC"
check "    ... with scope=openid only"                "*scope=openid&*" "$LOGIN_LOC"
check "    ... and no-store"                          "no-store" "$(header cache-control "$COMMUNITY/auth/login")"
# The return URL is signed into the example_auth cookie; foreign hosts must fall back to the community home.
RT=$(header set-cookie "$COMMUNITY/auth/login?return=https://evil.example/" | sed 's/^example_auth=//; s/;.*//' | cut -d. -f2 | python3 -c "import base64,json,sys; t=sys.stdin.read().strip(); print(json.loads(base64.urlsafe_b64decode(t + '=' * (-len(t) % 4)))['returnTo'])")
check "10. Open redirects are neutralised"            "$COMMUNITY/" "$RT"
check "11. Community home answers"                    "200" "$(status "$COMMUNITY/")"

check "12. /contact/me without login is 401"          "401" "$(status -H "Origin: $SITE" "$COMMUNITY/contact/me")"
check "    ... with CORS for the website's origin"    "$SITE" "$(header access-control-allow-origin -H "Origin: $SITE" "$COMMUNITY/contact/me")"
check "    ... and credentials allowed"               "true" "$(header access-control-allow-credentials -H "Origin: $SITE" "$COMMUNITY/contact/me")"
check "    ... but not for a foreign origin"          ""     "$(header access-control-allow-origin -H "Origin: https://evil.example" "$COMMUNITY/contact/me")"
check "    No contact card in the anonymous variant"  "0"    "$(curl -s "$SITE/" | grep -c 'class="example-contact-card"')"
check "    ... and no username in any cached page"    "0"    "$(curl -s "$SITE/" | grep -c 'anna')"

echo
for u in anna ben; do node scripts/login-flow.mjs login "$u" || ((fail++)); done
node scripts/login-flow.mjs logout anna || ((fail++))

echo; echo "━━━ Varnish counters ━━━"
docker compose exec -T varnish varnishstat -1 -f MAIN.cache_hit -f MAIN.cache_miss -f MAIN.s_pass -f MAIN.n_object | awk '{printf "  %-18s %s\n", $1, $2}'

if [[ "${1:-}" == "--with-refresh" ]]; then
  echo; echo "━━━ Silent refresh (id_token lifetime temporarily 5s in Keycloak) ━━━"
  kc_set_token_lifespan 5
  node scripts/login-flow.mjs refresh anna --wait 7 || ((fail++))
  node scripts/login-flow.mjs refresh-fail ben --wait 7 || ((fail++))
  kc_set_token_lifespan 900
  echo "(id_token lifetime restored to 900s)"
fi

echo; echo "curl checks: $pass passed, $fail failed (login flows: see ✅/❌ above)"
[[ $fail -eq 0 ]]
