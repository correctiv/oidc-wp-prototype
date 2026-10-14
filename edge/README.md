# The edge: HAProxy and Varnish in front of the website

What this directory contains is everything the edge needs to turn a login cookie into an access
level that WordPress can act on, while the site stays cacheable per level. It is meant to be
taken as is and wired into an existing HAProxy and Varnish deployment.

```
browser ──► HAProxy ──► Varnish ──► WordPress
            decrypt cookie, verify id_token, set role header, strip cookie
                        cache one variant per role header
```

## Files

| File | Purpose |
| --- | --- |
| `haproxy/haproxy.cfg` | The HAProxy frontend. Decrypts the login cookie (AES-256-GCM), verifies the `id_token` inside with the IdP's public key (RS256, `iss`, `exp`), reads the role claim, removes the cookie, sets the role header, redirects expired tokens to the community app's silent refresh. Everything environment-specific is a `${EDGE_*}` variable. |
| `haproxy/idp-public.pem` | The IdP's public key. The committed file is the prototype's demo key; replace it with `bin/fetch-idp-key.sh`. |
| `varnish/edge.vcl` | The caching logic as a VCL template: hash on the role header, bypass rules, `Set-Cookie` stripped from cacheable responses. Contains `${EDGE_*}` placeholders. |
| `varnish/render-vcl.sh` | Replaces the placeholders from the environment; fails if one is unset. Run it before `varnishd` starts. |
| `varnish/default.vcl` | Example of the wiring: a backend plus `include` of the rendered file. Replace with your own. |
| `varnish/tests/edge.vtc` | `varnishtest` for the template with a mocked backend. |
| `bin/fetch-idp-key.sh` | `fetch-idp-key.sh <jwks-url> [kid] > idp-public.pem`: converts the IdP's JWKS into the PEM file HAProxy needs. |
| `edge.env.example` | Every variable, with the prototype's values. |

## Variables

| Variable | Meaning |
| --- | --- |
| `EDGE_LOGIN_COOKIE_NAME` | Name of the domain-wide cookie the community app sets. |
| `EDGE_LOGIN_COOKIE_KEY` | 32-byte AES-256-GCM key, base64, shared with the community app. Confidentiality only: a holder can read tokens, not forge them. |
| `EDGE_OIDC_ISSUER` | Expected `iss` of the `id_token`. |
| `EDGE_IDP_PUBLIC_KEY_FILE` | Path of the PEM file inside the HAProxy process's view. |
| `EDGE_ROLE_CLAIM` | The `id_token` claim holding the level. |
| `EDGE_ROLE_HEADER` | The header carrying the level to Varnish and WordPress. The website reads the same name. |
| `EDGE_REFRESH_URL` | The community app's silent-refresh endpoint, called with `?next=<current URL>`. |
| `EDGE_CACHE_DEFAULT_TTL` | Varnish `default_ttl` in seconds for responses without `s-maxage` or `max-age`. |

HAProxy expands `${VAR}` at parse time; inside fetch arguments and header names only when the
argument is double-quoted, which the config already does. Varnish cannot read the environment,
hence the render step.

## What the cookie contains

`base64(nonce).base64(ciphertext).base64(tag)` in standard base64 with padding: AES-256-GCM,
12-byte random nonce per login, 16-byte tag, no additional data. The plaintext is the compact
`id_token` as issued by the IdP. A cookie that does not decrypt, does not verify, has the wrong
issuer or has expired yields the anonymous level; the cookie itself never reaches Varnish or
WordPress, valid or not.

## Running it

```sh
# HAProxy
set -a; . ./edge.env; set +a
haproxy -c -f haproxy/haproxy.cfg          # validate
# Varnish, before varnishd starts
sh varnish/render-vcl.sh varnish/edge.vcl /etc/varnish/edge.vcl
varnishd -p default_ttl="$EDGE_CACHE_DEFAULT_TTL" -f /etc/varnish/default.vcl ...
# tests
varnishtest varnish/tests/edge.vtc
```

## Operational notes

- **Network.** Varnish and WordPress must be reachable from HAProxy only; the role header is
  trusted downstream.
- **Logging.** Do not log the `Cookie` header on the HAProxy frontend.
- **Two alerts worth having:** decryption failures (a key mismatch after rotation looks exactly
  like this) and silent-refresh redirects per minute (a loop or an IdP problem looks like this).
