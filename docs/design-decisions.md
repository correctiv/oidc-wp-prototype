# Design decisions and the alternatives we tried

The prototype went through several shapes before settling on the one in the README. This document
records each question we had to answer, the options we tried or seriously considered, what spoke
for and against them, and what we chose. Commit hashes point at the version of the repository
where an option can be seen working.

The constraints that drove every decision:

- WordPress must store no user data and must not know who the user is, only an access level.
- The site must stay fully cacheable: one cached variant per access level, never per person.
- The environment it is designed for has a reverse proxy in front of the page cache (HAProxy and
  Varnish), an OIDC identity provider, and a separate community app on a sibling subdomain that is
  already an OIDC relying party and must share the login.

## 1. Where the per-request logic runs

The per-request job: read a cookie, verify it, turn it into `X-Example-Role`, strip the cookie,
cache per role.

| Option | For | Against | Outcome |
| --- | --- | --- | --- |
| **Node reverse proxy** (Hono, then Express) with an in-memory cache | Everything in one small, readable codebase; easy to demo; no platform dependency | Not a real cache; one more service in the request path; does not resemble the target environment | Used for the first version (`a174a15`), replaced |
| **Varnish VCL** with `vmod_digest` for the HMAC check | The target environment already has Varnish; the cache is real; VCL is what operators can read | `vmod_digest` had to be compiled into the image and its base64 helpers turned out unreliable; JWT parsing in VCL is regex work; the HMAC key ends up in VCL on every node | Used (`9eee39b`), replaced when HAProxy turned out to be in front |
| **HAProxy** with `jwt_verify` | Native JWT verification including RS256 with the IdP's public key, so no shared secret; HAProxy is already the first hop; Varnish shrinks to hashing on a header | Public key must be kept in sync with the IdP's rotation; JSON path handling is limited (flat claims only) | **Chosen** (`8c8b3a3` onwards) |

## 2. What is in the cookie

| Option | For | Against | Outcome |
| --- | --- | --- | --- |
| **Own minted JWT** with only `role` and `exp` (HS256) | Smallest possible cookie; no `sub` anywhere in the browser; lifetime under our control | The edge has to trust the minting service and share a secret with it; a compromised minting service can invent roles; one more token format to explain | Used in the first two versions, dropped |
| **The IdP's `id_token`** as issued | The edge trusts only the IdP's signature; the relying party is a courier that cannot forge anything; one token format; the IdP's key rotation is the only key management | Contains an opaque `sub` and standard claims; lifetime is the IdP's token lifetime; slightly larger cookie | **Chosen** (`8c8b3a3` onwards). Requires the IdP to issue a lean token: `openid` scope plus the role claim only |

## 3. Who is the OIDC relying party

| Option | For | Against | Outcome |
| --- | --- | --- | --- |
| **A dedicated mini app** behind the edge | Small (about 150 lines with `openid-client`); independent of other systems; easy to reason about | One more deployable to run; duplicates a login that the community app already has | Used until `60891e7`, replaced |
| **HAProxy itself** | No extra deployable | Impossible with configuration alone: the code exchange is an outbound HTTP call. Feasible in Lua with HAProxy's HTTP client, but that means a hand-written OIDC client without a maintained library, JSON parsing in Lua, and login logic owned by the edge team | Considered, rejected |
| **The IdP directly** | Nothing to run | An identity provider cannot set cookies for another domain or receive its own callback; every OIDC web login needs a relying party on the site's side | Considered, not possible |
| **oauth2-proxy** or similar | Off the shelf, works with most identity providers | Its cookie is an encrypted blob HAProxy cannot read, so every request would have to pass through it; it is built to require login, whereas anonymous visitors are a first-class role here | Considered, rejected |
| **The community app** as the single relying party for both hosts | Already exists and already logs users in; no second client, no second login UI; single sign-on comes for free | Website login depends on the community app being up; the community app has to know how to hand the login to the website (see 4) | **Chosen** (`8c8b3a3` onwards) |
| **Two relying parties**, one per host, with SSO through the IdP session | Textbook OIDC; nothing crosses a host boundary; each host owns its cookie | Two clients to maintain; sessions on the two hosts drift apart; the website's client-side call to the community API needs a community session, which a website-only login does not create (see 5) | Considered late, rejected because of 5 |

## 4. How the website receives the login

The website and the community app live on sibling hosts under one parent domain. Something has
to make the login visible on the website's host.

| Option | For | Against | Outcome |
| --- | --- | --- | --- |
| **Domain-wide cookie** (`Domain=parent`) set by the community app | Simplest possible mechanism; one Set-Cookie; logout and refresh stay entirely inside the community app | Every subdomain receives the cookie, including anything CNAMEd to a third party; `__Host-` prefix impossible | **Chosen** (`0d29fc8`, then again `c52626d`) with the token kept lean so the exposure is bounded: an opaque `sub`, the level, and read access to the website's gated content for one token lifetime |
| **Form hand-over**: the community app answers with an auto-submitting form that POSTs the token to the website's `/auth/session`, where HAProxy verifies it and sets a host-only cookie | No cookie crosses a host; `__Host-` possible; the token never appears in a URL | Needed a hand-over endpoint, a clear endpoint, an `Origin` check against login CSRF, cross-host return-URL validation and a loop guard; visibly convoluted for a very common task | Built (`1a6b0ff`), reverted |
| **Token in a redirect URL** | Simplest mechanics, plain 302 chain | The token lands in access logs, browser history and referrers; the implicit flow was deprecated for exactly this | Considered, rejected |
| **Two relying parties** (see 3) | Each host logs in on its own | See 3 and 5 | Considered, rejected |

## 5. How the website page shows personal data

The cached page must not contain anything personal, but a logged-in user should see, for example,
their name from the community app.

| Option | For | Against | Outcome |
| --- | --- | --- | --- |
| **Client-side call** from the page to the community app's `/contact/me`, cookies sent because the hosts are the same site, CORS for the website's origin only | The cached page stays anonymous; the community app owns its API and its session; standard browser mechanics | Needs a community session in the browser, so the login must be shared (see 4); CORS must be exact, never `*` | **Chosen** (`0d29fc8` onwards) |
| **Proxy the API through the website's edge** with the verified token as a bearer header | No CORS, no second cookie; one session drives everything | Puts the community API behind the website's edge, a new network path; felt like working around CORS rather than using it | Considered, rejected |
| **Chain the logins**: after the website login, redirect once through the community login silently | Keeps two independent relying parties | Two sessions that expire independently; the profile box goes blank when the community session lapses first | Considered, rejected |

## 6. Protecting the origin

| Option | For | Against | Outcome |
| --- | --- | --- | --- |
| **Shared secret header** checked by a WordPress mu-plugin | Defence in depth even if the network is misconfigured; visible in a demo | One more secret in three places; solves a problem that network isolation solves anyway | Used until `60891e7`, removed |
| **Network isolation** only: WordPress and Varnish reachable from the edge alone | No code, no secret; what production does anyway | Nothing catches a misconfiguration | **Chosen**. The README keeps the header as an optional second line of defence |

## 7. Keeping the session alive

| Option | For | Against | Outcome |
| --- | --- | --- | --- |
| **Silent re-login** with `prompt=none` when the token has expired, triggered by the edge on HTML navigations | No refresh token or secret at the edge; falls back cleanly to anonymous when the IdP session is gone | One extra redirect round trip per token lifetime; the edge has to recognise "expired but otherwise valid" | **Chosen** |
| **Refresh token** held by the relying party | Invisible to the user | Long-lived secret material in the relying party; more logic | Considered, rejected |
| **Long-lived token** (hours) | Nothing to build | Role changes take hours to propagate | Considered, rejected |

## 8. Smaller decisions

- **Every logged-in user has a level.** An early version had a demo user who was logged in with
  level `none`. That state does not exist in the real use case and complicated the page logic
  (which links to show). Removed; the community app refuses a login whose token has no valid level.
- **Keycloak stands in for the identity provider** in the prototype: realistic, role claim via a
  mapper, fixed signing key so HAProxy can hold the public key. A mock IdP or `dex` would have been
  lighter but less convincing. Any provider that can issue a flat role claim works; with Zitadel,
  for example, that is an Action.
- **Hostnames have three labels** (`www.example.localhost`) so that a domain cookie can be
  demonstrated locally; browsers reject `Domain=localhost`.
- **Keycloak's `Secure` cookies on `*.localhost`** are accepted by browsers but not by `curl`,
  which is why the login flows are exercised by a small Node script instead of curl.

## History at a glance

| Commit | Shape |
| --- | --- |
| `a174a15` | Node proxy (Express) does everything: RP, own HS256 role cookie, cache. Origin guard header. |
| `9eee39b` | Varnish becomes the edge (VCL + `vmod_digest`); Express shrinks to the RP. |
| `60891e7` | Origin guard removed; RP slimmed. |
| `8c8b3a3` | HAProxy becomes the edge; community app is the sole RP; cookie holds the IdP's `id_token`. |
| `0d29fc8` | Community app on its own host; domain-wide cookie; `/contact/me` with CORS; "logged in without level" removed. |
| `1a6b0ff` | Host-only cookies via form hand-over to HAProxy. |
| `c52626d` | Back to the domain-wide login cookie, community session host-only. Current shape. |
