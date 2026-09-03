// Central configuration from environment variables.
//
// OIDC endpoints come from discovery on OIDC_ISSUER. Locally the browser and the edge container
// must therefore reach the IdP under the same URL; docker-compose.yml maps auth.localhost to the
// Docker host inside the edge container for that (extra_hosts).

function env(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') {
    if (fallback === undefined) throw new Error(`Missing environment variable ${name}`);
    return fallback;
  }
  return value;
}

const stripSlash = (s) => s.replace(/\/+$/, '');

const publicUrl = stripSlash(env('PUBLIC_URL'));

export const ROLES = ['none', 'limited', 'full'];

export function normalizeRole(value) {
  return typeof value === 'string' && ROLES.includes(value) ? value : 'none';
}

export const config = {
  port: Number(env('PORT', '8000')),
  publicUrl,
  secureCookies: publicUrl.startsWith('https://'),

  origin: {
    url: stripSlash(env('ORIGIN_URL')),
    sharedSecret: env('EDGE_SHARED_SECRET'),
  },

  oidc: {
    issuer: stripSlash(env('OIDC_ISSUER')),
    clientId: env('OIDC_CLIENT_ID'),
    clientSecret: env('OIDC_CLIENT_SECRET'),
    roleClaim: env('OIDC_ROLE_CLAIM', 'example_role'),
    redirectUri: `${publicUrl}/auth/callback`,
  },

  session: {
    secret: env('SESSION_SECRET'),
    // Lifetime of the role JWT
    ttlSeconds: Number(env('SESSION_TTL_SECONDS', '900')),
    // The cookie outlives the JWT so that an expired JWT can trigger the silent re-login.
    cookieMaxAgeSeconds: Number(env('SESSION_COOKIE_MAX_AGE_SECONDS', '43200')),
    // Lifetime of the intermediate login state (state, nonce, PKCE verifier)
    authStateTtlSeconds: 300,
  },

  cache: {
    defaultTtlSeconds: Number(env('DEFAULT_CACHE_TTL_SECONDS', '60')),
  },

  debug: env('EDGE_DEBUG', '0') === '1',
  debugClaims: env('DEBUG_CLAIMS', '0') === '1',
};
