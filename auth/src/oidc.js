// OIDC relying party built on openid-client (https://github.com/panva/openid-client).
//
// The library handles discovery, PKCE, the code exchange and the full id_token validation
// (signature via JWKS, iss, aud, exp, nonce). This module reads exactly one claim from the
// validated id_token (the role) and discards the rest.

import * as client from 'openid-client';

export const ROLES = ['none', 'limited', 'full'];
export const normalizeRole = (value) => (ROLES.includes(value) ? value : 'none');

export function createOidc({ issuer, clientId, clientSecret, redirectUri, roleClaim, debugClaims = false }) {
  let discovered = null;

  // Discovers the IdP lazily on first use and caches the result. A failed discovery (e.g. the
  // IdP is still starting) is retried on the next request instead of poisoning the cache.
  function configuration() {
    if (!discovered) {
      const url = new URL(issuer);
      // http is only acceptable in the local prototype; openid-client refuses it unless told otherwise.
      const execute = url.protocol === 'http:' ? [client.allowInsecureRequests] : [];
      discovered = client
        .discovery(url, clientId, clientSecret, undefined, { execute })
        .then((cfg) => {
          cfg[client.clockTolerance] = 30;
          console.log(`[oidc] discovered issuer ${cfg.serverMetadata().issuer}`);
          return cfg;
        })
        .catch((err) => {
          discovered = null;
          throw err;
        });
    }
    return discovered;
  }

  return {
    configuration,

    /** Prepares an authorization request: the values to remember for the callback plus the redirect URL. */
    async createAuthRequest({ silent }) {
      const cfg = await configuration();
      const codeVerifier = client.randomPKCECodeVerifier();
      const state = client.randomState();
      const nonce = client.randomNonce();
      const url = client.buildAuthorizationUrl(cfg, {
        redirect_uri: redirectUri,
        scope: 'openid',
        state,
        nonce,
        code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
        code_challenge_method: 'S256',
        ...(silent ? { prompt: 'none' } : {}),
      });
      return { state, nonce, codeVerifier, url: url.toString() };
    },

    /**
     * Exchanges the code, validates the id_token and returns nothing but the role.
     * @param {URL} callbackUrl the callback URL exactly as the browser requested it
     */
    async completeLogin(callbackUrl, { state, nonce, codeVerifier }) {
      const tokens = await client.authorizationCodeGrant(await configuration(), callbackUrl, {
        pkceCodeVerifier: codeVerifier,
        expectedState: state,
        expectedNonce: nonce,
        idTokenExpected: true,
      });
      const claims = tokens.claims();
      // Claim names only, no values: demonstrates that the token carries no PII besides sub.
      if (debugClaims) console.log(`[oidc] id_token claims: ${Object.keys(claims).join(', ')}`);
      return normalizeRole(claims[roleClaim]);
    },

    /** RP-initiated logout URL. client_id is added by the library; no id_token_hint on purpose. */
    async buildLogoutUrl(postLogoutRedirectUri) {
      return client.buildEndSessionUrl(await configuration(), { post_logout_redirect_uri: postLogoutRedirectUri }).toString();
    },
  };
}
