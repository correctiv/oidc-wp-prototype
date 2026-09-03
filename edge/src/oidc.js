// OIDC relying party built on openid-client (https://github.com/panva/openid-client).
//
// The library handles discovery, PKCE, the code exchange and the full id_token validation
// (signature via JWKS, iss, aud, exp, nonce). The edge reads exactly one claim from the
// validated id_token (the role) and discards the rest.

import * as client from 'openid-client';
import { config, normalizeRole } from './config.js';

let discovered = null;

/**
 * Discovers the IdP lazily on first use and caches the result. A failed discovery (e.g. the IdP
 * is still starting) is retried on the next request instead of poisoning the cache.
 */
export function getOidcConfig() {
  if (!discovered) {
    const issuer = new URL(config.oidc.issuer);
    // http is only acceptable in the local prototype; openid-client refuses it unless told otherwise.
    const execute = issuer.protocol === 'http:' ? [client.allowInsecureRequests] : [];
    discovered = client
      .discovery(issuer, config.oidc.clientId, config.oidc.clientSecret, undefined, { execute })
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

/**
 * Prepares an authorization request. Returns the values that must be remembered for the
 * callback (in the signed auth-state cookie) plus the URL to redirect the browser to.
 */
export async function createAuthRequest({ silent }) {
  const cfg = await getOidcConfig();
  const codeVerifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const url = client.buildAuthorizationUrl(cfg, {
    redirect_uri: config.oidc.redirectUri,
    scope: 'openid',
    state,
    nonce,
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    ...(silent ? { prompt: 'none' } : {}),
  });
  return { state, nonce, codeVerifier, url: url.toString() };
}

/**
 * Completes the login: exchanges the code, validates the id_token and returns nothing but the
 * role. `sub` and every other claim are neither used nor logged.
 *
 * @param {URL} callbackUrl the callback URL exactly as the browser requested it
 */
export async function completeLogin(callbackUrl, { state, nonce, codeVerifier }) {
  const cfg = await getOidcConfig();
  const tokens = await client.authorizationCodeGrant(cfg, callbackUrl, {
    pkceCodeVerifier: codeVerifier,
    expectedState: state,
    expectedNonce: nonce,
    idTokenExpected: true,
  });
  const claims = tokens.claims();
  if (config.debugClaims) {
    // Claim names only, no values: demonstrates that the token carries no PII besides sub.
    console.log(`[oidc] id_token claims: ${Object.keys(claims).join(', ')}`);
  }
  return normalizeRole(claims[config.oidc.roleClaim]);
}

/** RP-initiated logout URL. client_id is added by the library; no id_token_hint on purpose. */
export async function buildLogoutUrl(postLogoutRedirectUri) {
  const cfg = await getOidcConfig();
  return client.buildEndSessionUrl(cfg, { post_logout_redirect_uri: postLogoutRedirectUri }).toString();
}
