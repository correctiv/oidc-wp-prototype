// Signed cookies and small helpers of the community app stand-in. The signing key is private to
// this app; nothing else needs to read these cookies.
//
// - auth state: state, nonce, PKCE verifier and return URL travel through the login redirect in a
//   short-lived cookie, so the app stays stateless.
// - community session: the app's own login session with the profile it fetched at login. This is
//   where personal data lives; the domain-wide id_token cookie stays lean.

import { SignJWT, jwtVerify } from 'jose';

export const AUTH_COOKIE = 'example_auth';
export const COMMUNITY_COOKIE = 'community_session';
const AUTHSTATE_TYP = 'example-authstate+jwt';
const COMMUNITY_TYP = 'example-community-session+jwt';

function signer(secret, typ) {
  const key = new TextEncoder().encode(secret);
  return {
    sign: (payload, ttlSeconds) =>
      new SignJWT(payload).setProtectedHeader({ alg: 'HS256', typ }).setIssuedAt().setExpirationTime(`${ttlSeconds}s`).sign(key),
    async verify(token) {
      if (!token) return null;
      try {
        return (await jwtVerify(token, key, { algorithms: ['HS256'], typ })).payload;
      } catch {
        return null;
      }
    },
  };
}

export function createAuthState({ secret, ttlSeconds = 300, allowedReturnHosts, fallbackReturn }) {
  const jwt = signer(secret, AUTHSTATE_TYP);
  const sanitise = (value) => safeReturnUrl(value, allowedReturnHosts, fallbackReturn);
  return {
    sanitiseReturn: sanitise,
    /** @param {{state:string, nonce:string, codeVerifier:string, returnTo:string, silent:boolean}} data */
    mint: (data) => jwt.sign(data, ttlSeconds),
    /** Returns the auth state or null if the token is missing, expired or tampered. */
    async verify(token) {
      const payload = await jwt.verify(token);
      return payload && { ...payload, returnTo: sanitise(payload.returnTo) };
    },
  };
}

export function createCommunitySession({ secret }) {
  const jwt = signer(secret, COMMUNITY_TYP);
  return {
    /** @param {{sub:string, username?:string, role:string}} profile lives as long as the id_token */
    mint: (profile, ttlSeconds) => jwt.sign(profile, ttlSeconds),
    verify: (token) => jwt.verify(token),
  };
}

/**
 * Where to send the browser after login or logout. Accepts absolute http(s) URLs whose host is
 * on the allowlist, and relative paths (which stay on this app). Everything else, including
 * protocol-relative URLs and the auth routes themselves, falls back to the given default.
 */
export function safeReturnUrl(value, allowedHosts, fallback) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2000) return fallback;
  if (value.startsWith('/')) {
    if (value.startsWith('//') || value.startsWith('/\\') || value.startsWith('/auth/')) return fallback;
    return value;
  }
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol)) return fallback;
    if (!allowedHosts.includes(url.host)) return fallback;
    if (url.pathname.startsWith('/auth/')) return fallback;
    return url.toString();
  } catch {
    return fallback;
  }
}

/** Parses a Cookie header into a plain object. Later duplicates win. */
export function parseCookies(cookieHeader) {
  const out = {};
  for (const part of (cookieHeader || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}
