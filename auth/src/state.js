// Login state and small helpers of the community app stand-in.
//
// The auth-state JWT carries state, nonce, PKCE verifier and the return URL through the login
// redirect in a short-lived cookie, so the app stays stateless. Its key is private to this app.

import { SignJWT, jwtVerify } from 'jose';

export const AUTH_COOKIE = 'example_auth';
const AUTHSTATE_TYP = 'example-authstate+jwt';

export function createAuthState({ secret, ttlSeconds = 300, allowedReturnHosts, fallbackReturn }) {
  const key = new TextEncoder().encode(secret);
  const sanitise = (value) => safeReturnUrl(value, allowedReturnHosts, fallbackReturn);
  return {
    sanitiseReturn: sanitise,

    /** @param {{state:string, nonce:string, codeVerifier:string, returnTo:string, silent:boolean}} data */
    mint: (data) =>
      new SignJWT(data)
        .setProtectedHeader({ alg: 'HS256', typ: AUTHSTATE_TYP })
        .setIssuedAt()
        .setExpirationTime(`${ttlSeconds}s`)
        .sign(key),

    /** Returns the auth state or null if the token is missing, expired or tampered. */
    async verify(token) {
      if (!token) return null;
      try {
        const { payload } = await jwtVerify(token, key, { algorithms: ['HS256'], typ: AUTHSTATE_TYP });
        return { ...payload, returnTo: sanitise(payload.returnTo) };
      } catch {
        return null;
      }
    },
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
