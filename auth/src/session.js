// Cookies and JWTs of the auth service.
//
// The session JWT is the only thing the browser receives for the site: role plus timestamps,
// nothing else. It is signed with HS256 and a secret shared only with Varnish, which verifies it
// in VCL. This service only mints it and never needs to read it back.
//
// The auth-state JWT carries state, nonce and PKCE verifier through the login redirect, so the
// service stays stateless. Both JWTs use the same key but different `typ` values, which is what
// lets Varnish reject an auth-state token presented as a session.

import { SignJWT, jwtVerify } from 'jose';

export const SESSION_COOKIE = 'example_session';
export const AUTH_COOKIE = 'example_auth';

const SESSION_TYP = 'example-session+jwt';
const AUTHSTATE_TYP = 'example-authstate+jwt';

export function createSessions({ secret, ttlSeconds, authStateTtlSeconds = 300 }) {
  const key = new TextEncoder().encode(secret);

  const sign = (payload, typ, ttl) =>
    new SignJWT(payload).setProtectedHeader({ alg: 'HS256', typ }).setIssuedAt().setExpirationTime(`${ttl}s`).sign(key);

  return {
    mintSession: (role) => sign({ role }, SESSION_TYP, ttlSeconds),

    /** @param {{state:string, nonce:string, codeVerifier:string, returnTo:string, silent:boolean}} data */
    mintAuthState: (data) => sign(data, AUTHSTATE_TYP, authStateTtlSeconds),

    /** Returns the auth state or null if the token is missing, expired, tampered or of another typ. */
    async verifyAuthState(token) {
      if (!token) return null;
      try {
        const { payload } = await jwtVerify(token, key, { algorithms: ['HS256'], typ: AUTHSTATE_TYP });
        return { ...payload, returnTo: safeReturnPath(payload.returnTo) };
      } catch {
        return null;
      }
    },
  };
}

/** Only relative paths within the site; never external targets or /auth/*. */
export function safeReturnPath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2000) return '/';
  if (value[0] !== '/' || value.startsWith('//') || value.startsWith('/\\')) return '/';
  if (value.startsWith('/auth/')) return '/';
  return value;
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
