// Session JWT and auth-state JWT.
//
// The session JWT is the only thing the browser receives for the site. It contains the role and
// timestamps, nothing else: no user id, no email, no IdP token. Signed with HS256 using an
// edge-owned secret the IdP does not know.

import { SignJWT, jwtVerify, errors } from 'jose';
import { config, normalizeRole } from './config.js';

export const SESSION_COOKIE = 'example_session';
export const AUTH_COOKIE = 'example_auth';

const SESSION_TYP = 'example-session+jwt';
const AUTHSTATE_TYP = 'example-authstate+jwt';

const key = new TextEncoder().encode(config.session.secret);

const nowSeconds = () => Math.floor(Date.now() / 1000);

export async function mintSession(role) {
  return new SignJWT({ role: normalizeRole(role) })
    .setProtectedHeader({ alg: 'HS256', typ: SESSION_TYP })
    .setIssuedAt()
    .setExpirationTime(nowSeconds() + config.session.ttlSeconds)
    .sign(key);
}

/**
 * @returns {Promise<{state:'missing'}|{state:'invalid'}|{state:'expired'}|{state:'valid', role:string}>}
 */
export async function verifySession(token) {
  if (!token) return { state: 'missing' };
  try {
    const { payload } = await jwtVerify(token, key, { algorithms: ['HS256'], typ: SESSION_TYP });
    return { state: 'valid', role: normalizeRole(payload.role) };
  } catch (err) {
    if (err instanceof errors.JWTExpired) return { state: 'expired' };
    return { state: 'invalid' };
  }
}

/**
 * Intermediate login state, signed into a cookie instead of kept in server memory.
 * @param {{state:string, nonce:string, codeVerifier:string, returnTo:string, silent:boolean}} data
 */
export async function mintAuthState(data) {
  return new SignJWT({
    st: data.state,
    nc: data.nonce,
    cv: data.codeVerifier,
    rt: data.returnTo,
    si: data.silent ? 1 : 0,
  })
    .setProtectedHeader({ alg: 'HS256', typ: AUTHSTATE_TYP })
    .setIssuedAt()
    .setExpirationTime(nowSeconds() + config.session.authStateTtlSeconds)
    .sign(key);
}

export async function verifyAuthState(token) {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, key, { algorithms: ['HS256'], typ: AUTHSTATE_TYP });
    return {
      state: String(payload.st),
      nonce: String(payload.nc),
      codeVerifier: String(payload.cv),
      returnTo: safeReturnPath(payload.rt),
      silent: payload.si === 1,
    };
  } catch {
    return null;
  }
}

/** Only relative paths within the site; never external targets or /auth/*. */
export function safeReturnPath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2000) return '/';
  if (value[0] !== '/' || value.startsWith('//') || value.startsWith('/\\')) return '/';
  if (value.startsWith('/auth/') || value.startsWith('/_edge/')) return '/';
  return value;
}

/** Express cookie options. maxAge is in seconds here and converted to milliseconds. */
export function cookieOptions(maxAgeSeconds) {
  return {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    secure: config.secureCookies,
    ...(maxAgeSeconds !== undefined ? { maxAge: maxAgeSeconds * 1000 } : {}),
  };
}

/** Parses a Cookie header into a plain object. Later duplicates win. */
export function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    out[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
  }
  return out;
}

/** Removes the named cookies from a Cookie header. Returns null if nothing is left. */
export function stripCookies(cookieHeader, names) {
  if (!cookieHeader) return null;
  const kept = cookieHeader
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .filter((part) => {
      const eq = part.indexOf('=');
      const name = eq === -1 ? part : part.slice(0, eq);
      return !names.includes(name);
    });
  return kept.length > 0 ? kept.join('; ') : null;
}
