// Auth service: the OIDC relying party behind Varnish. Varnish routes /auth/* here uncached and
// handles everything else itself (role from the session cookie, X-Example-Role, cache per role).
//
//   /auth/login     start the login at the IdP
//   /auth/refresh   silent re-login (prompt=none) after the role JWT expired
//   /auth/callback  exchange the code for an id_token, extract the role, set the session cookie
//   /auth/logout    delete the session cookie, RP-initiated logout at the IdP

import express from 'express';
import { createOidc } from './oidc.js';
import { AUTH_COOKIE, SESSION_COOKIE, createSessions, parseCookies, safeReturnPath } from './session.js';

function env(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') {
    if (fallback === undefined) throw new Error(`Missing environment variable ${name}`);
    return fallback;
  }
  return value;
}

const publicUrl = env('PUBLIC_URL').replace(/\/+$/, '');
const port = Number(env('PORT', '3000'));
// The cookie outlives the JWT so that an expired JWT can trigger the silent re-login.
const cookieMaxAgeSeconds = Number(env('SESSION_COOKIE_MAX_AGE_SECONDS', '43200'));

const sessions = createSessions({
  secret: env('SESSION_SECRET'),
  ttlSeconds: Number(env('SESSION_TTL_SECONDS', '900')),
});

const oidc = createOidc({
  issuer: env('OIDC_ISSUER').replace(/\/+$/, ''),
  clientId: env('OIDC_CLIENT_ID'),
  clientSecret: env('OIDC_CLIENT_SECRET'),
  redirectUri: `${publicUrl}/auth/callback`,
  roleClaim: env('OIDC_ROLE_CLAIM', 'example_role'),
  debugClaims: env('DEBUG_CLAIMS', '0') === '1',
});

/** Express cookie options; maxAge in seconds. Host-only (no Domain), so the IdP domain never sees it. */
const cookie = (maxAgeSeconds) => ({
  path: '/',
  httpOnly: true,
  sameSite: 'lax',
  secure: publicUrl.startsWith('https://'),
  ...(maxAgeSeconds !== undefined ? { maxAge: maxAgeSeconds * 1000 } : {}),
});

const str = (v) => (typeof v === 'string' ? v : undefined);

const app = express();
app.disable('x-powered-by');
app.set('etag', false);

// Nothing this service answers may be cached anywhere.
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

async function startAuth(req, res, { silent }) {
  const returnTo = safeReturnPath(str(req.query.return));
  const { state, nonce, codeVerifier, url } = await oidc.createAuthRequest({ silent });
  res.cookie(AUTH_COOKIE, await sessions.mintAuthState({ state, nonce, codeVerifier, returnTo, silent }), cookie(300));
  console.log(`[auth] ${silent ? 'silent re-login' : 'login'} started, return=${returnTo}`);
  res.redirect(302, url);
}

app.get('/auth/login', (req, res) => startAuth(req, res, { silent: false }));
app.get('/auth/refresh', (req, res) => startAuth(req, res, { silent: true }));

app.get('/auth/callback', async (req, res) => {
  const authState = await sessions.verifyAuthState(parseCookies(req.headers.cookie)[AUTH_COOKIE]);
  res.clearCookie(AUTH_COOKIE, cookie());
  if (!authState) return res.status(400).type('text/plain').send('Login state is missing or expired. Please log in again.');
  if (str(req.query.state) !== authState.state) return res.status(400).type('text/plain').send('Invalid state parameter.');

  const error = str(req.query.error);
  if (error) {
    // Typically login_required / interaction_required during a silent re-login when the IdP
    // session has expired. The user then falls back cleanly to "none".
    res.clearCookie(SESSION_COOKIE, cookie());
    console.log(`[auth] IdP error: ${error} (silent=${authState.silent})`);
    if (authState.silent) return res.redirect(302, authState.returnTo);
    return res.status(400).type('text/plain').send(`Login failed: ${error}`);
  }

  try {
    const role = await oidc.completeLogin(new URL(req.originalUrl, publicUrl), authState);
    res.cookie(SESSION_COOKIE, await sessions.mintSession(role), cookie(cookieMaxAgeSeconds));
    console.log(`[auth] login successful, role=${role} silent=${authState.silent}`);
    return res.redirect(302, authState.returnTo);
  } catch (err) {
    console.error(`[auth] callback failed: ${err.message}`);
    res.clearCookie(SESSION_COOKIE, cookie());
    if (authState.silent) return res.redirect(302, authState.returnTo);
    return res.status(502).type('text/plain').send('Login failed. See the auth service log for details.');
  }
});

app.get('/auth/logout', async (req, res) => {
  res.clearCookie(SESSION_COOKIE, cookie());
  res.clearCookie(AUTH_COOKIE, cookie());
  console.log('[auth] logout, redirecting to the IdP');
  res.redirect(302, await oidc.buildLogoutUrl(`${publicUrl}/`));
});

// Express 5 forwards rejected promises here.
app.use((err, req, res, next) => {
  console.error(`[auth] unhandled error: ${err.message}`);
  res.status(500).type('text/plain').send('500 Internal Server Error');
});

app.listen(port, () => {
  console.log(`[auth] listening on :${port}, public=${publicUrl}`);
  // Warm up discovery; failures are logged only, the first request retries.
  oidc.configuration().catch((err) => console.warn(`[oidc] discovery not yet possible: ${err.message}`));
});
