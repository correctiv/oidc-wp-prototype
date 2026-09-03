// Edge prototype: OIDC relying party + role-based cache in front of WordPress.
//
//   /auth/login     start the login at the IdP
//   /auth/refresh   silent re-login (prompt=none) after the role JWT expired
//   /auth/callback  exchange the code for an id_token, extract the role, set the session cookie
//   /auth/logout    delete the session cookie, RP-initiated logout at the IdP
//   /_edge/cache    debug view of the cache (prototype only)
//   *               proxy to WordPress with X-Example-Role and a cache per role

import express from 'express';
import { config } from './config.js';
import { buildLogoutUrl, completeLogin, createAuthRequest, getOidcConfig } from './oidc.js';
import { cache, handleProxy } from './proxy.js';
import {
  AUTH_COOKIE,
  SESSION_COOKIE,
  cookieOptions,
  mintAuthState,
  mintSession,
  parseCookies,
  safeReturnPath,
  verifyAuthState,
} from './session.js';

const app = express();
app.disable('x-powered-by');
app.set('etag', false);

const str = (v) => (typeof v === 'string' ? v : undefined);

// Nothing under /auth/* or /_edge/* may be cached anywhere.
const noStore = (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
};
app.use('/auth', noStore);
app.use('/_edge', noStore);

async function startAuth(req, res, { silent }) {
  const returnTo = safeReturnPath(str(req.query.return));
  const { state, nonce, codeVerifier, url } = await createAuthRequest({ silent });

  const authState = await mintAuthState({ state, nonce, codeVerifier, returnTo, silent });
  res.cookie(AUTH_COOKIE, authState, cookieOptions(config.session.authStateTtlSeconds));

  console.log(`[auth] ${silent ? 'silent re-login' : 'login'} started, return=${returnTo}`);
  res.redirect(302, url);
}

app.get('/auth/login', (req, res) => startAuth(req, res, { silent: false }));
app.get('/auth/refresh', (req, res) => startAuth(req, res, { silent: true }));

app.get('/auth/callback', async (req, res) => {
  const authState = await verifyAuthState(parseCookies(req.headers.cookie)[AUTH_COOKIE]);
  res.clearCookie(AUTH_COOKIE, cookieOptions());

  if (!authState) {
    return res.status(400).type('text/plain').send('Login state is missing or expired. Please log in again.');
  }

  const state = str(req.query.state);
  const code = str(req.query.code);
  const error = str(req.query.error);
  const errorDescription = str(req.query.error_description);

  if (state !== authState.state) {
    return res.status(400).type('text/plain').send('Invalid state parameter.');
  }

  if (error) {
    // Typically login_required / interaction_required during a silent re-login when the IdP
    // session has expired. The user then falls back cleanly to "none".
    res.clearCookie(SESSION_COOKIE, cookieOptions());
    console.log(`[auth] IdP error: ${error} (silent=${authState.silent})`);
    if (authState.silent) return res.redirect(302, authState.returnTo);
    return res.status(400).type('text/plain').send(`Login failed: ${error}${errorDescription ? ` (${errorDescription})` : ''}`);
  }

  if (!code) return res.status(400).type('text/plain').send('No authorization code received.');

  try {
    const callbackUrl = new URL(req.originalUrl, config.publicUrl);
    const role = await completeLogin(callbackUrl, authState);
    const session = await mintSession(role);
    res.cookie(SESSION_COOKIE, session, cookieOptions(config.session.cookieMaxAgeSeconds));
    console.log(`[auth] login successful, role=${role} silent=${authState.silent}`);
    return res.redirect(302, authState.returnTo);
  } catch (err) {
    console.error(`[auth] callback failed: ${err.message}`);
    res.clearCookie(SESSION_COOKIE, cookieOptions());
    if (authState.silent) return res.redirect(302, authState.returnTo);
    return res.status(502).type('text/plain').send('Login failed. See the edge log for details.');
  }
});

app.get('/auth/logout', async (req, res) => {
  res.clearCookie(SESSION_COOKIE, cookieOptions());
  res.clearCookie(AUTH_COOKIE, cookieOptions());
  console.log('[auth] logout, redirecting to the IdP');
  res.redirect(302, await buildLogoutUrl(`${config.publicUrl}/`));
});

if (config.debug) {
  app.get('/_edge/cache', (req, res) => res.json({ entries: cache.snapshot() }));
  app.delete('/_edge/cache', (req, res) => {
    cache.clear();
    res.json({ cleared: true });
  });
}

app.all('/{*path}', handleProxy);

// Express 5 forwards rejected promises here.
app.use((err, req, res, next) => {
  console.error(`[edge] unhandled error: ${err.message}`);
  res.status(500).set('Cache-Control', 'no-store').type('text/plain').send('500 Internal Server Error');
});

app.listen(config.port, () => {
  console.log(`[edge] listening on :${config.port}, public=${config.publicUrl}, origin=${config.origin.url}, issuer=${config.oidc.issuer}`);
  // Warm up discovery; failures are logged only, the first request retries.
  getOidcConfig().catch((err) => console.warn(`[oidc] discovery not yet possible: ${err.message}`));
});
