// Stand-in for the community app: the OIDC relying party for the whole example.localhost domain.
//
// It logs users in at the IdP and stores the resulting id_token in a cookie scoped to the parent
// domain, so the website (www.example.localhost, behind HAProxy) receives it too. HAProxy
// verifies that cookie on every request and turns it into X-Example-Role; this app never has to.
//
//   /               tiny status page (what the real community app would be)
//   /auth/login     start the login at the IdP, then return to ?return=
//   /auth/refresh   silent re-login (prompt=none) after the id_token expired
//   /auth/callback  exchange the code, set the cookies, redirect to the return URL
//   /auth/logout    delete the cookies, RP-initiated logout at the IdP, return to ?return=
//   /contact/me     JSON about the logged-in user, for the website's client-side call (CORS)
//
// Two cookies: example_session (Domain=example.localhost, the lean id_token, read by HAProxy) and
// community_session (host-only, this app's own login with the profile from userinfo).

import express from 'express';
import { decodeJwt } from 'jose';
import { createOidc } from './oidc.js';
import { AUTH_COOKIE, COMMUNITY_COOKIE, createAuthState, createCommunitySession, parseCookies } from './state.js';

function env(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') {
    if (fallback === undefined) throw new Error(`Missing environment variable ${name}`);
    return fallback;
  }
  return value;
}

const LOGIN_COOKIE = 'example_session';
// Every logged-in user has one of these; "none" is what the website uses for anonymous visitors.
const LEVELS = ['limited', 'full'];

const appUrl = env('APP_URL').replace(/\/+$/, '');
const siteUrl = env('SITE_URL').replace(/\/+$/, '');
const port = Number(env('PORT', '3000'));
const cookieDomain = env('COOKIE_DOMAIN');
const cookieMaxAgeSeconds = Number(env('COOKIE_MAX_AGE_SECONDS', '43200'));
const secure = appUrl.startsWith('https://');

const authState = createAuthState({
  secret: env('APP_SECRET'),
  allowedReturnHosts: env('ALLOWED_RETURN_HOSTS').split(',').map((h) => h.trim()),
  fallbackReturn: `${appUrl}/`,
});
const communitySession = createCommunitySession({ secret: env('APP_SECRET') });

const oidc = createOidc({
  issuer: env('OIDC_ISSUER').replace(/\/+$/, ''),
  clientId: env('OIDC_CLIENT_ID'),
  clientSecret: env('OIDC_CLIENT_SECRET'),
  redirectUri: `${appUrl}/auth/callback`,
  debugClaims: env('DEBUG_CLAIMS', '0') === '1',
});

// The login cookie is scoped to the parent domain on purpose: that is what lets the website see
// it. Every other subdomain receives it as well, which is why it holds a lean id_token only.
const loginCookie = { domain: cookieDomain, path: '/', httpOnly: true, sameSite: 'lax', secure };
// The app's own cookies stay host-only; nobody but this app needs them.
const stateCookie = { path: '/', httpOnly: true, sameSite: 'lax', secure };
const sessionCookie = { path: '/', httpOnly: true, sameSite: 'lax', secure };

const str = (v) => (typeof v === 'string' ? v : undefined);

const app = express();
app.disable('x-powered-by');
app.set('etag', false);

// Nothing this app answers may be cached anywhere.
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// The website calls /contact/* from the browser. Cross-origin but same-site, so the browser
// sends the cookies as long as the page asks with credentials: 'include' and this app allows
// exactly that origin. A wildcard origin is not allowed together with credentials.
app.use('/contact', (req, res, next) => {
  if (req.headers.origin === siteUrl) {
    res.set('Access-Control-Allow-Origin', siteUrl);
    res.set('Access-Control-Allow-Credentials', 'true');
    res.set('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.get('/contact/me', async (req, res) => {
  const session = await communitySession.verify(parseCookies(req.headers.cookie)[COMMUNITY_COOKIE]);
  if (!session) return res.status(401).json({ error: 'not logged in' });
  res.json({ id: session.sub, username: session.username ?? null, role: session.role, sessionExpiresAt: new Date(session.exp * 1000).toISOString() });
});

app.get('/', async (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const session = await communitySession.verify(cookies[COMMUNITY_COOKIE]);
  let status = session ? `Logged in as <strong>${session.username ?? session.sub}</strong> (role ${session.role}).` : 'You are not logged in.';
  if (cookies[LOGIN_COOKIE]) {
    try {
      const claims = decodeJwt(cookies[LOGIN_COOKIE]);
      const expired = typeof claims.exp === 'number' && claims.exp * 1000 < Date.now();
      status += ` Domain cookie for ${cookieDomain}: ${expired ? 'expired' : 'valid'} id_token with claims ${Object.keys(claims).join(', ')}.`;
    } catch {
      status += ' Domain cookie present but not a JWT.';
    }
  }
  const back = encodeURIComponent(`${appUrl}/`);
  res.type('html').send(`<!doctype html><title>Community app</title>
<h1>Community app (stand-in)</h1>
<p>${status}</p>
<p><a href="/auth/login?return=${back}">Log in</a> · <a href="/auth/logout?return=${back}">Log out</a> · <a href="/contact/me">/contact/me</a> · <a href="${siteUrl}/">Go to the website</a></p>
<p><small>The real community app would live here. In this prototype it plays the OIDC relying party and answers /contact/me.</small></p>`);
});

async function startAuth(req, res, { silent }) {
  const returnTo = authState.sanitiseReturn(str(req.query.return));
  const { state, nonce, codeVerifier, url } = await oidc.createAuthRequest({ silent });
  res.cookie(AUTH_COOKIE, await authState.mint({ state, nonce, codeVerifier, returnTo, silent }), { ...stateCookie, maxAge: 300_000 });
  console.log(`[auth] ${silent ? 'silent re-login' : 'login'} started, return=${returnTo}`);
  res.redirect(302, url);
}

app.get('/auth/login', (req, res) => startAuth(req, res, { silent: false }));
app.get('/auth/refresh', (req, res) => startAuth(req, res, { silent: true }));

app.get('/auth/callback', async (req, res) => {
  const state = await authState.verify(parseCookies(req.headers.cookie)[AUTH_COOKIE]);
  res.clearCookie(AUTH_COOKIE, stateCookie);
  if (!state) return res.status(400).type('text/plain').send('Login state is missing or expired. Please log in again.');
  if (str(req.query.state) !== state.state) return res.status(400).type('text/plain').send('Invalid state parameter.');

  const error = str(req.query.error);
  if (error) {
    // Typically login_required / interaction_required during a silent re-login when the IdP
    // session has expired. The user then falls back cleanly to "none" on the website.
    res.clearCookie(LOGIN_COOKIE, loginCookie);
    res.clearCookie(COMMUNITY_COOKIE, sessionCookie);
    console.log(`[auth] IdP error: ${error} (silent=${state.silent})`);
    if (state.silent) return res.redirect(302, state.returnTo);
    return res.status(400).type('text/plain').send(`Login failed: ${error}`);
  }

  try {
    const { idToken, claims, userinfo } = await oidc.completeLogin(new URL(req.originalUrl, appUrl), state);
    const role = claims.example_role;
    if (!LEVELS.includes(role)) {
      // The IdP is expected to assign a level to every account. Fail closed rather than log the
      // user in without one.
      console.error(`[auth] id_token without a valid access level (got ${JSON.stringify(role ?? null)})`);
      res.clearCookie(LOGIN_COOKIE, loginCookie);
      res.clearCookie(COMMUNITY_COOKIE, sessionCookie);
      if (state.silent) return res.redirect(302, state.returnTo);
      return res.status(403).type('text/plain').send('Your account has no access level assigned. Please contact support.');
    }
    const ttlSeconds = Math.max(1, claims.exp - Math.floor(Date.now() / 1000));
    res.cookie(LOGIN_COOKIE, idToken, { ...loginCookie, maxAge: cookieMaxAgeSeconds * 1000 });
    const profile = { sub: claims.sub, username: userinfo.preferred_username, role };
    res.cookie(COMMUNITY_COOKIE, await communitySession.mint(profile, ttlSeconds), { ...sessionCookie, maxAge: ttlSeconds * 1000 });
    console.log(`[auth] login successful, role=${role} silent=${state.silent}`);
    return res.redirect(302, state.returnTo);
  } catch (err) {
    console.error(`[auth] callback failed: ${err.message}`);
    res.clearCookie(LOGIN_COOKIE, loginCookie);
    res.clearCookie(COMMUNITY_COOKIE, sessionCookie);
    if (state.silent) return res.redirect(302, state.returnTo);
    return res.status(502).type('text/plain').send('Login failed. See the community app log for details.');
  }
});

app.get('/auth/logout', async (req, res) => {
  const returnTo = new URL(authState.sanitiseReturn(str(req.query.return)), appUrl).toString();
  res.clearCookie(LOGIN_COOKIE, loginCookie);
  res.clearCookie(COMMUNITY_COOKIE, sessionCookie);
  res.clearCookie(AUTH_COOKIE, stateCookie);
  console.log(`[auth] logout, redirecting to the IdP, return=${returnTo}`);
  res.redirect(302, await oidc.buildLogoutUrl(returnTo));
});

// Express 5 forwards rejected promises here.
app.use((err, req, res, next) => {
  console.error(`[auth] unhandled error: ${err.message}`);
  res.status(500).type('text/plain').send('500 Internal Server Error');
});

app.listen(port, () => {
  console.log(`[auth] listening on :${port}, app=${appUrl}, cookie domain=${cookieDomain}`);
  // Warm up discovery; failures are logged only, the first request retries.
  oidc.configuration().catch((err) => console.warn(`[oidc] discovery not yet possible: ${err.message}`));
});
