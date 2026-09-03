#!/usr/bin/env node
// Plays the browser: login at the IdP through the edge, logout, silent refresh.
// No dependencies, Node >= 22 only.
//
//   node scripts/login-flow.mjs login anna                 # expects role full
//   node scripts/login-flow.mjs login ben                  # expects role limited
//   node scripts/login-flow.mjs login carla                # expects role none (logged in, but no level)
//   node scripts/login-flow.mjs logout anna                # login, then logout via the edge -> none
//   node scripts/login-flow.mjs refresh anna --wait 7      # login, let the JWT expire -> silent re-login keeps the role
//   node scripts/login-flow.mjs refresh-fail anna --wait 7 # login, end the IdP session, let the JWT expire -> none
//
// The refresh scenarios need a short JWT lifetime, e.g.:
//   SESSION_TTL_SECONDS=5 docker compose up -d edge
//
// Note: Keycloak sets Secure cookies on *.localhost (browsers treat *.localhost as a secure
// context). curl drops such cookies over http, which is why this script exists instead of curl.

const EDGE = process.env.EDGE_URL || 'http://www.localhost:8000';
const IDP = process.env.IDP_URL || 'http://auth.localhost:8080/realms/example';
const EXPECTED = { anna: 'full', ben: 'limited', carla: 'none' };
// Text markers from the demo content, used to show which sections are visible.
const SECTIONS = ['You are not logged in', 'From level limited', 'You have limited access', 'Level full only'];

const [scenario, user, ...rest] = process.argv.slice(2);
const waitIdx = rest.indexOf('--wait');
const waitSeconds = waitIdx === -1 ? 0 : Number(rest[waitIdx + 1]);
const password = process.env.DEMO_PASSWORD || 'password';

if (!scenario || !user) {
  console.error('usage: login-flow.mjs <login|logout|refresh|refresh-fail> <user> [--wait N]');
  process.exit(2);
}

// --- Minimal per-host cookie jar. Path and Secure are ignored on purpose. ---
const jar = new Map();
function cookieHeader(url) {
  const c = jar.get(url.host);
  return c && c.size ? [...c].map(([k, v]) => `${k}=${v}`).join('; ') : undefined;
}
function storeCookies(url, res) {
  for (const sc of res.headers.getSetCookie()) {
    const [pair, ...attrs] = sc.split(';');
    const eq = pair.indexOf('=');
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    const lower = attrs.map((a) => a.trim().toLowerCase());
    const maxAge = lower.find((a) => a.startsWith('max-age='));
    const expires = lower.find((a) => a.startsWith('expires='));
    const expired = (maxAge && Number(maxAge.slice(8)) <= 0) || (expires && new Date(expires.slice(8)).getTime() <= Date.now());
    if (!jar.has(url.host)) jar.set(url.host, new Map());
    if (value === '' || expired) jar.get(url.host).delete(name);
    else jar.get(url.host).set(name, value);
  }
}

async function request(url, { method = 'GET', body, headers = {} } = {}) {
  url = new URL(url);
  const h = { accept: 'text/html,*/*', ...headers };
  const cookie = cookieHeader(url);
  if (cookie) h.cookie = cookie;
  const res = await fetch(url, { method, body, headers: h, redirect: 'manual' });
  storeCookies(url, res);
  return res;
}

/** Follows redirects like a browser and logs every hop. */
async function follow(url, opts, maxHops = 12) {
  let res = await request(url, opts);
  let current = new URL(url);
  let hops = 0;
  while ([301, 302, 303, 307, 308].includes(res.status)) {
    if (++hops > maxHops) throw new Error('too many redirects');
    const next = new URL(res.headers.get('location'), current);
    step(`  ↪ ${res.status} → ${short(next)}`);
    current = next;
    res = await request(next);
  }
  return { res, url: current, html: await res.text() };
}

function short(u) {
  const url = new URL(u);
  return `${url.host}${url.pathname}${url.search ? '?' + url.searchParams.keys().next().value + '=…' : ''}`;
}
const step = (msg) => console.log(msg);
const attr = (html, tag, name) => html.match(new RegExp(`<form[^>]*${tag}="${name}"[^>]*>`))?.[0];
const decode = (s) => s.replace(/&amp;/g, '&');

function formAction(html, formSelector, pageUrl) {
  const form = attr(html, 'id', formSelector) || html.match(new RegExp(`<form[^>]*action="[^"]*${formSelector}[^"]*"[^>]*>`))?.[0];
  if (!form) throw new Error(`form ${formSelector} not found`);
  const action = decode(form.match(/action="([^"]+)"/)[1]);
  return new URL(action, pageUrl);
}
function hiddenInputs(html) {
  const out = new URLSearchParams();
  for (const m of html.matchAll(/<input[^>]*type="hidden"[^>]*>/g)) {
    const name = m[0].match(/name="([^"]+)"/)?.[1];
    const value = m[0].match(/value="([^"]*)"/)?.[1] ?? '';
    if (name) out.set(name, value);
  }
  return out;
}

async function currentRole(path = '/') {
  const res = await request(`${EDGE}${path}`);
  if (res.status !== 200) throw new Error(`GET ${path}: HTTP ${res.status}`);
  const html = await res.text();
  const visible = SECTIONS.filter((s) => html.includes(s));
  step(`  ☐ visible sections on ${path}: ${visible.join(' | ') || '(none)'}  [${res.headers.get('x-cache')}]`);
  return { role: res.headers.get('x-example-role'), cache: res.headers.get('x-cache'), key: res.headers.get('x-cache-key') };
}

async function login() {
  step(`\n▶ Login as ${user} via ${EDGE}/auth/login`);
  const page = await follow(`${EDGE}/auth/login?return=/members/`);
  if (!page.html.includes('kc-form-login')) throw new Error('Keycloak login page not reached');
  const action = formAction(page.html, 'kc-form-login', page.url);
  const body = hiddenInputs(page.html);
  body.set('username', user);
  body.set('password', password);
  step(`  ✎ submitting the form to ${short(action)}`);
  const done = await follow(action, { method: 'POST', body, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  if (done.url.host !== new URL(EDGE).host || done.url.pathname !== '/members/') {
    throw new Error(`login did not end on /members/ but on ${done.url} (HTTP ${done.res.status})`);
  }
  step(`  ✓ back on ${short(done.url)} with role ${done.res.headers.get('x-example-role')}`);
  const sessionCookie = jar.get(new URL(EDGE).host)?.get('example_session');
  if (!sessionCookie) throw new Error('no example_session cookie set');
  const claims = JSON.parse(Buffer.from(sessionCookie.split('.')[1], 'base64url').toString());
  step(`  ✓ session JWT claims: ${JSON.stringify(claims)}  (no sub, no email)`);
  step(`  ✓ cookies for ${new URL(EDGE).host}: ${[...jar.get(new URL(EDGE).host).keys()].join(', ')}`);
  step(`  ✓ cookies for ${new URL(IDP).host}: ${[...(jar.get(new URL(IDP).host)?.keys() ?? [])].join(', ')}`);
  return currentRole();
}

async function edgeLogout() {
  step(`\n▶ Logout via ${EDGE}/auth/logout`);
  const page = await follow(`${EDGE}/auth/logout`);
  await confirmIdpLogout(page);
}

async function idpLogoutDirect() {
  step(`\n▶ Ending the IdP session directly at the IdP (edge cookie stays in place)`);
  const url = new URL(`${IDP}/protocol/openid-connect/logout`);
  url.searchParams.set('client_id', 'example-web');
  url.searchParams.set('post_logout_redirect_uri', `${EDGE}/`);
  await confirmIdpLogout(await follow(url));
}

async function confirmIdpLogout(page) {
  if (page.html.includes('logout-confirm')) {
    const action = formAction(page.html, 'logout-confirm', page.url);
    step(`  ✎ confirming the logout at the IdP`);
    const done = await follow(action, { method: 'POST', body: hiddenInputs(page.html), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    step(`  ✓ landed on ${short(done.url)}`);
  } else {
    step(`  ✓ landed on ${short(page.url)} (no confirmation needed)`);
  }
}

async function waitForExpiry() {
  step(`\n▶ Waiting ${waitSeconds}s for the role JWT to expire`);
  await new Promise((r) => setTimeout(r, waitSeconds * 1000));
  const res = await request(`${EDGE}/`);
  if (res.status !== 302 || !res.headers.get('location').startsWith('/auth/refresh')) {
    throw new Error(`expected 302 → /auth/refresh, got HTTP ${res.status} ${res.headers.get('location') ?? ''}`);
  }
  step(`  ↪ 302 → ${res.headers.get('location').split('?')[0]} (silent re-login, prompt=none)`);
  const done = await follow(new URL(res.headers.get('location'), EDGE));
  step(`  ✓ landed on ${short(done.url)} with role ${done.res.headers.get('x-example-role')}`);
  return currentRole();
}

function expect(label, actual, expected) {
  const ok = actual === expected;
  console.log(`${ok ? '✅' : '❌'} ${label}: ${actual}${ok ? '' : ` (expected ${expected})`}`);
  if (!ok) process.exitCode = 1;
}

try {
  const expectedRole = EXPECTED[user] ?? 'none';
  const after = await login();
  expect(`role after login (${user})`, after.role, expectedRole);

  if (scenario === 'logout') {
    await edgeLogout();
    expect('role after logout', (await currentRole()).role, 'none');
  } else if (scenario === 'refresh') {
    if (!waitSeconds) throw new Error('--wait N is required');
    expect('role after silent refresh', (await waitForExpiry()).role, expectedRole);
  } else if (scenario === 'refresh-fail') {
    if (!waitSeconds) throw new Error('--wait N is required');
    await idpLogoutDirect();
    expect('role after the IdP session ended', (await waitForExpiry()).role, 'none');
    const again = await request(`${EDGE}/`);
    expect('no further redirect (cookie deleted)', String(again.status), '200');
  } else if (scenario !== 'login') {
    throw new Error(`unknown scenario ${scenario}`);
  }
} catch (err) {
  console.error(`❌ ${err.message}`);
  process.exit(1);
}
