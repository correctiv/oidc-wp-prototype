#!/usr/bin/env node
// Plays the browser: login via the community app (including the form hand-over to the website),
// logout, silent refresh, and what the website makes of its cookie. No dependencies, Node >= 22.
//
//   node scripts/login-flow.mjs login anna                 # expects role full on the website
//   node scripts/login-flow.mjs login ben                  # expects role limited
//   node scripts/login-flow.mjs logout anna                # login, then logout via the community app -> none
//   node scripts/login-flow.mjs refresh anna --wait 7      # login, let the id_token expire -> silent re-login keeps the role
//   node scripts/login-flow.mjs refresh-fail anna --wait 7 # login, end the IdP session, let the token expire -> none
//
// The refresh scenarios need a short id_token lifetime (accessTokenLifespan in the realm);
// scripts/demo.sh --with-refresh sets it temporarily through the Keycloak admin API.
//
// Note: Keycloak sets Secure cookies on *.localhost (browsers treat *.localhost as a secure
// context). curl drops such cookies over http, which is why this script exists instead of curl.

const SITE = process.env.SITE_URL || 'http://www.example.localhost:8000';
const COMMUNITY = process.env.COMMUNITY_URL || 'http://community.example.localhost:8001';
const IDP = process.env.IDP_URL || 'http://auth.example.localhost:8080/realms/example';
const EXPECTED = { anna: 'full', ben: 'limited' };
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

// --- Minimal cookie jar with Domain support. Path and Secure are ignored on purpose. ---
// key: domain -> Map(name -> {value, hostOnly})
const jar = new Map();
const domainMatches = (host, domain, hostOnly) => (hostOnly ? host === domain : host === domain || host.endsWith(`.${domain}`));
function cookieHeader(url) {
  const pairs = [];
  for (const [domain, cookies] of jar) {
    for (const [name, c] of cookies) if (domainMatches(url.hostname, domain, c.hostOnly)) pairs.push(`${name}=${c.value}`);
  }
  return pairs.length ? pairs.join('; ') : undefined;
}
function storeCookies(url, res) {
  for (const sc of res.headers.getSetCookie()) {
    const [pair, ...attrs] = sc.split(';');
    const eq = pair.indexOf('=');
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    const lower = attrs.map((a) => a.trim());
    const domainAttr = lower.find((a) => a.toLowerCase().startsWith('domain='))?.slice(7).replace(/^\./, '').toLowerCase();
    const maxAge = lower.find((a) => a.toLowerCase().startsWith('max-age='))?.slice(8);
    const expires = lower.find((a) => a.toLowerCase().startsWith('expires='))?.slice(8);
    const expired = (maxAge !== undefined && Number(maxAge) <= 0) || (expires && new Date(expires).getTime() <= Date.now());
    const domain = domainAttr || url.hostname;
    if (!jar.has(domain)) jar.set(domain, new Map());
    if (value === '' || expired) jar.get(domain).delete(name);
    else jar.get(domain).set(name, { value, hostOnly: !domainAttr });
  }
}
const cookieNames = (host) => {
  const names = [];
  for (const [domain, cookies] of jar) for (const [name, c] of cookies) if (domainMatches(host, domain, c.hostOnly)) names.push(`${name}${c.hostOnly ? '' : ` (Domain=${domain})`}`);
  return names.join(', ') || '(none)';
};

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
  const html = await res.text();
  // The community app hands the token to the website with an auto-submitting form; a browser
  // submits it with an Origin header, so do we.
  if (html.includes('id="handover"')) {
    const action = formAction(html, 'handover', current);
    step(`  ✎ auto-submitting the hand-over form to ${short(action)} (Origin: ${current.origin})`);
    return follow(action, { method: 'POST', body: hiddenInputs(html), headers: { 'content-type': 'application/x-www-form-urlencoded', origin: current.origin } }, maxHops - hops);
  }
  return { res, url: current, html };
}

function short(u) {
  const url = new URL(u);
  return `${url.host}${url.pathname}${url.search ? '?' + url.searchParams.keys().next().value + '=…' : ''}`;
}
const step = (msg) => console.log(msg);
const decode = (s) => s.replace(/&amp;/g, '&');

function formAction(html, formSelector, pageUrl) {
  const form = html.match(new RegExp(`<form[^>]*id="${formSelector}"[^>]*>`))?.[0] || html.match(new RegExp(`<form[^>]*action="[^"]*${formSelector}[^"]*"[^>]*>`))?.[0];
  if (!form) throw new Error(`form ${formSelector} not found`);
  return new URL(decode(form.match(/action="([^"]+)"/)[1]), pageUrl);
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
  const res = await request(`${SITE}${path}`);
  if (res.status !== 200) throw new Error(`GET ${path}: HTTP ${res.status}`);
  const html = await res.text();
  const visible = SECTIONS.filter((s) => html.includes(s));
  step(`  ☐ visible sections on ${path}: ${visible.join(' | ') || '(none)'}  [${res.headers.get('x-cache')}]`);
  return { role: res.headers.get('x-example-role'), cache: res.headers.get('x-cache') };
}

async function login() {
  const returnTo = `${SITE}/members/`;
  step(`\n▶ Login as ${user} via ${COMMUNITY}/auth/login, returning to ${returnTo}`);
  const page = await follow(`${COMMUNITY}/auth/login?return=${encodeURIComponent(returnTo)}`);
  if (!page.html.includes('kc-form-login')) throw new Error('Keycloak login page not reached');
  const body = hiddenInputs(page.html);
  body.set('username', user);
  body.set('password', password);
  const action = formAction(page.html, 'kc-form-login', page.url);
  step(`  ✎ submitting the form to ${short(action)}`);
  const done = await follow(action, { method: 'POST', body, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  if (done.url.toString() !== returnTo) throw new Error(`login did not end on ${returnTo} but on ${done.url} (HTTP ${done.res.status})`);
  step(`  ✓ back on ${short(done.url)} with role ${done.res.headers.get('x-example-role')}`);
  const siteHost = new URL(SITE).hostname;
  const cookie = jar.get(siteHost)?.get('example_session');
  if (!cookie) throw new Error('no example_session cookie on the website host');
  if (!cookie.hostOnly) throw new Error('example_session is not host-only');
  const claims = JSON.parse(Buffer.from(cookie.value.split('.')[1], 'base64url').toString());
  step(`  ✓ host-only id_token cookie on ${siteHost} carries: ${Object.keys(claims).join(', ')}  (role=${claims.example_role ?? 'none'})`);
  step(`  ✓ cookies sent to ${siteHost}: ${cookieNames(siteHost)}`);
  step(`  ✓ cookies sent to ${new URL(COMMUNITY).hostname}: ${cookieNames(new URL(COMMUNITY).hostname)}`);
  step(`  ✓ cookies sent to ${new URL(IDP).hostname}: ${cookieNames(new URL(IDP).hostname)}`);
  await contactMe();
  return currentRole();
}

/** What the website's client-side call sees: same-site XHR with cookies, answered with CORS headers. */
async function contactMe() {
  const res = await request(`${COMMUNITY}/contact/me`, { headers: { origin: SITE, accept: 'application/json' } });
  const body = res.status === 200 ? await res.json() : null;
  step(`  ☐ GET /contact/me from origin ${SITE}: HTTP ${res.status}, ` +
    `Access-Control-Allow-Origin=${res.headers.get('access-control-allow-origin')}, ` +
    `Access-Control-Allow-Credentials=${res.headers.get('access-control-allow-credentials')}` +
    (body ? `, username=${body.username}, role=${body.role}` : ''));
  return body;
}

async function communityLogout() {
  step(`\n▶ Logout via ${COMMUNITY}/auth/logout`);
  await confirmIdpLogout(await follow(`${COMMUNITY}/auth/logout?return=${encodeURIComponent(`${SITE}/`)}`));
}

async function idpLogoutDirect() {
  step(`\n▶ Ending the IdP session directly at the IdP (login cookie stays in place)`);
  const url = new URL(`${IDP}/protocol/openid-connect/logout`);
  url.searchParams.set('client_id', 'community-app');
  url.searchParams.set('post_logout_redirect_uri', `${SITE}/`);
  await confirmIdpLogout(await follow(url));
}

async function confirmIdpLogout(page) {
  if (page.html.includes('logout-confirm')) {
    step(`  ✎ confirming the logout at the IdP`);
    const done = await follow(formAction(page.html, 'logout-confirm', page.url), { method: 'POST', body: hiddenInputs(page.html), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    step(`  ✓ landed on ${short(done.url)}`);
  } else {
    step(`  ✓ landed on ${short(page.url)} (no confirmation needed)`);
  }
}

async function waitForExpiry() {
  step(`\n▶ Waiting ${waitSeconds}s for the id_token to expire`);
  await new Promise((r) => setTimeout(r, waitSeconds * 1000));
  const res = await request(`${SITE}/`);
  const location = res.headers.get('location') || '';
  if (res.status !== 302 || !location.includes('/auth/refresh')) {
    throw new Error(`expected 302 → …/auth/refresh, got HTTP ${res.status} ${location}`);
  }
  step(`  ↪ 302 → ${short(location)} (silent re-login, prompt=none)`);
  const done = await follow(location);
  step(`  ✓ landed on ${short(done.url)} with role ${done.res.headers.get('x-example-role')}`);
  return currentRole();
}

function expect(label, actual, expected) {
  const ok = actual === expected;
  console.log(`${ok ? '✅' : '❌'} ${label}: ${actual}${ok ? '' : ` (expected ${expected})`}`);
  if (!ok) process.exitCode = 1;
}

try {
  const expectedRole = EXPECTED[user];
  if (!expectedRole) throw new Error(`unknown demo user ${user}`);
  expect(`role after login (${user})`, (await login()).role, expectedRole);
  expect(`/contact/me knows the user (${user})`, (await contactMe())?.username, user);

  if (scenario === 'logout') {
    await communityLogout();
    expect('role after logout', (await currentRole()).role, 'none');
    expect('/contact/me after logout', String((await request(`${COMMUNITY}/contact/me`, { headers: { origin: SITE } })).status), '401');
  } else if (scenario === 'refresh') {
    if (!waitSeconds) throw new Error('--wait N is required');
    expect('role after silent refresh', (await waitForExpiry()).role, expectedRole);
  } else if (scenario === 'refresh-fail') {
    if (!waitSeconds) throw new Error('--wait N is required');
    await idpLogoutDirect();
    expect('role after the IdP session ended', (await waitForExpiry()).role, 'none');
    expect('no further redirect (cookie deleted)', String((await request(`${SITE}/`)).status), '200');
  } else if (scenario !== 'login') {
    throw new Error(`unknown scenario ${scenario}`);
  }
} catch (err) {
  console.error(`❌ ${err.message}`);
  process.exit(1);
}
