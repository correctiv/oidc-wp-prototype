import './_env.js';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mintAuthState, mintSession, parseCookies, safeReturnPath, stripCookies, verifyAuthState, verifySession } from '../src/session.js';

test('session: mint and verify return the role', async () => {
  const token = await mintSession('full');
  assert.deepEqual(await verifySession(token), { state: 'valid', role: 'full' });
});

test('session: unknown role becomes none', async () => {
  const token = await mintSession('admin');
  assert.deepEqual(await verifySession(token), { state: 'valid', role: 'none' });
});

test('session: missing cookie is missing', async () => {
  assert.deepEqual(await verifySession(undefined), { state: 'missing' });
  assert.deepEqual(await verifySession(''), { state: 'missing' });
});

test('session: tampered token is invalid', async () => {
  const token = await mintSession('limited');
  const [h, p, s] = token.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  payload.role = 'full';
  const forged = [h, Buffer.from(JSON.stringify(payload)).toString('base64url'), s].join('.');
  assert.deepEqual(await verifySession(forged), { state: 'invalid' });
  assert.deepEqual(await verifySession('abc'), { state: 'invalid' });
});

test('session: expired token is expired', async () => {
  const token = await mintSession('full');
  await new Promise((r) => setTimeout(r, 1100));
  assert.deepEqual(await verifySession(token), { state: 'expired' });
});

test('session: an auth-state token is not a valid session token', async () => {
  const token = await mintAuthState({ state: 's', nonce: 'n', codeVerifier: 'cv', returnTo: '/x', silent: false });
  assert.deepEqual(await verifySession(token), { state: 'invalid' });
});

test('auth state: round trip', async () => {
  const token = await mintAuthState({ state: 's1', nonce: 'n1', codeVerifier: 'cv1', returnTo: '/members/', silent: true });
  assert.deepEqual(await verifyAuthState(token), {
    state: 's1',
    nonce: 'n1',
    codeVerifier: 'cv1',
    returnTo: '/members/',
    silent: true,
  });
});

test('safeReturnPath: only relative site paths', () => {
  assert.equal(safeReturnPath('/members/?a=1'), '/members/?a=1');
  assert.equal(safeReturnPath('https://evil.example'), '/');
  assert.equal(safeReturnPath('//evil.example'), '/');
  assert.equal(safeReturnPath('/\\evil.example'), '/');
  assert.equal(safeReturnPath('/auth/login'), '/');
  assert.equal(safeReturnPath(undefined), '/');
  assert.equal(safeReturnPath(''), '/');
});

test('parseCookies: parses a Cookie header', () => {
  assert.deepEqual(parseCookies('a=1; example_session=x.y.z; b=2'), { a: '1', example_session: 'x.y.z', b: '2' });
  assert.deepEqual(parseCookies(undefined), {});
  assert.deepEqual(parseCookies('junk; a=1'), { a: '1' });
});

test('stripCookies: removes edge cookies, keeps the rest', () => {
  assert.equal(stripCookies('a=1; example_session=xyz; b=2', ['example_session']), 'a=1; b=2');
  assert.equal(stripCookies('example_session=xyz', ['example_session']), null);
  assert.equal(stripCookies(null, ['example_session']), null);
  assert.equal(stripCookies('example_auth=1; example_session=2', ['example_session', 'example_auth']), null);
});
