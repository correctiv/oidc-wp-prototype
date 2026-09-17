import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeJwt } from 'jose';
import { createAuthState, parseCookies, safeReturnUrl } from '../src/state.js';

const hosts = ['www.example.localhost:8000', 'community.example.localhost:8001'];
const fallback = 'http://community.example.localhost:8001/';
const authState = createAuthState({ secret: 'test-secret-test-secret-test-secret-1234', allowedReturnHosts: hosts, fallbackReturn: fallback });
const data = { state: 's1', nonce: 'n1', codeVerifier: 'cv1', returnTo: 'http://www.example.localhost:8000/members/', silent: true };

test('auth state: round trip', async () => {
  const back = await authState.verify(await authState.mint(data));
  assert.deepEqual({ ...back, iat: undefined, exp: undefined }, { ...data, iat: undefined, exp: undefined });
});

test('auth state: missing or tampered is rejected', async () => {
  assert.equal(await authState.verify(undefined), null);
  assert.equal(await authState.verify('abc'), null);
  const token = await authState.mint(data);
  const [h, p, s] = token.split('.');
  const payload = decodeJwt(token);
  payload.returnTo = 'https://evil.example/';
  const forged = [h, Buffer.from(JSON.stringify(payload)).toString('base64url'), s].join('.');
  assert.equal(await authState.verify(forged), null);
});

test('auth state: return URL is sanitised on read', async () => {
  const token = await authState.mint({ ...data, returnTo: 'https://evil.example/' });
  assert.equal((await authState.verify(token)).returnTo, fallback);
});

test('safeReturnUrl: allowlisted absolute URLs and relative paths only', () => {
  assert.equal(safeReturnUrl('http://www.example.localhost:8000/members/?a=1', hosts, fallback), 'http://www.example.localhost:8000/members/?a=1');
  assert.equal(safeReturnUrl('/somewhere', hosts, fallback), '/somewhere');
  assert.equal(safeReturnUrl('https://evil.example/', hosts, fallback), fallback);
  assert.equal(safeReturnUrl('http://www.example.localhost:9999/', hosts, fallback), fallback);
  assert.equal(safeReturnUrl('//evil.example', hosts, fallback), fallback);
  assert.equal(safeReturnUrl('/\\evil.example', hosts, fallback), fallback);
  assert.equal(safeReturnUrl('/auth/login', hosts, fallback), fallback);
  assert.equal(safeReturnUrl('http://www.example.localhost:8000/auth/login', hosts, fallback), fallback);
  assert.equal(safeReturnUrl('javascript:alert(1)', hosts, fallback), fallback);
  assert.equal(safeReturnUrl(undefined, hosts, fallback), fallback);
});

test('parseCookies: parses a Cookie header', () => {
  assert.deepEqual(parseCookies('a=1; example_session=x.y.z; b=2'), { a: '1', example_session: 'x.y.z', b: '2' });
  assert.deepEqual(parseCookies(undefined), {});
});

test('community session: round trip, and not interchangeable with the auth state', async () => {
  const { createCommunitySession } = await import('../src/state.js');
  const session = createCommunitySession({ secret: 'test-secret-test-secret-test-secret-1234' });
  const token = await session.mint({ sub: 'u1', username: 'anna', role: 'full' }, 60);
  const back = await session.verify(token);
  assert.equal(back.username, 'anna');
  assert.equal(back.role, 'full');
  assert.equal(await authState.verify(token), null);
  assert.equal(await session.verify(await authState.mint(data)), null);
});
