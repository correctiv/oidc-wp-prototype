import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { createSessions, parseCookies, safeReturnPath } from '../src/session.js';

const sessions = createSessions({ secret: 'test-secret-test-secret-test-secret-1234', ttlSeconds: 900 });
const authState = { state: 's1', nonce: 'n1', codeVerifier: 'cv1', returnTo: '/members/', silent: true };

test('session JWT: carries only role, iat and exp, with the typ Varnish pins', async () => {
  const token = await sessions.mintSession('full');
  assert.deepEqual(decodeProtectedHeader(token), { alg: 'HS256', typ: 'example-session+jwt' });
  const claims = decodeJwt(token);
  assert.deepEqual(Object.keys(claims).sort(), ['exp', 'iat', 'role']);
  assert.equal(claims.role, 'full');
  assert.equal(claims.exp - claims.iat, 900);
});

test('auth state: round trip', async () => {
  const token = await sessions.mintAuthState(authState);
  const back = await sessions.verifyAuthState(token);
  assert.deepEqual({ ...back, iat: undefined, exp: undefined }, { ...authState, iat: undefined, exp: undefined });
});

test('auth state: missing, tampered or wrong typ is rejected', async () => {
  assert.equal(await sessions.verifyAuthState(undefined), null);
  assert.equal(await sessions.verifyAuthState('abc'), null);
  const token = await sessions.mintAuthState(authState);
  const [h, p, s] = token.split('.');
  const payload = decodeJwt(token);
  payload.returnTo = 'https://evil.example';
  const forged = [h, Buffer.from(JSON.stringify(payload)).toString('base64url'), s].join('.');
  assert.equal(await sessions.verifyAuthState(forged), null);
  assert.equal(await sessions.verifyAuthState(await sessions.mintSession('full')), null);
});

test('auth state: return path is sanitised on read', async () => {
  const token = await sessions.mintAuthState({ ...authState, returnTo: '//evil.example' });
  assert.equal((await sessions.verifyAuthState(token)).returnTo, '/');
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
