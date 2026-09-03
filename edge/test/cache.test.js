import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MemoryCache, bypassReason, cacheKey, cacheTtlFromHeaders } from '../src/cache.js';

test('cacheKey: the role is part of the key', () => {
  const base = { host: 'www.localhost:8000', pathname: '/', search: '' };
  assert.equal(cacheKey({ ...base, role: 'none' }), 'none|www.localhost:8000|/');
  assert.equal(cacheKey({ ...base, role: 'full' }), 'full|www.localhost:8000|/');
  assert.notEqual(cacheKey({ ...base, role: 'limited' }), cacheKey({ ...base, role: 'full' }));
});

test('cacheKey: the query string is part of the key', () => {
  const base = { role: 'none', host: 'h', pathname: '/p' };
  assert.notEqual(cacheKey({ ...base, search: '?a=1' }), cacheKey({ ...base, search: '' }));
});

test('cacheKey: assets do not vary by role', () => {
  const a = cacheKey({ role: 'full', host: 'h', pathname: '/wp-content/themes/x/style.css', search: '' });
  const b = cacheKey({ role: 'none', host: 'h', pathname: '/wp-content/themes/x/style.css', search: '' });
  assert.equal(a, b);
  assert.equal(a, '-|h|/wp-content/themes/x/style.css');
});

test('bypassReason: method, path, WP login cookie', () => {
  assert.equal(bypassReason('GET', '/', null), null);
  assert.equal(bypassReason('HEAD', '/', null), null);
  assert.equal(bypassReason('POST', '/', null), 'method');
  assert.equal(bypassReason('GET', '/wp-admin/', null), 'path');
  assert.equal(bypassReason('GET', '/wp-login.php', null), 'path');
  assert.equal(bypassReason('GET', '/auth/login', null), 'path');
  assert.equal(bypassReason('GET', '/', 'wordpress_logged_in_abc=1'), 'wp-login-cookie');
  assert.equal(bypassReason('GET', '/', 'foo=1; wordpress_sec_abc=1'), 'wp-login-cookie');
  assert.equal(bypassReason('GET', '/', 'example_session=abc'), null);
});

test('cacheTtlFromHeaders: s-maxage over max-age over default; private/no-store block', () => {
  const h = (cc) => new Headers(cc ? { 'cache-control': cc } : {});
  assert.equal(cacheTtlFromHeaders(h('public, s-maxage=300, max-age=10'), 60), 300);
  assert.equal(cacheTtlFromHeaders(h('max-age=10'), 60), 10);
  assert.equal(cacheTtlFromHeaders(h(null), 60), 60);
  assert.equal(cacheTtlFromHeaders(h('private, max-age=100'), 60), 0);
  assert.equal(cacheTtlFromHeaders(h('no-store'), 60), 0);
  assert.equal(cacheTtlFromHeaders(h('no-cache'), 60), 0);
});

test('MemoryCache: set/get/expire', async () => {
  const c = new MemoryCache();
  const entry = { status: 200, headers: [['content-type', 'text/html']], body: Buffer.from('x') };
  c.set('k', entry, 1);
  assert.equal(c.get('k').status, 200);
  assert.equal(c.snapshot().length, 1);
  await new Promise((r) => setTimeout(r, 1100));
  assert.equal(c.get('k'), null);
  assert.equal(c.snapshot().length, 0);
});
