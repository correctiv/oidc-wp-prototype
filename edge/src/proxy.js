// Reverse proxy to the origin with role derivation, header hygiene and caching.

import { Readable } from 'node:stream';
import { config } from './config.js';
import { MemoryCache, bypassReason, cacheKey, cacheTtlFromHeaders } from './cache.js';
import { AUTH_COOKIE, SESSION_COOKIE, parseCookies, stripCookies, verifySession } from './session.js';

export const cache = new MemoryCache();

/** Headers that are not forwarded end to end. */
const HOP_BY_HOP = ['connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate'];

export async function handleProxy(req, res) {
  const started = Date.now();
  const host = req.headers.host || new URL(config.publicUrl).host;
  const url = new URL(req.originalUrl, `${req.protocol}://${host}`);

  // 1. Derive the role from the session cookie. Anything but "valid" means "none".
  const session = await verifySession(parseCookies(req.headers.cookie)[SESSION_COOKIE]);
  const role = session.state === 'valid' ? session.role : 'none';

  // Expired JWT on an HTML navigation: one silent re-login at the IdP.
  // No loop is possible: if the silent login fails, the callback deletes the cookie.
  const wantsHtml = req.method === 'GET' && (req.headers.accept || '').includes('text/html');
  if (session.state === 'expired' && wantsHtml) {
    log(req.method, url, role, 'REFRESH', 302, started);
    res.set('Cache-Control', 'no-store');
    return res.redirect(302, `/auth/refresh?return=${encodeURIComponent(url.pathname + url.search)}`);
  }

  // 2. Cache decision
  const bypass = bypassReason(req.method, url.pathname, req.headers.cookie);
  const key = cacheKey({ role, host: url.host, pathname: url.pathname, search: url.search });

  if (!bypass) {
    const hit = cache.get(key);
    if (hit) {
      log(req.method, url, role, 'HIT', hit.status, started);
      return send(res, hit, {
        'X-Cache': 'HIT',
        'X-Example-Role': role,
        'X-Cache-Key': key,
        Age: String(Math.floor((Date.now() - hit.storedAt) / 1000)),
      });
    }
  }

  // 3. Origin request with sanitized headers
  let originRes;
  try {
    const hasBody = req.method !== 'GET' && req.method !== 'HEAD';
    originRes = await fetch(`${config.origin.url}${url.pathname}${url.search}`, {
      method: req.method,
      headers: buildOriginHeaders(req.headers, url, role),
      body: hasBody ? Readable.toWeb(req) : undefined,
      redirect: 'manual',
      ...(hasBody ? { duplex: 'half' } : {}),
    });
  } catch (err) {
    console.error(`[edge] origin unreachable: ${err.message}`);
    return res.status(502).set('Cache-Control', 'no-store').type('text/plain').send('502 Bad Gateway: origin unreachable');
  }

  const body = Buffer.from(await originRes.arrayBuffer());
  const headers = sanitizeResponseHeaders(originRes.headers, { keepSetCookie: Boolean(bypass) });
  const entry = { status: originRes.status, headers, body, storedAt: Date.now() };

  // 4. Store if allowed
  let cacheStatus = bypass ? 'BYPASS' : 'MISS';
  if (!bypass) {
    const ttl = cacheTtlFromHeaders(originRes.headers, config.cache.defaultTtlSeconds);
    if (originRes.status === 200 && ttl > 0) {
      cache.set(key, entry, ttl);
    } else {
      cacheStatus = 'UNCACHEABLE';
    }
  }

  log(req.method, url, role, bypass ? `BYPASS(${bypass})` : cacheStatus, originRes.status, started);
  return send(res, entry, {
    'X-Cache': cacheStatus,
    'X-Example-Role': role,
    ...(bypass ? {} : { 'X-Cache-Key': key }),
  });
}

function buildOriginHeaders(incoming, url, role) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming)) {
    if (HOP_BY_HOP.includes(name) || value === undefined) continue;
    for (const v of Array.isArray(value) ? value : [value]) headers.append(name, v);
  }

  // Whatever the client claims about its role or the edge is discarded.
  headers.delete('x-example-role');
  headers.delete('x-edge-secret');
  headers.delete('x-forwarded-host');
  headers.delete('x-forwarded-proto');
  headers.delete('x-forwarded-for');
  // The origin should answer uncompressed so the cache stores plain text.
  headers.delete('accept-encoding');

  // The edge cookies never leave the edge. WordPress never sees them.
  const cookie = stripCookies(incoming.cookie, [SESSION_COOKIE, AUTH_COOKIE]);
  if (cookie) headers.set('cookie', cookie);
  else headers.delete('cookie');

  // Note: Node's fetch (undici) drops a Host header set here. WordPress therefore receives the
  // public host via X-Forwarded-Host (see WORDPRESS_CONFIG_EXTRA in docker-compose.yml).
  headers.set('x-forwarded-host', url.host);
  headers.set('x-forwarded-proto', url.protocol.replace(':', ''));
  headers.set('x-example-role', role);
  headers.set('x-edge-secret', config.origin.sharedSecret);
  return headers;
}

/**
 * Response headers for cache and client. Set-Cookie is only passed through on BYPASS
 * (WordPress login for editors). On cacheable responses it is dropped and logged.
 */
function sanitizeResponseHeaders(originHeaders, { keepSetCookie }) {
  const out = [];
  for (const [name, value] of originHeaders) {
    if (HOP_BY_HOP.includes(name)) continue;
    if (name === 'content-length' || name === 'content-encoding') continue;
    if (name === 'set-cookie') continue; // handled separately
    // Rewrite absolute redirects to the internal origin host to the public URL.
    if (name === 'location' && value.startsWith(`${config.origin.url}/`)) {
      out.push([name, config.publicUrl + value.slice(config.origin.url.length)]);
      continue;
    }
    out.push([name, value]);
  }
  const setCookies = originHeaders.getSetCookie();
  if (setCookies.length > 0) {
    if (keepSetCookie) {
      for (const sc of setCookies) out.push(['set-cookie', sc]);
    } else {
      const names = setCookies.map((sc) => sc.split('=')[0]).join(', ');
      console.warn(`[edge] origin tried to set cookies on a cacheable response, dropped: ${names}`);
    }
  }
  return out;
}

/** Writes a stored/origin response. Uses res.end() to avoid Express' ETag and Content-Type logic. */
function send(res, entry, extraHeaders) {
  res.status(entry.status);
  for (const [name, value] of entry.headers) res.append(name, value);
  for (const [name, value] of Object.entries(extraHeaders)) res.set(name, value);
  if (entry.status === 204 || entry.status === 304) return res.end();
  return res.end(entry.body);
}

function log(method, url, role, cacheStatus, status, started) {
  // Deliberately without cookies, tokens or query strings.
  console.log(`[edge] ${method} ${url.pathname} role=${role} cache=${cacheStatus} status=${status} ${Date.now() - started}ms`);
}
