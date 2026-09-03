// In-memory cache plus the rules for what gets cached and under which key.
//
// The cache key contains the role explicitly. `Vary` is deliberately not evaluated, because many
// CDNs handle Vary on arbitrary headers unreliably. Static assets do not vary by role.

/** Paths that are never cached. */
export const BYPASS_PREFIXES = ['/wp-admin', '/wp-login.php', '/wp-cron.php', '/xmlrpc.php', '/auth/', '/_edge/'];

/** Paths whose content is identical for every role. */
export const ASSET_PREFIXES = ['/wp-content/', '/wp-includes/'];

/** Cookies that indicate a logged-in WordPress editor. Such requests bypass the cache. */
const WP_LOGIN_COOKIE = /(?:^|;\s*)(wordpress_logged_in_|wordpress_sec_|wp-postpass_)/;

export function isAsset(pathname) {
  return ASSET_PREFIXES.some((p) => pathname.startsWith(p));
}

/** @returns {null|'method'|'path'|'wp-login-cookie'} */
export function bypassReason(method, pathname, cookieHeader) {
  if (method !== 'GET' && method !== 'HEAD') return 'method';
  if (BYPASS_PREFIXES.some((p) => pathname.startsWith(p))) return 'path';
  if (cookieHeader && WP_LOGIN_COOKIE.test(cookieHeader)) return 'wp-login-cookie';
  return null;
}

export function cacheKey({ role, host, pathname, search }) {
  const roleKey = isAsset(pathname) ? '-' : role;
  return `${roleKey}|${host}|${pathname}${search || ''}`;
}

/**
 * TTL in seconds derived from the origin's Cache-Control. 0 means: do not cache.
 * s-maxage wins over max-age; without either, the default applies.
 */
export function cacheTtlFromHeaders(headers, defaultTtl) {
  const cc = (headers.get('cache-control') || '').toLowerCase();
  if (/\b(no-store|private|no-cache)\b/.test(cc)) return 0;
  const sMaxAge = cc.match(/\bs-maxage=(\d+)/);
  if (sMaxAge) return Number(sMaxAge[1]);
  const maxAge = cc.match(/\bmax-age=(\d+)/);
  if (maxAge) return Number(maxAge[1]);
  return defaultTtl;
}

export class MemoryCache {
  constructor() {
    this.map = new Map();
  }

  get(key) {
    const entry = this.map.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.map.delete(key);
      return null;
    }
    return entry;
  }

  set(key, { status, headers, body }, ttlSeconds) {
    const now = Date.now();
    this.map.set(key, { status, headers, body, storedAt: now, expiresAt: now + ttlSeconds * 1000 });
  }

  clear() {
    this.map.clear();
  }

  /** For the debug view. */
  snapshot() {
    const now = Date.now();
    const entries = [];
    for (const [key, entry] of this.map) {
      if (entry.expiresAt <= now) {
        this.map.delete(key);
        continue;
      }
      entries.push({
        key,
        status: entry.status,
        bytes: entry.body.byteLength,
        ageSeconds: Math.floor((now - entry.storedAt) / 1000),
        ttlRemainingSeconds: Math.ceil((entry.expiresAt - now) / 1000),
      });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }
}
