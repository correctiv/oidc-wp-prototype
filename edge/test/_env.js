// Minimal environment for unit tests. Must be imported before src/config.js.
process.env.PUBLIC_URL ??= 'http://www.localhost:8000';
process.env.ORIGIN_URL ??= 'http://wordpress';
process.env.OIDC_ISSUER ??= 'http://auth.localhost:8080/realms/example';
process.env.OIDC_CLIENT_ID ??= 'example-web';
process.env.OIDC_CLIENT_SECRET ??= 'secret';
process.env.SESSION_SECRET ??= 'test-secret-test-secret-test-secret-1234';
process.env.EDGE_SHARED_SECRET ??= 'edge-secret';
process.env.SESSION_TTL_SECONDS ??= '1';
