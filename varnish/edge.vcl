# Edge logic: derive the access level from the session JWT, enforce header hygiene, cache per role.
#
# The including file provides two backends (wordpress, auth) and `sub edge_config`, which sets
# var "session_key" (HMAC key of the session JWT). In Docker that is default.vcl + the rendered
# config.vcl; in varnishtest the .vtc.
#
# WordPress must only be reachable through this Varnish (network isolation); otherwise the
# X-Example-Role header could be forged by talking to WordPress directly.

import std;
import cookie;
import var;
import blob;
import digest;

# --- Role derivation --------------------------------------------------------------------------
# Sets req.http.X-Example-Role (none|limited|full) and req.http.X-Session-State
# (missing|invalid|expired|valid). Anything but "valid" yields "none".
sub edge_role_from_cookie {
    set req.http.X-Example-Role = "none";
    set req.http.X-Session-State = "missing";

    if (req.http.Cookie) {
        cookie.parse(req.http.Cookie);
        if (cookie.isset("example_session")) {
            set req.http.X-Session-Token = cookie.get("example_session");
            set req.http.X-Session-State = "invalid";
        }
    }

    if (req.http.X-Session-Token ~ "^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$") {
        set req.http.X-JWT-Header  = regsub(req.http.X-Session-Token, "^([^.]+)\.([^.]+)\.([^.]+)$", "\1");
        set req.http.X-JWT-Payload = regsub(req.http.X-Session-Token, "^([^.]+)\.([^.]+)\.([^.]+)$", "\2");
        set req.http.X-JWT-Sig     = regsub(req.http.X-Session-Token, "^([^.]+)\.([^.]+)\.([^.]+)$", "\3");
        set req.http.X-JWT-Header-Json = digest.base64url_nopad_decode(req.http.X-JWT-Header);

        # 1. Pin algorithm and token type, so the auth-state JWT (same key, other typ) is rejected.
        # 2. HMAC-SHA256 over "header.payload" must equal the signature. digest.hmac_sha256 returns
        #    "0x" + lowercase hex; the signature is transcoded from base64url to lowercase hex with
        #    the built-in vmod_blob (digest's own *_hex helpers are unreliable in 1.0.3).
        if (req.http.X-JWT-Header-Json ~ {""alg":"HS256""} &&
            req.http.X-JWT-Header-Json ~ {""typ":"example-session\+jwt""} &&
            regsub(digest.hmac_sha256(var.get("session_key"), req.http.X-JWT-Header + "." + req.http.X-JWT-Payload), "^0x", "")
                == blob.transcode(decoding = BASE64URLNOPAD, encoding = HEX, case = LOWER, encoded = req.http.X-JWT-Sig)) {

            set req.http.X-JWT-Claims = digest.base64url_nopad_decode(req.http.X-JWT-Payload);

            # 3. Expiry
            if (req.http.X-JWT-Claims ~ {""exp":[0-9]+"} &&
                std.integer(regsub(req.http.X-JWT-Claims, {"^.*"exp":([0-9]+).*$"}, "\1"), 0) > std.time2integer(now, 0)) {
                set req.http.X-Session-State = "valid";
                # 4. Role, whitelisted. Anything else stays "none".
                if (req.http.X-JWT-Claims ~ {""role":"(limited|full)""}) {
                    set req.http.X-Example-Role = regsub(req.http.X-JWT-Claims, {"^.*"role":"(limited|full)".*$"}, "\1");
                }
            } else {
                set req.http.X-Session-State = "expired";
            }
        }
    }
}

# Expired JWT on an HTML navigation: one silent re-login via the auth service.
# No loop is possible: if the silent login fails, the auth service deletes the cookie.
sub edge_refresh_redirect {
    # Minimal percent-encoding of the characters that matter inside a query value.
    set req.http.X-Refresh-Location = "/auth/refresh?return=" +
        regsuball(regsuball(regsuball(regsuball(regsuball(regsuball(req.url,
            "%", "%25"), "&", "%26"), "\?", "%3F"), "#", "%23"), "\+", "%2B"), "=", "%3D");
    return (synth(752));
}

# --- Request handling -------------------------------------------------------------------------
sub vcl_recv {
    call edge_config;

    if (req.method != "GET" && req.method != "HEAD" && req.method != "POST" &&
        req.method != "PUT" && req.method != "PATCH" && req.method != "DELETE" && req.method != "OPTIONS") {
        return (pipe);
    }

    # Nothing the client claims about its role or the edge is trusted.
    unset req.http.X-Example-Role;
    unset req.http.X-Forwarded-Host;
    unset req.http.X-Forwarded-Proto;
    unset req.http.X-Session-State;
    unset req.http.X-Session-Token;
    unset req.http.X-Cache-Decision;
    unset req.http.X-Cache-Key;

    # The auth service is the OIDC relying party: never cached, cookies passed untouched.
    if (req.url ~ "^/auth/") {
        set req.backend_hint = auth;
        set req.http.X-Cache-Decision = "BYPASS(auth)";
        return (pass);
    }

    set req.backend_hint = wordpress;
    call edge_role_from_cookie;

    if (req.http.X-Session-State == "expired" && req.method == "GET" && req.http.Accept ~ "text/html") {
        call edge_refresh_redirect;
    }

    # The edge cookies never reach WordPress. Other cookies are forwarded but do not
    # prevent caching; only a WordPress login cookie does (see below).
    if (req.http.Cookie) {
        cookie.parse(req.http.Cookie);
        cookie.filter("example_session,example_auth");
        set req.http.Cookie = cookie.get_string();
        if (req.http.Cookie == "") {
            unset req.http.Cookie;
        }
    }

    # Bypass rules
    if (req.method != "GET" && req.method != "HEAD") {
        set req.http.X-Cache-Decision = "BYPASS(method)";
        return (pass);
    }
    if (req.url ~ "^/(wp-admin|wp-login\.php|wp-cron\.php|xmlrpc\.php)") {
        set req.http.X-Cache-Decision = "BYPASS(path)";
        return (pass);
    }
    if (req.http.Cookie ~ "(^|;\s*)(wordpress_logged_in_|wordpress_sec_|wp-postpass_)") {
        set req.http.X-Cache-Decision = "BYPASS(wp-login-cookie)";
        return (pass);
    }

    # Static assets are identical for every role and share one cache entry.
    if (req.url ~ "^/(wp-content|wp-includes)/") {
        set req.http.X-Cache-Key = "-|" + req.http.Host + "|" + req.url;
    } else {
        set req.http.X-Cache-Key = req.http.X-Example-Role + "|" + req.http.Host + "|" + req.url;
    }
    return (hash);
}

sub vcl_hash {
    hash_data(req.url);
    hash_data(req.http.Host);
    if (req.url !~ "^/(wp-content|wp-includes)/") {
        hash_data(req.http.X-Example-Role);
    }
    return (lookup);
}

sub vcl_synth {
    if (resp.status == 752) {
        set resp.status = 302;
        set resp.http.Location = req.http.X-Refresh-Location;
        set resp.http.Cache-Control = "no-store";
        set resp.http.X-Cache = "REFRESH";
        set resp.http.X-Example-Role = "none";
        return (deliver);
    }
}

# --- Backend side -----------------------------------------------------------------------------
sub vcl_backend_fetch {
    # Internal working headers never leave Varnish.
    unset bereq.http.X-Session-Token;
    unset bereq.http.X-Session-State;
    unset bereq.http.X-JWT-Header;
    unset bereq.http.X-JWT-Header-Json;
    unset bereq.http.X-JWT-Payload;
    unset bereq.http.X-JWT-Sig;
    unset bereq.http.X-JWT-Claims;
    unset bereq.http.X-Cache-Key;
    unset bereq.http.X-Cache-Decision;
    unset bereq.http.X-Refresh-Location;
}

sub vcl_backend_response {
    if (!bereq.uncacheable) {
        # WordPress must not set cookies on cacheable responses. Drop them and log it.
        if (beresp.http.Set-Cookie) {
            std.log("edge: origin tried to set cookies on a cacheable response, dropped");
            unset beresp.http.Set-Cookie;
        }
        # Only successful responses are cached; everything else becomes a short hit-for-miss.
        if (beresp.status != 200) {
            set beresp.ttl = 120s;
            set beresp.uncacheable = true;
            return (deliver);
        }
    }
    # TTL: Varnish derives it from s-maxage / max-age; otherwise the default_ttl parameter applies.
    # The built-in vcl_backend_response still runs and handles private / no-store.
}

# --- Delivery ---------------------------------------------------------------------------------
sub vcl_deliver {
    if (req.http.X-Cache-Decision) {
        set resp.http.X-Cache = req.http.X-Cache-Decision;
    } elsif (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } elsif (obj.uncacheable) {
        set resp.http.X-Cache = "UNCACHEABLE";
    } else {
        set resp.http.X-Cache = "MISS";
    }
    set resp.http.X-Example-Role = req.http.X-Example-Role;
    if (req.http.X-Cache-Key) {
        set resp.http.X-Cache-Key = req.http.X-Cache-Key;
    }
}
