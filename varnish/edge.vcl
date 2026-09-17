# Varnish behind HAProxy: cache WordPress per access level.
#
# HAProxy has already verified the login cookie, removed it and set X-Example-Role. Varnish only
# has to key the cache on that header and keep WordPress' responses clean. Varnish must therefore
# be reachable from HAProxy only; a client talking to it directly could set the header itself.
#
# The including file provides the backend `wordpress`: default.vcl in Docker, the .vtc in tests.

import std;

sub vcl_recv {
    if (req.method != "GET" && req.method != "HEAD" && req.method != "POST" &&
        req.method != "PUT" && req.method != "PATCH" && req.method != "DELETE" && req.method != "OPTIONS") {
        return (pipe);
    }

    # Only the known levels; anything else, including a missing header, is "none".
    if (req.http.X-Example-Role !~ "^(limited|full)$") {
        set req.http.X-Example-Role = "none";
    }
    unset req.http.X-Cache-Decision;
    unset req.http.X-Cache-Key;

    # Bypass rules. Other cookies do not prevent caching; only a WordPress login cookie does.
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

    # Static assets are identical for every level and share one cache entry.
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

sub vcl_backend_fetch {
    unset bereq.http.X-Cache-Key;
    unset bereq.http.X-Cache-Decision;
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
