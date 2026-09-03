# Open-source Varnish with vmod_digest (HMAC-SHA256) for the JWT check in VCL.
# vmod_cookie, vmod_var and vmod_std ship with the official image; /pkgs/*.deb holds varnish-dev.
FROM varnish:7.7

USER root
RUN set -e; \
    apt-get update; \
    apt-get -y install --no-install-recommends libmhash2 libmhash-dev $VMOD_DEPS /pkgs/*.deb; \
    install-vmod https://github.com/varnish/libvmod-digest/archive/refs/tags/libvmod-digest-1.0.3.tar.gz; \
    apt-get -y purge --auto-remove libmhash-dev varnish-dev $VMOD_DEPS; \
    rm -rf /var/lib/apt/lists/*

COPY default.vcl edge.vcl config.vcl.template /etc/varnish/
COPY entrypoint.sh /usr/local/bin/edge-entrypoint
RUN chmod +x /usr/local/bin/edge-entrypoint && chown -R varnish:varnish /etc/varnish

USER varnish
ENTRYPOINT ["/usr/local/bin/edge-entrypoint"]
