#!/bin/sh
# Renders the secrets into config.vcl, then hands over to the official Varnish entrypoint.
# VCL cannot read environment variables, so this is the one place where they enter the config.
set -e
: "${SESSION_SECRET:?SESSION_SECRET is required}"
: "${EDGE_SHARED_SECRET:?EDGE_SHARED_SECRET is required}"

case "${SESSION_SECRET}${EDGE_SHARED_SECRET}" in
  *[\"\\\|]*) echo 'secrets must not contain ", \ or |' >&2; exit 1 ;;
esac

sed -e "s|@@SESSION_SECRET@@|${SESSION_SECRET}|" \
    -e "s|@@EDGE_SHARED_SECRET@@|${EDGE_SHARED_SECRET}|" \
    /etc/varnish/config.vcl.template > /etc/varnish/config.vcl

exec /usr/local/bin/docker-varnish-entrypoint "$@"
