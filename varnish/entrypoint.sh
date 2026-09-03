#!/bin/sh
# Renders the secret into config.vcl, then hands over to the official Varnish entrypoint.
# VCL cannot read environment variables, so this is the one place where it enters the config.
set -e
: "${SESSION_SECRET:?SESSION_SECRET is required}"

case "${SESSION_SECRET}" in
  *[\"\\\|]*) echo 'SESSION_SECRET must not contain ", \ or |' >&2; exit 1 ;;
esac

sed -e "s|@@SESSION_SECRET@@|${SESSION_SECRET}|" \
    /etc/varnish/config.vcl.template > /etc/varnish/config.vcl

exec /usr/local/bin/docker-varnish-entrypoint "$@"
