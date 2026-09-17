#!/usr/bin/env bash
# Runs the VCL tests (varnish/tests/*.vtc) inside the Varnish image, against the current edge.vcl.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose run --rm --no-deps -v "$PWD/varnish:/work:ro" --entrypoint varnishtest varnish "$@" /work/tests/edge.vtc
