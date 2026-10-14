#!/usr/bin/env bash
# Runs the VCL tests (edge/varnish/tests/*.vtc) inside the Varnish image, against the current template.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose run --rm --no-deps -v "$PWD/edge/varnish:/work:ro" --entrypoint varnishtest varnish "$@" /work/tests/edge.vtc
