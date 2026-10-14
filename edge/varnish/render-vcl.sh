#!/bin/sh
# Renders a VCL template: every ${EDGE_*} placeholder is replaced with the environment variable of
# the same name. Fails if a placeholder has no value, so a missing variable cannot produce a VCL
# with an empty header name.
#
#   render-vcl.sh <template> <output>
set -eu
template=$1
output=$2
cp "$template" "$output"
for name in $(grep -o '[$]{EDGE_[A-Z0-9_]*}' "$template" | tr -d '${}' | sort -u); do
  value=$(printenv "$name" || true)
  if [ -z "$value" ]; then
    echo "render-vcl.sh: $name is not set but used in $template" >&2
    exit 1
  fi
  sed -i "s|[$]{$name}|$value|g" "$output"
done
