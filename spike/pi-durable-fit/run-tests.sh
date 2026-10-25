#!/bin/sh
set -eu
cd "$(dirname "$0")"
node_path=$(command -v node)
mkdir -p .home artifacts
exec env -i PATH="$(dirname "$node_path"):/usr/bin:/bin" HOME="$PWD/.home" TMPDIR=/tmp \
  "$node_path" --test test/*.test.mjs
