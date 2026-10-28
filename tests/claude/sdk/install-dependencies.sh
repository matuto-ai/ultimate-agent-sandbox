#!/bin/sh
# Main sdk.mjs bundles its runtime dependencies. Omit optional SDK binaries;
# the separately locked Claude Code binary is supplied by its public option.
# Acquisition only. Do not import account settings or run package lifecycle scripts.
set -eu
cd "$(dirname "$0")"
node_path=$(command -v node)
npm_path=$(command -v npm)
mkdir -p .home .npm-cache
test ! -e .npmrc || { echo 'Refusing unexpected project npm configuration' >&2; exit 1; }
: > .home/empty-user.npmrc
: > .home/empty-global.npmrc
env -i PATH="$(dirname "$node_path"):/usr/bin:/bin" HOME="$PWD/.home" \
  "$node_path" check-lock.mjs
# Retain only existing network routing/trust, never npm auth or model credentials.
exec env -i PATH="$(dirname "$node_path"):$(dirname "$npm_path"):/usr/bin:/bin" \
  HOME="$PWD/.home" TMPDIR=/tmp \
  HTTPS_PROXY="${HTTPS_PROXY-}" HTTP_PROXY="${HTTP_PROXY-}" ALL_PROXY="${ALL_PROXY-}" NO_PROXY="${NO_PROXY-}" \
  https_proxy="${https_proxy-}" http_proxy="${http_proxy-}" all_proxy="${all_proxy-}" no_proxy="${no_proxy-}" \
  NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS-}" NODE_USE_SYSTEM_CA=1 \
  NPM_CONFIG_USERCONFIG="$PWD/.home/empty-user.npmrc" \
  NPM_CONFIG_GLOBALCONFIG="$PWD/.home/empty-global.npmrc" \
  NPM_CONFIG_CACHE="$PWD/.npm-cache" NPM_CONFIG_IGNORE_SCRIPTS=true \
  "$npm_path" ci --omit=optional --legacy-peer-deps --registry=https://registry.npmjs.org --ignore-scripts --no-audit --no-fund \
  --prefer-offline --fetch-retries=0 --fetch-timeout=20000 --update-notifier=false
