#!/bin/sh
# Never skip the native qualification when this gate is explicitly invoked.
set -eu
cd "$(dirname "$0")/../.."
# Fail rather than use any previous/symlinked cache. Creation and removal remain
# inside the measured native job; each matrix job owns its separate checkout.
cache="$PWD/tests/pi/.compile-cache"
if [ -e "$cache" ] || [ -L "$cache" ]; then
    echo 'Refusing preexisting Pi compile cache' >&2
    exit 1
fi
# Native launchers deliberately clean their environment; absence of this directory
# also carries the opt-out into those children without changing production envs.
if [ -z "${NODE_V8_COVERAGE:-}" ] && [ "${NODE_DISABLE_COMPILE_CACHE:-}" != 1 ]; then
    (umask 077; mkdir "$cache")
    trap 'rm -rf -- "$cache"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
fi
UAS_PI_INSTALL="${UAS_PI_INSTALL:-$PWD/tests/pi}"
UAS_PI_EVIDENCE="${UAS_PI_EVIDENCE:-$PWD/tests/pi/evidence.jsonl}"
export UAS_PI_INSTALL UAS_PI_EVIDENCE PYTHONDONTWRITEBYTECODE=1
: > "$UAS_PI_EVIDENCE"
node -e 'const fs=require("node:fs"); const p=process.env.UAS_PI_INSTALL+"/node_modules/@earendil-works/pi-coding-agent/package.json"; if(JSON.parse(fs.readFileSync(p)).version!=="1.4.0") throw Error("Official Pi 1.4.0 required");'
node tests/pi/auth-contract.mjs
node tests/pi/resume-contract.mjs
node tests/pi/library-scan-contract.mjs
node tests/pi/library-capture-contract.mjs
python3 tests/pi/parallel-tests.py "$@"
cat "$UAS_PI_EVIDENCE"
