#!/bin/sh
# Never skip the native qualification when this gate is explicitly invoked.
set -eu
cd "$(dirname "$0")/../.."
UAS_PI_INSTALL="${UAS_PI_INSTALL:-$PWD/tests/pi}"
UAS_PI_EVIDENCE="${UAS_PI_EVIDENCE:-$PWD/tests/pi/evidence.jsonl}"
export UAS_PI_INSTALL UAS_PI_EVIDENCE PYTHONDONTWRITEBYTECODE=1
: > "$UAS_PI_EVIDENCE"
node -e 'const fs=require("node:fs"); const p=process.env.UAS_PI_INSTALL+"/node_modules/@earendil-works/pi-coding-agent/package.json"; if(JSON.parse(fs.readFileSync(p)).version!=="1.4.0") throw Error("Official Pi 1.4.0 required");'
node tests/pi/auth-contract.mjs
node tests/pi/resume-contract.mjs
python3 tests/pi/parallel-tests.py
cat "$UAS_PI_EVIDENCE"
