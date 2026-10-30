#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
: "${UAS_CLAUDE_INSTALL:?Official pinned package installation required}"
: "${UAS_CLAUDE_SDK_INSTALL:?Matching pinned TypeScript SDK required}"
: "${UAS_CLAUDE_NODE:?Pinned CI Node executable required}"
export PYTHONDONTWRITEBYTECODE=1
# Same deterministic scan/parser contract as Pi; this does not substitute for native tool execution.
UAS_PI_INSTALL="$PWD/tests/claude/library" "$UAS_CLAUDE_NODE" tests/pi/library-scan-contract.mjs
python3 tests/claude/probe.py
# Independent modules own temporary homes/ports; keep discovery complete and both worker exits binding.
printf '%s\0' tests/test_claude*.py | xargs -0 -n 1 -P 2 sh -c \
  'exec python3 -m unittest discover -s tests -p "${1##*/}" -v' sh
