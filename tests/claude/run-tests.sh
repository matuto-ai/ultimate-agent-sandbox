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
python3 -m unittest discover -s tests -p 'test_claude*.py' -v
