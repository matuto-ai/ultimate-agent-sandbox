#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
: "${UAS_CLAUDE_INSTALL:?Official pinned package installation required}"
: "${UAS_CLAUDE_SDK_INSTALL:?Matching pinned TypeScript SDK required}"
: "${UAS_CLAUDE_NODE:?Pinned CI Node executable required}"
export PYTHONDONTWRITEBYTECODE=1
python3 tests/claude/probe.py
python3 -m unittest discover -s tests -p 'test_claude*.py' -v
