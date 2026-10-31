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
# Start measured long modules early instead of leaving one worker idle at the end.
# These are ordering hints, never an allowlist: discover every future module too.
# Independent modules own temporary homes/ports; both worker exits stay binding.
priority='sdk_receiver participant sdk readiness runtime library_read library'
{
  for name in $priority; do
    file="tests/test_claude_${name}.py"
    if [ -f "$file" ]; then printf '%s\0' "$file"; fi
  done
  for file in tests/test_claude*.py; do
    name=${file#tests/test_claude_}
    name=${name%.py}
    case " $priority " in
      *" $name "*) ;;
      *) printf '%s\0' "$file" ;;
    esac
  done
} | xargs -0 -n 1 -P 2 sh -c \
  'exec python3 -m unittest discover -s tests -p "${1##*/}" -v' sh
