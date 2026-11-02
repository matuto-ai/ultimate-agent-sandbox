#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
: "${UAS_CLAUDE_INSTALL:?Official pinned package installation required}"
: "${UAS_CLAUDE_SDK_INSTALL:?Matching pinned TypeScript SDK required}"
: "${UAS_CLAUDE_NODE:?Pinned CI Node executable required}"
# CI isolates the longest measured module on its own runner. Local invocation
# still discovers everything and uses at most two workers, not two full suites.
partition=all
if [ "$#" -ne 0 ]; then
  if [ "$#" -ne 2 ] || [ "$1" != --partition ]; then
    echo 'Usage: run-tests.sh [--partition 0|1]' >&2; exit 2
  fi
  case "$2" in 0|1) partition=$2 ;; *) echo 'Invalid Claude partition' >&2; exit 2 ;; esac
fi
# Fail closed on an incomplete checkout instead of accepting an empty shard.
test -f tests/test_claude_sdk_receiver.py || { echo 'Missing Claude receiver suite' >&2; exit 1; }
test -f tests/test_claude_participant.py || { echo 'Missing Claude participant suite' >&2; exit 1; }
export PYTHONDONTWRITEBYTECODE=1
# Same deterministic scan/parser contract as Pi; this does not substitute for native tool execution.
UAS_PI_INSTALL="$PWD/tests/claude/library" "$UAS_CLAUDE_NODE" tests/pi/library-scan-contract.mjs
python3 tests/claude/probe.py
# Start measured long modules early instead of leaving one worker idle at the end.
# These are ordering hints, never an allowlist: discover every future module too.
# Independent modules own temporary homes/ports; both worker exits stay binding.
priority='sdk_receiver participant sdk readiness runtime library_read library'
selected() {
  case "$partition:$1" in
    all:*|0:sdk_receiver) return 0 ;;
    1:sdk_receiver) return 1 ;;
    1:*) return 0 ;;
    *) return 1 ;;
  esac
}
{
  for name in $priority; do
    file="tests/test_claude_${name}.py"
    if [ -f "$file" ] && selected "$name"; then printf '%s\0' "$file"; fi
  done
  for file in tests/test_claude*.py; do
    name=${file#tests/test_claude_}
    name=${name%.py}
    selected "$name" || continue
    case " $priority " in
      *" $name "*) ;;
      *) printf '%s\0' "$file" ;;
    esac
  done
} | xargs -0 -n 1 -P 2 sh -c \
  'exec python3 -m unittest discover -s tests -p "${1##*/}" -v' sh
