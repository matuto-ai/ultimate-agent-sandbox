#!/usr/bin/env bash
# One-command prototype check: full session lifecycle against the fixture
# runtime, plus a best-effort real-Pi smoke test. Run from anywhere:
#   spike/session-control/demo.sh
set -euo pipefail
cd "$(dirname "$0")"
export ROOMCTL_HOME="$(mktemp -d /tmp/roomctl-demo.XXXXXX)"
export ROOMCTL_PROFILES="$ROOMCTL_HOME/profiles"
mkdir -p "$ROOMCTL_PROFILES"
cp profiles/*.json "$ROOMCTL_PROFILES"/
BIN="$ROOMCTL_HOME/roomctl"
cleanup() {
  "$BIN" close demo >/dev/null 2>&1 || true
  "$BIN" close swapx >/dev/null 2>&1 || true
  "$BIN" close pisess >/dev/null 2>&1 || true
  rm -rf "$ROOMCTL_HOME"
}
trap cleanup EXIT

say() { printf '\n== %s\n' "$*"; }

# expect_output <pattern> <command...> — run, echo output to stderr, grep for pattern.
# No tee: some harnesses cannot address their own fds as files.
expect_output() {
  local pat="$1"; shift
  local out
  out=$("$@")
  printf '%s\n' "$out" >&2
  grep -q "$pat" <<<"$out"
}

say "build"
go build -o "$BIN" .
go vet ./...

say "open"
"$BIN" open demo --profile fixture --workdir "$PWD"
expect_output "process=RUNNING" "$BIN" status demo

say "identify"
expect_output "demo.*fixture.*fixture-agent" "$BIN" list

say "send (operator input)"
"$BIN" send demo "mark via-send"
sleep 0.5
grep -q "via-send" "$ROOMCTL_HOME/marker-demo.txt"

say "attach (scripted: scrollback replay + live input)"
printf 'mark via-attach\r' | "$BIN" attach demo > "$ROOMCTL_HOME/attach.out" || true
grep -q "via-attach" "$ROOMCTL_HOME/marker-demo.txt"
grep -q "fakecli up mode=fresh" "$ROOMCTL_HOME/attach.out"

say "crash the holder (workstation-restart stand-in)"
kill -9 "$(cat "$ROOMCTL_HOME/run/demo.pid")"
sleep 0.5
expect_output "process=EXITED" "$BIN" status demo

say "restore (runtime-native resume, bulk path)"
expect_output "restored demo (resume)" "$BIN" restore
expect_output "process=RUNNING" "$BIN" status demo
printf '' | "$BIN" attach demo > "$ROOMCTL_HOME/attach2.out" || true
grep -q "fakecli up mode=resume" "$ROOMCTL_HOME/attach2.out"

say "clear (new native session, same identity)"
before="$("$BIN" status demo | sed 's/.*session=\([^ ]*\).*/\1/')"
"$BIN" clear demo
after="$("$BIN" status demo | sed 's/.*session=\([^ ]*\).*/\1/')"
[ "$before" != "$after" ]
expect_output "process=RUNNING" "$BIN" status demo

say "clear rolls back when the relaunch dies at boot"
cp "$ROOMCTL_PROFILES/fixture.json" "$ROOMCTL_PROFILES/swap.json"
"$BIN" open swapx --profile swap --workdir "$PWD" >/dev/null
shandle="$("$BIN" status swapx | sed 's/.*session=\([^ ]*\).*/\1/')"
printf '{"name":"swap","runtime":"fixture","actor":"x","command":["/bin/false"],"sessionTemplate":"{root}/native/{name}-{ts}"}' \
  > "$ROOMCTL_PROFILES/swap.json"
if "$BIN" clear swapx 2>/dev/null; then
  echo "FAIL: clear succeeded with a dead-on-boot relaunch" >&2
  exit 1
fi
[ "$("$BIN" status swapx | sed 's/.*session=\([^ ]*\).*/\1/')" = "$shandle" ]

say "close"
"$BIN" close demo
sleep 0.5
expect_output "process=EXITED" "$BIN" status demo
expect_output "demo.*closed" "$BIN" list

say "restore never revives a closed session"
if "$BIN" restore demo 2>/dev/null; then
  echo "FAIL: closed session was restored" >&2
  exit 1
fi

say "open fails fast on a dead-on-boot runtime"
printf '{"name":"truex","runtime":"fixture","actor":"x","command":["/bin/true"],"sessionTemplate":"{root}/native/{name}-{ts}"}' \
  > "$ROOMCTL_PROFILES/truex.json"
if "$BIN" open truex --profile truex --workdir "$PWD" 2>/dev/null; then
  echo "FAIL: open reported success for a runtime that exited at boot" >&2
  exit 1
fi
if "$BIN" list | grep -q truex; then
  echo "FAIL: dead-on-boot session left a registry entry" >&2
  exit 1
fi
rm "$ROOMCTL_PROFILES/truex.json"

say "pi smoke (real runtime; soft-fail)"
mkdir -p "$ROOMCTL_HOME/piwork"
# Pi shows a ~30s startup splash that swallows early input; wait it out,
# then send one tiny real message. The native session file materializes on
# the first exchange; grep it for the reply as end-to-end evidence.
if "$BIN" open pisess --profile pi-default --workdir "$ROOMCTL_HOME/piwork"; then
  sleep 40
  "$BIN" send pisess "Reply with exactly: roomctl-ok" || true
  sess="$("$BIN" status pisess | sed 's/.*session=\([^ ]*\).*/\1/')"
  ok=""
  for _ in 1 2 3 4 5 6; do
    sleep 5
    if [ -s "$sess" ] && grep -q "roomctl-ok" "$sess"; then ok=1; break; fi
  done
  "$BIN" status pisess >&2
  if [ -n "$ok" ]; then
    echo "pi smoke: PASS (open+send+native session $sess)"
  else
    echo "pi smoke: SKIPPED/FAILED (no roomctl-ok reply observed in $sess)"
  fi
  "$BIN" close pisess || true
else
  echo "pi smoke: SKIPPED/FAILED (pi unavailable in this environment)"
fi

say "PASS"
