#!/usr/bin/env bash
# One-command prototype check: full session lifecycle against the fixture
# runtime, plus a best-effort real-Pi smoke test. Run from anywhere:
#   spike/session-control/demo.sh
set -euo pipefail
cd "$(dirname "$0")"
export ROOMCTL_HOME="$(mktemp -d /tmp/roomctl-demo.XXXXXX)"
export ROOMCTL_PROFILES="$PWD/profiles"
BIN="$ROOMCTL_HOME/roomctl"
cleanup() {
  "$BIN" close demo >/dev/null 2>&1 || true
  "$BIN" close pisess >/dev/null 2>&1 || true
  rm -rf "$ROOMCTL_HOME"
}
trap cleanup EXIT

say() { printf '\n== %s\n' "$*"; }

say "build"
go build -o "$BIN" .
go vet ./...

say "open"
"$BIN" open demo --profile fixture --workdir "$PWD"
sleep 1
"$BIN" status demo | tee /dev/stderr | grep -q "process=RUNNING"

say "identify"
"$BIN" list | tee /dev/stderr | grep -q "demo.*fixture.*fixture-agent"

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
"$BIN" status demo | tee /dev/stderr | grep -q "process=EXITED"

say "restore (runtime-native resume)"
"$BIN" restore demo | tee /dev/stderr | grep -q "restored demo (resume)"
sleep 1
"$BIN" status demo | grep -q "process=RUNNING"
printf '' | "$BIN" attach demo > "$ROOMCTL_HOME/attach2.out" || true
grep -q "fakecli up mode=resume" "$ROOMCTL_HOME/attach2.out"

say "clear (new native session, same identity)"
before="$("$BIN" status demo | sed 's/.*session=\([^ ]*\).*/\1/')"
"$BIN" clear demo
sleep 1
after="$("$BIN" status demo | sed 's/.*session=\([^ ]*\).*/\1/')"
[ "$before" != "$after" ]
"$BIN" status demo | grep -q "process=RUNNING"

say "close"
"$BIN" close demo
sleep 0.5
"$BIN" status demo | tee /dev/stderr | grep -q "process=EXITED"
"$BIN" list | grep -q "demo.*closed"

say "pi smoke (real runtime; soft-fail)"
mkdir -p "$ROOMCTL_HOME/piwork"
# Pi shows a ~30s startup splash that swallows early input; wait it out,
# then submit a local slash command (no model call) to materialize the
# native session file.
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
  "$BIN" status pisess | tee /dev/stderr
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
