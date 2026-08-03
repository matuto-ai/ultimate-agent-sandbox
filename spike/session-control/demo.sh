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
  "$BIN" close disc >/dev/null 2>&1 || true
  "$BIN" close orph >/dev/null 2>&1 || true
  "$BIN" close multi >/dev/null 2>&1 || true
  "$BIN" close sock >/dev/null 2>&1 || true
  "$BIN" close clrs >/dev/null 2>&1 || true
  "$BIN" close clro >/dev/null 2>&1 || true
  "$BIN" close stub >/dev/null 2>&1 || true
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

say "malformed arguments fail with usage, not a panic"
if "$BIN" open demo --profile > "$ROOMCTL_HOME/malformed.out" 2>&1; then
  echo "FAIL: trailing --profile flag accepted" >&2
  exit 1
fi
if grep -qi panic "$ROOMCTL_HOME/malformed.out"; then
  echo "FAIL: malformed open panicked" >&2
  exit 1
fi
if "$BIN" open 2>/dev/null; then
  echo "FAIL: nameless open accepted" >&2
  exit 1
fi

# count_holders <name> — live holder processes for a session, via /proc
# (ps is not available in every harness).
count_holders() {
  local n=0 c
  for c in /proc/[0-9]*/cmdline; do
    if tr '\0' ' ' < "$c" 2>/dev/null | grep -q "[__]holder $1 "; then n=$((n+1)); fi
  done
  echo "$n"
}

say "restore after holder/runtime loss keeps exactly one holder"
"$BIN" open disc --profile fixture --workdir "$PWD" >/dev/null
kill -9 "$("$BIN" status disc | sed 's/.*runtimePid=\([0-9]*\).*/\1/')"
sleep 1
"$BIN" restore disc >/dev/null
expect_output "process=RUNNING" "$BIN" status disc
[ "$(count_holders disc)" = "1" ]
"$BIN" close disc >/dev/null
for _ in 1 2 3 4 5 6 7 8; do
  [ "$(count_holders disc)" = "0" ] && break
  sleep 0.5
done
[ "$(count_holders disc)" = "0" ]

dead() { [ ! -e "/proc/$1/stat" ] || grep -q ") Z" "/proc/$1/stat"; }

say "restore reaps a holder whose socket is unreachable"
"$BIN" open sock --profile fixture --workdir "$PWD" >/dev/null
oldhp=$(cat "$ROOMCTL_HOME/run/sock.pid")
oldrp=$("$BIN" status sock | sed 's/.*runtimePid=\([0-9]*\).*/\1/')
rm -f "$ROOMCTL_HOME/sock/sock.sock"   # holder and runtime stay alive, socket is gone
"$BIN" restore sock >/dev/null
expect_output "process=RUNNING" "$BIN" status sock
[ "$(count_holders sock)" = "1" ] || { echo "FAIL: restore duplicated the sock holder"; exit 1; }
dead "$oldhp" || { echo "FAIL: socket-less holder $oldhp survived restore"; exit 1; }
dead "$oldrp" || { echo "FAIL: previous runtime $oldrp survived restore"; exit 1; }
"$BIN" close sock >/dev/null

say "close does not return while a TERM-ignoring runtime lives"
printf '%s\n' '{"name":"stub","runtime":"fixture","actor":"x","command":["/bin/bash","-c","trap \"\" TERM HUP; while :; do sleep 1; done"],"sessionTemplate":"{root}/native/{name}-{ts}"}' \
  > "$ROOMCTL_PROFILES/stub.json"
"$BIN" open stub --profile stub --workdir "$PWD" >/dev/null
stubrp=$("$BIN" status stub | sed 's/.*runtimePid=\([0-9]*\).*/\1/')
"$BIN" close stub >/dev/null   # must block through the holder's TERM grace
dead "$stubrp" || { echo "FAIL: close returned while runtime $stubrp was RUNNING"; exit 1; }

say "clear reaps a socket-unreachable holder before relaunch"
"$BIN" open clrs --profile fixture --workdir "$PWD" >/dev/null
chp=$(cat "$ROOMCTL_HOME/run/clrs.pid")
crp=$("$BIN" status clrs | sed 's/.*runtimePid=\([0-9]*\).*/\1/')
rm -f "$ROOMCTL_HOME/sock/clrs.sock"
"$BIN" clear clrs >/dev/null
expect_output "process=RUNNING" "$BIN" status clrs
[ "$(count_holders clrs)" = "1" ] || { echo "FAIL: clear duplicated the clrs holder"; exit 1; }
dead "$chp" || { echo "FAIL: socket-less holder $chp survived clear"; exit 1; }
dead "$crp" || { echo "FAIL: previous runtime $crp survived clear"; exit 1; }
"$BIN" close clrs >/dev/null

say "clear reaps an orphaned runtime before relaunch"
"$BIN" open clro --profile fixture --workdir "$PWD" >/dev/null
ohp=$(cat "$ROOMCTL_HOME/run/clro.pid")
orp2=$("$BIN" status clro | sed 's/.*runtimePid=\([0-9]*\).*/\1/')
kill -9 "$ohp"   # holder dies hard; runtime (own session leader) is orphaned
"$BIN" clear clro >/dev/null
expect_output "process=RUNNING" "$BIN" status clro
dead "$orp2" || { echo "FAIL: orphaned runtime $orp2 survived clear"; exit 1; }
[ "$(count_holders clro)" = "1" ] || { echo "FAIL: clear duplicated the clro holder"; exit 1; }
"$BIN" close clro >/dev/null

say "close kills an orphaned runtime when the holder is gone"
printf '%s\n' '{"name":"orph","runtime":"fixture","actor":"x","command":["/bin/bash","-c","trap \"\" HUP; exec sleep 300"],"sessionTemplate":"{root}/native/{name}-{ts}"}' \
  > "$ROOMCTL_PROFILES/orph.json"
"$BIN" open orph --profile orph --workdir "$PWD" >/dev/null
opid="$("$BIN" status orph | sed 's/.*runtimePid=\([0-9]*\).*/\1/')"
kill -9 "$(cat "$ROOMCTL_HOME/run/orph.pid")"
"$BIN" close orph
if [ -e "/proc/$opid/stat" ] && ! grep -q ") Z" "/proc/$opid/stat"; then
  echo "FAIL: orphaned runtime $opid survived close" >&2
  exit 1
fi

say "clear never reuses a native handle"
printf '{"name":"multi","runtime":"fixture","actor":"x","command":["%s/fixture/fakecli.sh","multi"],"sessionTemplate":"{root}/native/{name}-{ts}"}' "$PWD" \
  > "$ROOMCTL_PROFILES/multi.json"
"$BIN" open multi --profile multi --workdir "$PWD" >/dev/null
h1="$("$BIN" status multi | sed 's/.*session=\([^ ]*\).*/\1/')"
"$BIN" clear multi >/dev/null
h2="$("$BIN" status multi | sed 's/.*session=\([^ ]*\).*/\1/')"
"$BIN" clear multi >/dev/null
h3="$("$BIN" status multi | sed 's/.*session=\([^ ]*\).*/\1/')"
[ "$h1" != "$h2" ] && [ "$h2" != "$h3" ]
"$BIN" close multi >/dev/null

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

say "claude smoke (real runtime; soft-fail)"
mkdir -p "$ROOMCTL_HOME/ccwork"
# Guards the two Claude-specific defects from issue #20: an inherited
# CLAUDE_CODE_CHILD_SESSION kills transcript saving (so --resume has nothing to
# resume), and a combined text+CR write is swallowed by paste detection (so the
# turn never runs). Both are silent, so the check is that a transcript appears.
if "$BIN" open ccsess --profile claude-default --workdir "$ROOMCTL_HOME/ccwork"; then
  sleep 20
  "$BIN" send ccsess "Reply with exactly: roomctl-ok" || true
  proj="$HOME/.claude"; [ -n "${CLAUDE_CONFIG_DIR:-}" ] && proj="$CLAUDE_CONFIG_DIR"
  sess="$("$BIN" status ccsess | sed 's/.*session=\([^ ]*\).*/\1/')"
  ok=""
  for _ in 1 2 3 4 5 6 7 8; do
    sleep 5
    f="$(find "$proj/projects" -name "$sess.jsonl" 2>/dev/null | head -1)"
    if [ -n "$f" ] && [ -s "$f" ]; then ok=1; break; fi
  done
  if grep -aq 'Transcript saving is off' "$ROOMCTL_HOME/logs/ccsess.log" 2>/dev/null; then
    echo "claude smoke: FAILED (transcript saving disabled by inherited env marker)"
    ok=""
  fi
  if [ -n "$ok" ]; then
    echo "claude smoke: PASS (open+send+persisted native session $sess)"
  else
    echo "claude smoke: SKIPPED/FAILED (no persisted transcript for $sess)"
  fi
  "$BIN" close ccsess || true
else
  echo "claude smoke: SKIPPED/FAILED (claude unavailable in this environment)"
fi

say "PASS"
