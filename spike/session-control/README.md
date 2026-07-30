# roomctl — PROTOTYPE session supervisor and deployment CLI

> [!WARNING]
> Throwaway-grade spike prototype for
> [Prototype visible long-lived session control](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/8)
> (map: [Chart the evolvable collaborative agent sandbox spike](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/1)).
> It answers a design question; it is not production code.

## The question

What minimal supervisor and deployment CLI can reliably **open, identify,
inspect status, attach, send operator input, clear, close, and restore**
Profile-backed Pi and Claude sessions inside one Trusted Workstation — while
keeping terminal control separate from the Hub's canonical agent
communication?

## The answer this artifact demonstrates

One small static Go binary, stdlib only, no daemon:

- **Per-session holder process.** `roomctl open` spawns a detached holder that
  owns one PTY (the visible, addressable terminal), runs the Runtime inside
  it, mirrors output to a scrollback log, and serves one unix socket for
  `status` / `send` / `attach` / `close`. No central supervisor to keep alive;
  the registry on disk is the only shared state.
- **Registry = durable identity and topology.** `registry.json` records
  session name, Runtime, Runtime Launch Profile, Actor Identity, workdir, and
  the runtime-native session handle. Live state (pids, sockets) is derived
  from pid files and native liveness signals, never from terminal content.
- **Declarative Runtime Launch Profiles** (`profiles/*.json`): runtime,
  Actor Identity, open command, resume command, native session template, env.
  Adding a Runtime is a profile file, not code.
- **Two-phase restore.** Phase 1 is free: the registry *is* the topology and
  survives any crash. Phase 2: `roomctl restore` relaunches dead sessions
  through the runtime-native resume command (`pi --session <file>`,
  `claude --resume <id>`), never a replay or scrape.
- **Clear vs close vs restore.** `clear` mints a new native session handle and
  relaunches under the same identity (context wiped, Participant preserved);
  `close` terminates; `restore` resumes the same native session.
- **Two state axes, honestly separated.** `status` reports only the *process*
  axis (`RUNNING / EXITED / DISCONNECTED`) from holder socket + pid liveness.
  Turn *readiness* is a separate, adapter-owned axis (see
  [Non-disruptive delivery signals](../../docs/research/non-disruptive-delivery-signals.md));
  roomctl never infers it from terminal output or silence.
- **Hub separation.** roomctl is the terminal control plane only. Room
  Messages, Requests, and Commands travel through the Hub adapters inside the
  session (Pi extension, Claude MCP). roomctl carries no Room traffic and the
  Hub needs no terminal access.

Rejected, per the settled decisions: terminal scraping as a transport, hidden
sessions, a central supervisor daemon, replay-based restore.

## Commands

```text
roomctl open <name> --profile <p> [--workdir dir]
roomctl list                  # identify: name, profile, runtime, actor, state, native session
roomctl status [name]         # process axis only: RUNNING | EXITED | DISCONNECTED
roomctl attach <name>         # operator terminal; Ctrl-] detaches
roomctl send <name> <text>    # operator input, delivered like typing
roomctl clear <name>          # wipe context, keep identity/profile
roomctl close <name>
roomctl restore [name]        # runtime-native resume; no name = all dead sessions
```

State root: `$ROOMCTL_HOME` (default `.roomctl/`). Profiles:
`$ROOMCTL_PROFILES` (default `profiles/`).

## Run it

```bash
spike/session-control/demo.sh
```

Builds, then exercises the full lifecycle against a fixture runtime with
assertions (open → identify → send → attach → holder-crash → restore →
clear → close), and finishes with a best-effort real-Pi smoke: open a Pi
session in a PTY, deliver an operator message, and verify the reply lands in
the native `--session` file.

## Evidence and limits

Proven here (Pi 0.83.0, Go 1.26.5, Linux):

- all eight operations against the fixture runtime, including restore after
  `kill -9` of the holder;
- real Pi: open, send, and native session persistence (`pi --session <path>`
  creates fresh at a new path and resumes the same session at an existing
  path — verified directly).

Not proven here:

- **Claude.** The binary is absent in this environment; `claude-default.json`
  encodes only the documented flags (`--session-id`, `--resume`). Its
  interactive behavior must be proven on a workstation that has Claude.
- Pi's ~30s startup splash swallows early operator input; `send` before the
  TUI is up is lost (the demo waits it out). A production profile may want
  Pi's extension seam for input instead of raw PTY writes.
- No window-resize forwarding on attach; a slow attached reader can stall the
  output pump; CLOSE has a fixed 3s SIGTERM→SIGKILL grace. All acceptable at
  prototype fidelity.

## Files

- `main.go` — CLI, registry, profiles, lifecycle commands
- `holder.go` — per-session PTY/socket holder
- `pty_linux.go` — Linux PTY + raw-terminal attach (stdlib only)
- `profiles/` — fixture, Pi, Claude Runtime Launch Profiles
- `fixture/fakecli.sh` — fake long-lived agent CLI for deterministic checks
- `demo.sh` — the one-command lifecycle check
