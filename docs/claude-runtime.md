# Claude Code conservative fixture seam (#71)

## Pre-implementation decision and evidence boundary

The exact `fe32b7a5af4ea6df4d86d77c67a379091597eded` source tree, issue #71,
specification #58, the existing MCP prototype, and delivery-signals research
were inspected before implementation. The first bounded experiment selects
official Claude Code **2.1.310**, not a fake Claude process.

The account-free test uses the documented `ANTHROPIC_BASE_URL` gateway route
and a newly generated, fixture-only API-key string. The server binds loopback,
has no upstream, and returns deterministic Anthropic-format protocol replies.
This is **actual CLI / fixture provider** evidence, not real Anthropic model,
subscription, authentication, billing, coding-quality, or deployment acceptance.
No existing credentials, persistent user configuration, or permission bypass is
used. Official docs do not support non-Claude upstream models; this fixture is
a protocol test double, not an alternate model offering.

## Affected seams recorded before code

* **CLI:** documented `-p`, `stream-json`, `--replay-user-messages`, `--resume`,
  and `--session-id`. Spawn, pipe write, init, and MCP connected are not receipts.
* **MCP:** preserve the prototype separately. No HTTP/SSE reconnect or channel
  guarantee is claimed. The first slice selects the documented CLI invocation
  acknowledgment surface instead of pretending MCP connection means idle.
* **Adapter / Hub:** initially fixture-owned authority only. Hub queue admission,
  native acceptance, Participant acceptance, and work completion remain distinct.
  Only correlated native evidence may yield a Hub receipt / start its clock.
* **Supervisor:** no production seat authority yet; never substitute a process
  name, session ID, or connected boolean for the supervisor's process binding.
* **Restoration / reset:** same-Run resume must have a fresh process incarnation
  and fresh safe evidence; no queue remap. A fresh session is not automatically
  a qualified cross-Run reset. Unsupported reset leaves the adapter held.
* **Conservative fallback:** process liveness and turn readiness are separate.
  Working, needs-input, unknown signal, transport loss, process absence,
  unresponsiveness, and replacement hold. No silence-to-idle rule and no
  Pi-equivalent readiness or compaction claim.

## Planned smallest real-runtime experiment

Acquire the pinned official package without lifecycle scripts into an isolated
directory. Launch with fresh HOME and an allowlisted environment, no tools or
auto-discovered MCP, hooks, or plugins, and only the fixture gateway. Record
version, package integrity, native event types, correlated acknowledgment, and
terminal result. Then test a delayed result and resume before attempting any
larger adapter. CI runs in a child network namespace with loopback only; no host
network changes and no networked fallback.

## First-party surfaces checked 2026-10-26

* [Gateway connection](https://code.claude.com/docs/en/llm-gateway-connect)
* [Gateway limitations](https://code.claude.com/docs/en/llm-gateway)
* [CLI reference](https://code.claude.com/docs/en/cli-reference)
* [Programmatic CLI](https://code.claude.com/docs/en/headless)

The installed version's observed behavior, not this living documentation alone,
must qualify each load-bearing signal.
