# Peer messaging — prototype

> [!WARNING]
> Throwaway spike for [Prototype Pi and Claude peer messaging through the Hub](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/11). It answers an integration question; it is not production code.

## Question

Can small, runtime-specific adapters let long-lived Pi and Claude Participants discover peers and exchange durable, correlated Hub traffic without terminal scraping or depending on each other's plugin system?

## Run

```bash
# Deterministic, no Claude token spend
spike/peer-messaging/demo.sh

# Closure attestation on a Claude-equipped workstation
REAL_CLAUDE=1 spike/peer-messaging/demo.sh
```

The default run uses Python's standard library plus the installed Pi runtime. The opt-in phase spends real Claude tokens (`CLAUDE_MODEL`, default `haiku`) and fails unless every real-runtime check passes. Evidence remains in `spike/peer-messaging/.demo/evidence.json`.

## Current evidence

The deterministic run proves:

- a real Pi RPC process loads `pi-adapter.ts` and sends or receives Hub traffic without forcing an LLM turn;
- the Claude adapter's stdio and authenticated Streamable HTTP transports expose the same peer tools;
- peer discovery, correlated request/reply, reply authorization, broadcast delivery, durable cursor replay, and SQLite Hub restart recovery;
- expiring adapter leases remove dead processes from online presence without changing pull-only safe-point delivery;
- Room traffic never uses `roomctl`, PTY input, or terminal scraping.

A fresh `REAL_CLAUDE=1` run at the reviewed commit must additionally attest real Pi↔Claude traffic, resumable-session delivery (H9-04), unresponsive hold/recovery (H9-05), one-process HTTP MCP reconnect with no phantom delivery (H9-06), and missing-signal hold (H9-07). Until that run passes, those claims remain pending rather than proven by this working tree.

Out of scope here:

- Claude channels and interactive-session supervision, which belong to issue #22;
- production authentication, authorization, workflow policy, or network exposure.
