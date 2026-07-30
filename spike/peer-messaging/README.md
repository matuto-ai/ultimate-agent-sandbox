# Peer messaging — prototype

> [!WARNING]
> Throwaway spike for [Prototype Pi and Claude peer messaging through the Hub](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/9). It answers an integration question; it is not production code.

## Question

Can small, runtime-specific adapters let long-lived Pi and Claude Participants discover peers and exchange durable, correlated Hub traffic without terminal scraping or depending on each other's plugin system?

## Run

```bash
spike/peer-messaging/demo.sh
```

The demo uses only Python's standard library plus the installed Pi runtime. Evidence remains in `spike/peer-messaging/.demo/evidence.json`.

## Local verdict

Proven here:

- a real Pi RPC process loads `pi-adapter.ts` and sends or receives Hub traffic without forcing an LLM turn;
- the Claude MCP adapter's JSON-RPC tools discover peers, pull traffic, reply with the original correlation, and broadcast;
- adapter replacement resumes from a durable `after_seq` cursor;
- Hub restart preserves the SQLite event ledger and forces adapters to rejoin with fresh process-bound badges;
- Room traffic never uses `roomctl`, PTY input, or terminal scraping.

Not proven here:

- **real Claude Code execution** — the CLI is unavailable, so this remains the closure gate for the ticket;
- Claude channels, HTTP MCP reconnect behavior, and H9-04 through H9-07 against the actual runtime — this stdio harness is explicitly non-attesting for those cases;
- production authentication, authorization, workflow policy, or network exposure.
