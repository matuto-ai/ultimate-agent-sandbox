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

An installed and authenticated `claude` CLI adds the real-runtime phase; without it those checks stay `blocked` and the rest of the harness still runs. That phase spends real Claude tokens (`CLAUDE_MODEL`, default `haiku`) and asks a model to make specific tool calls, so a check can land `inconclusive` on a bad turn — rerun before reading it as a regression.

## Local verdict

Proven here:

- a real Pi RPC process loads `pi-adapter.ts` and sends or receives Hub traffic without forcing an LLM turn;
- a real Claude Code CLI process (`2.1.220`) loads `claude-mcp.py` as a stdio MCP server and exchanges correlated Hub traffic with that Pi peer;
- the Claude MCP adapter's JSON-RPC tools discover peers, pull traffic, reply with the original correlation, and broadcast;
- adapter replacement resumes from a durable `after_seq` cursor, including across real `--session-id` / `--resume` Claude processes (H9-04);
- a frozen Claude process group delivers nothing until it is resumed (H9-05);
- a severed adapter-to-Hub transport surfaces a tool failure instead of a phantom delivery, and the next process rejoins (H9-06, partial);
- an alive-but-not-pulling runtime produces no delivery, because delivery is pull-only and readiness is never inferred (H9-07);
- Hub restart preserves the SQLite event ledger and forces adapters to rejoin with fresh process-bound badges;
- Room traffic never uses `roomctl`, PTY input, or terminal scraping.

Not proven here:

- **HTTP/SSE MCP transport** — the adapter speaks stdio MCP, so MCP-level disconnect and reconnect behaviour is untested; only the adapter-to-Hub HTTP transport was severed;
- Claude channels and long-lived interactive (non-`-p`) Claude sessions;
- liveness: the Hub still lists an actor as connected after its process is gone, so presence is not liveness;
- production authentication, authorization, workflow policy, or network exposure.
