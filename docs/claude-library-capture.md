# Explicit Claude Library capture (T11 / #167)

The immutable Claude recipe has two distinct qualified profiles. `native-v1`
retains exactly the existing peer/review/Forge tools. `library-capture-v1`
exposes exactly `mcp__uas__library_enqueue`, no builtin, shell, file, Forge or
peer tool. The tool-less readiness fixture is unchanged. This is not the
Library synthesis-model qualification (T42), nor a live provider qualification.

## Selection and authority

A trusted configured Claude Participant Profile opts in with `tools:
["library.enqueue"]` and the current `library:enqueue` capability. A mixed tool
list or missing capability fails configuration-to-recipe selection. Direct
trusted recipe construction may explicitly select `tool_profile` for the same
narrow profile. The selection participates in the immutable recipe digest and
is forwarded only through fixed host/helper arguments. Unknown profiles fail
closed. No input to the capture tool selects a profile, Project, identity, path,
endpoint, credential, model or queue.

The native host still pins the official SDK/CLI and immutable payload. Exact
init tool inventory, MCP connection, turn IDs and tool result correlation remain
required. The production helper still uses the existing held native-child
lineage and Hub admission channel. The Hub derives Project/Actor from current
admission, checks `library:enqueue` for every attempt, and delegates to the
existing Library enqueue owner. Selecting the profile does not grant authority.

## Deliberate tool and retries

Call `library_enqueue` explicitly with `request_id` and `capture` (type, title,
body, optional sources and hints). The shared Pi/Claude adapter keeps these bytes
and ID unchanged and generates a fresh Hub Command ID per invocation. Its
response includes both IDs so an explicit retry can retain the Library ID and
payload. There is no hidden retry, transcript scanning, Run/reset hook, alternate
queue, working-copy fallback, or capture prerequisite for Run completion.

Only a validated `DURABLY_QUEUED` outcome proves publication. `NOT_DURABLE` is
retryable uncertainty, not proof that no write happened; `REJECTED` is a definite
service refusal. Hub refusal is distinct from a Library outcome. Unreachable or
invalid Hub responses return `TRANSPORT_UNAVAILABLE`, never fabricated Library
success/failure evidence. The shared authenticated Library framing can carry captures larger than one
64 KiB peer record, but the Claude host still retains its existing 256 KiB
native event-frame bound and 128 KiB send bound. This slice does not qualify
arbitrary 1 MiB native tool calls or raise those guards. Oversized native
frames fail closed; no truncation or success is invented. Unrelated native
tools retain their single-record guard. The 70k fixture body proves exact fragmented
transport to the Hub and the default Library policy rejection (`CAPTURE_TOO_LARGE`),
not permission to exceed the configured content limits.

## Qualification evidence and limits

Pure policy tests assert exact inventory/refusal, no credential forwarding,
unchanged default profile, and exact payload/ID/result behavior. Recipe tests
bind profile selection to current configuration and immutable artifacts.
The bounded official CLI/SDK loopback fixture exercises the real native MCP
profile and capture transport against the actual authenticated Hub/service and
disposable Git. Its controlled protocol response is not model obedience,
production credentials, real provider access or user-machine isolation proof.

New images must be built from this source: both runtime manifests now bind the
shared `runtime/library-capture.mjs` artifact. Do not relabel an older image.
