# Opt-in native Claude SDK boundary (#78)

This source adds a fixed Claude adapter, not a replacement for the qualified
account-free tool-less fixture. The existing fixture defaults remain unchanged.

## Ownership and wire order

1. `NativeClaudeRecipe` binds the installation-selected manifest digest, immutable
   image ID/reference, dedicated runtime subtree, checkout, model, session and
   fixed payload. Configuration selection preserves the configured model and
   refuses custom endpoint mappings until supported explicitly.
2. The exact Engine task runs `claude-host-bootstrap`: first 32 stdin bytes are
   the canonical one-use launch challenge. It sends `UAS1` plus that challenge,
   waits for `UAS-RELEASE-1\n`, and execs the fixed SDK host in the same task.
   That held task is **cleanup ownership**, never the Participant.
3. The host reads a second 32-byte challenge, with an eight-second input bound.
   Public SDK `spawnClaudeCodeProcess` launches `claude-native-bootstrap` with
   the SDK-forwarded abort signal. SDK stdin/stdout/stderr are untouched; only
   private FD3 carries this second challenge. Supervisor verifies the actual
   child kernel record and immediate live host ancestry before release. The
   wrapper execs pinned Claude in the same task, retaining only the root lifetime
   channel at FD3 (unused for CLI calls). SDK stdio remains unchanged.
4. Claude launches the sole fixed stdio MCP helper. The helper sends
   `UAS-CLAUDE-MCP-1\n`; Supervisor derives its actual native parent, releases
   that exact task, and it execs the fixed Node MCP server retaining peer FD3.
   Neither handshake conveys an Actor, epoch, reusable credential or PID claim.
5. Helper initialization/tools-list may run during native initialization, but
   **no Hub/Forge action is authorized** until actual native readiness and
   canonical root ADMIT complete. The helper rejects tool calls until the exact private-channel
   `UAS-HELPER-ACTIVE-1\n` record arrives after ADMIT; the shared owner also
   rejects queued pre-admission data. Initialization never grants authority.

The Supervisor-side native root, descendant lease and private control transfer
are the authority owners. The host's numeric PID/session frames corroborate SDK
observations only. Kernel-derived namespace mapping is required before comparing
CLI-visible PIDs. The host bootstrap channel closes on exec; the native root lifetime channel
remains open for admission. Neither socket EOF substitutes for pidfd exit evidence.

## Tools and delivery

The helper exposes only `uas_peer`, `uas_review`, and `gh`. Tool inputs retain
canonical operation IDs and existing owner schemas. It never invokes gh, a
shell, GitHub HTTP, or credential loading directly. All calls use the existing
bounded seqpacket frame and canonical Hub/RunReview/Forge route; each complete
encoded request must fit one 64 KiB record. Larger writes are refused before
contact (no fragmented-request support is claimed); authority and
idempotency remain there. Interrupted transport is fenced; writes are not retried.

The native host uses strict MCP configuration, no setting sources or built-in
tools, an explicit model, a fixed 16-turn SDK bound, and a fixed environment. Unknown MCP servers, native
versions, outstanding tools, permission attention and unexpected events hold
readiness. Supported SDK session/listing observations remain separate from exact
replay acknowledgements.

`NativeClaudeReceiver` consumes the concrete root's Engine RPC stream. It reuses
`_ClaudeJournal.accept` and its existing handoff/receipt schema, while the native
opener has no fixture key or loopback bypass. Unknown intents stay unknown.
Fresh proof requires the immutable host to exclusively create a previously
nonexistent HOME under the private configured context root before SDK startup.
Preexisting homes/symlinks are refused, not cleaned or overwritten. Provider auth
provisioning for that fresh home remains unresolved; no credentials are copied
or new grants inferred. Fresh proof rejects resume; same-Run restore requires an explicit owner contract,
not relabelling a restored session as fresh.

## Validation

`test_native_claude_recipe.py` and `test_native_claude_receiver.py` cover inert
contracts and malformed frames. `tests/claude/native/check.sh` is the hosted cheap
check: compile-only all three C wrappers, syntax-check host/server, and execute
pure JavaScript policy tests. No compiled wrapper is executed by that script.

Actual SDK/MCP/native-child behavior, admitted image/provider readiness, real
Pi–Claude traffic, GitHub and human merge remain the integration proof, not
consequences of these source tests.

## Supported SDK source

Pinned official SDK 0.3.310 defines `spawnClaudeCodeProcess` as replacement
spawning, accepts Node `ChildProcess`, and forwards a signal after its graceful
stdin-EOF window (`sdk.d.ts` lines 2490–2508 and 9792–9878). Assistant correlation
is stamped only on the first frame of a turn (lines 3688 onward); subsequent
frames remain within one already-bound, acknowledged invocation. The fixed MCP
server negotiates the pinned SDK's 2025-11-25 protocol plus prior supported
versions. See [official MCP documentation](https://code.claude.com/docs/en/agent-sdk/mcp).

### Persistent provider authentication is separate from context reset

Fresh HOME is not a requirement to log in or configure the provider every
session. The accepted boundary retains Runtime-owned provider authentication;
context history and provider credentials have different lifetimes. The missing
composition contract is:

- Installation selects one persistent **Runtime/provider credential reference**,
  independently of Actor GitHub credentials and of the native session ID.
- A trusted startup owner resolves that reference for the already selected
  Runtime/provider/model and injects only the provider-supported authentication
  material into the fixed native host's supported auth surface. No generic
  caller-supplied environment, provider switching, or whole-HOME restoration.
- Fresh context HOME/session creation remains exclusive. Reset/restart reuses
  the same persistent reference, while revocation remains visible at startup;
  missing/invalid auth holds inference without silently selecting another account.
- Secret bytes never enter recipe manifests, command-line arguments, handoff
  journals, readiness evidence or MCP tool schemas. The existing outer boundary
  still owns mount/egress and process admission.

This adapter has not implemented that trusted reference-to-native-auth binding.
It must be wired once at installation and reused, rather than asking the user to
repeat authentication per Run. No credential read, copying, provisioning or
permission change is performed by this source slice.
