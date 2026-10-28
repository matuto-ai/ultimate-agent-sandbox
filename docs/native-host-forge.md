# Direct native helper Forge boundary (#78)

The fixed Claude MCP helper has two same-task seqpacket connections:

* FD3: admitted peer/review traffic, transferred to the isolated Hub.
* FD4: Forge only, retained by the trusted Supervisor. The Hub never receives
  this descriptor. Native provider credentials are cleared before the helper's
  fixed Node entrypoint, as before.

The helper connects FD4 to the same Supervisor-issued endpoint after its first
release and before SDK initialization completes. `NativeDescendantLease` matches
its fixed hello against the **same retained kernel task** already lineage-bound
as the native Claude child. Release enables initialization, not Forge effects.
Both root and helper ADMIT acknowledgments are mandatory. A queued packet or EOF
on FD4 at the helper admission handoff is rejected, just like FD3.

`NativeClaudeRoot.initialize_helper(..., forge_client=existing_read_broker)`
constructs `NativeHostForge` only after both acknowledgments. The trusted caller
selects its retained FD4 for bounded `root.receive_forge_once()` processing; this
is a source composition seam, not a new daemon or production deployment launcher.
Missing exact Broker input leaves Forge unavailable. Fixture launch defaults do
not gain a native or credential path.

The original native packet and its SCM_PIDFD record remain held at the Supervisor
through request preparation, Broker authorization challenges and disclosure.
Actor, capabilities, incarnation and epoch are derived from the exact registered
native root, not supplied by the Hub or native JSON. The resulting authority
version is identical to the canonical Hub dispatcher version.

Before provider contact, the trusted host sends `RESERVE_FORGE` on its existing
private Hub control channel. This carries only the existing root operation,
helper operation, unchanged envelope, digest, controller and exchange ID. The
actual `workstation_service` entrypoint, when configured with an explicit trusted
Forge Project binding and seat capabilities, calls the canonical
`reserve_forge_operation` under local admission authorization. Its digest-bound
acknowledgment reserves the Room-wide operation namespace; **it grants no Actor
or process authority**. A hostile Hub cannot replace the original request bytes
or make the host invoke a request it did not receive from the held helper.

No lifecycle/admission/SQLite lock spans the Hub reservation RPC or provider I/O.
ReadBrokerClient still owns lifecycle rechecks, external Broker framing and
canonical audit/idempotency. The host rechecks helper/root/SDK host/controller/
epoch and Room before preparation, contact and disclosure. Requests and private
reservation frames are bounded to one 64 KiB record. Other private control
commands retain their original 8 KiB bound. Replies reuse bounded Broker framing.

There is no automatic resend. Timeout, malformed response or lost transport
fences the direct channel. A possible write remains uncertain; the existing
explicit `forge-reconcile` path retains the original mutation ID/body and audit
reference. No new workflow journal, credential, bearer token or replay cache is
introduced.

## Evidence and remaining composition

Pure guarded checks cover ownership, correlation, stale authority, lock placement,
queued pre-admission data and lost responses. The hosted-only Node transport test
now supplies distinct FD3/FD4 and checks `gh` goes only to FD4. These are not real
native Claude/SDK, account, namespace or complete-lifecycle qualification.

Pi's direct native Forge route, isolated Git provenance/target fencing, typed
human control, full isolated RunReview composition and the trusted deployment
launcher still need integration. The old same-process `attach_read_service`
remains a controlled test seam, not permission to mount a Supervisor store in Hub.
