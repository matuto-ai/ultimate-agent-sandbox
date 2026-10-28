# Opt-in authenticated native qualification (#78)

The fixed source entry now connects the existing human mTLS mechanism to the
actual native Run and Manager owners. This is a bounded, disposable qualification
path—not a production launcher or completed native lifecycle result. Ordinary
`qualify-native` remains pair-only when the optional input is absent.

## Explicit operator input, never request identity

An installation may explicitly select `human_host_manifest: {path, sha256}`.
The only accepted path is
`/etc/uas/native-human-grants/<installation nonce>.json`. It must already exist
under root-owned, non-writable-by-others, no-symlink directories, as a root-owned
private regular single-link file. Nothing creates it, changes permissions,
installs a certificate, or broadens a Start or Room-stream certificate binding.

Its exact schema is:

- `version: 1`, `purpose: "one-original-native-qualification"`;
- exact `deployment_id`, `room_id`, `configuration_sha256`, `installation_nonce`;
- explicit `manager_id`, `client_certificate_sha256` (DER SHA-256);
- `human_origin` with unchanged `actor_id`, `participant_id`, `incarnation_id`,
  `authority_version`, and an explicit `capabilities` list;
- explicit `actions` from `open-run`, `authorize-run-request`, `observe`,
  `request-changes`, `reconcile-changes`;
- `tls` containing only existing `trust_file`, `certificate_file`,
  `private_key_file` references.

The protected document is an **operator grant**, not an incoming identity claim.
Its nonce and hashes correlate that explicit grant; they do not create authority.
`open-run` and `authorize-run-request`, plus `human-open-run` capability, are
required. Either control action additionally requires explicit `observe` and
`human-control-run`. Empty scopes grant nothing. Merge, Start, Stop, arbitrary
Manager commands, account changes and permission expansion are not supported.
Actual operator grants, fingerprints and TLS references remain unselected here;
configuring them requires the operator's separate approval.

The Root owner retains the original read-only manifest FD. The final host checks
its ownership, identity, size and hash before and after parsing. It creates the
exact-instance grant only after observing the original running Room/configuration
in the canonical lifecycle owner. No wildcard instance, persisted authentication
success, JSON callback or fresh-grant fallback is accepted. This is immutable
one-invocation input, not a new hot-reload/revocation service. Existing retained
binding revocation and current Room/instance fences remain authoritative.

## Supported entry and ownership

A trusted listener owner supplies an already accepted **raw** stream through
`execute(plan, human_channel=channel)`, or passes its owned FD to
`python -m uas qualify-native … --execute-qualification --human-stream-fd FD`.
The command creates no listener and chooses no network endpoint. Socket checks
prove a connected raw stream, not historical acceptance; actual server-side TLS
and the explicit certificate binding authenticate its peer.

With both explicit inputs present, Root selects only `uas.native_human_entry`,
passing the raw stream and protected manifest FDs to the exact owned child.
After child adoption Root closes its descriptor copies, so it cannot mask the
child's TLS EOF. A transfer is marked one-shot before process creation; unknown
startup is not retried or converted into pair mode. Existing retained provisioning
rejects repeat/unknown invocations. Startup JSON contains references, original
instance and deadline only—not Origin, capabilities or authentication success.

The final non-root host negotiates TLS itself. An SSL connection is never passed
through exec as a numeric FD. TLS uses existing protected read-only references;
unreadable or changed references refuse startup, never trigger copying/chmod or
credential setup. The original Root monotonic deadline bounds handshake, retained
transport and native work; `run()` does not restart that deadline.

The first valid frame is:

```json
{"version":1,"action":"open-run","payload":{"operation_id":"chosen-operation","issue_number":78}}
```

The trusted selected plan chooses the Participant. Repeating identical frame data
does not open a second Run; changed operation/issue is rejected. The retained
transport described in [native-human-control.md](native-human-control.md) requires
complete valid frames within its at-most-five-second freshness interval. An
`observe` frame with `{}` payload can maintain that finite qualification lease.
This is not a claim of instantaneous remote-disconnect detection. Observed EOF,
transport failure, expiry, stopped pumping or revoked binding terminally denies
authority; late frames cannot revive it.

## Consumed canonical owners

The same exact `HumanSession` reaches `NativeHumanRunRequest`, native admission,
reviewer recruitment, same-Run restoration and the native driver. After `run()`
creates its original private `ReadBrokerClient`, it creates `NativeBrokerAudit`
and `NativeHumanReviewInbox` from that client and session. No alternate Broker,
empty host-local audit database, filesystem grant or arbitrary factory is used.

The TLS I/O thread performs framing/queues only. The native owner thread drains
unchanged Manager envelopes outside lifecycle, Git and SQLite locks. The existing
Manager/RunReview owners recheck action, current instance, exact observed version,
original audit uncertainty and continuing human authority at their consuming and
provider cuts. A lost response does not permit another comment or native effect.

`observe` requests a bounded canonical projection: Run ID, generation/status,
observed version, review stage, submission ID and Forge uncertainty. The Broker
retains its original audit writer fence through only the short local Hub snapshot;
acquisition/release occur outside owner locks. No provider call or audit row is
exposed. The transport response is explicitly **last published, not live**; a
queued response is not a mutation receipt. Current `observed_version` is always
rechecked by the consuming owner. Human comment bodies and Origin metadata are
not echoed in transport projections.

Root accepts `NATIVE_RUN_SESSION_FINISHED` only in selected human mode, with exact
configuration, installation, manifest and instance binding, original request/Run
correlation, and explicit remaining lifecycle blockers. Finished can mean
inconclusive, attention or unknown; it does not mean completed.

## Evidence and remaining limits

- Finite guarded tests cover actual canonical Run/comment reducers, the original
  Broker audit fence, fixed child/FD ordering and controlled entry/TLS seams.
  Native process, socket, thread, ctypes, TLS and permission boundaries are
  denied before repository imports; their test doubles are not runtime proof.
- Three additional real-mTLS cases reuse existing hosted temporary certificates
  and loopback. They run only with the existing hosted gate, together with all
  existing Manager TLS tests under the same 40-second/one-minute budget. A default
  suite skip is **not** an actual TLS pass.
- Actual native/account-connected execution, selected Project/Room policy and
  authorized target, production listener setup, and the original aggregate #78
  scenario remain separate. The finite qualification still tears down on lost
  human session/timeout; this does not establish persistent product-Room behavior.
