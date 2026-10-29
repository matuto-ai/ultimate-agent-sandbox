# Native Gate local control

`NativeGateControl` connects the exact native review host to its existing
`GateSupervisorService`, retaining the artifacts, command and diff profiles.
The service must already have real boundary admission, target leases, quota
reservation and a fixed helper launcher. This adapter does not provide them.

- Source resolution uses the host's existing source owner (or exact diff wrapper).
- Preparation and launch require an active native review invocation. Its short
  canonical lifecycle → Git currentness check ends before target/Engine work.
  This is a point-in-time check, not a guarantee of later authority; canonical
  success consumption must recheck currentness.
- `GateHelperLaunch.local_offer` accepts no caller channel, credentials or PID.
  It transfers its original bound helper channel once and duplicates its actual
  held pidfd only as an observer. Original launch custody remains responsible
  for exit, postproof and cleanup; the duplicate grants no admission authority.
- Existing journal intent, one-shot service/offer maps and bounded capacity
  prohibit replay after uncertainty. Partial handoff retains original cleanup
  custody and closes the duplicate observer, never adopts a replacement task.
- Finish requires the exact stored exited offer and target. Abort/reconcile
  remain available to the original owner after participant revocation, but
  cleanup is not a Gate verdict or successful Run transition.

The transport does not replace GateHub's ledger, policies, quota accounting or
final acceptance. Controlled source tests are not native helper qualification.
