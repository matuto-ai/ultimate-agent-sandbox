# Two-Room sibling-survival regression (#79)

`tests/test_two_room_survival.py` composes the existing canonical Supervisor,
RoomLedger, Manager stream/session/read model, ExternalMutationBroker and shared
Deployment ForgeAudit. Alpha and Beta have separate persistent instances,
ledgers and Projects; they share the existing file-backed host adapter and
Deployment stores. No replacement lifecycle or security framework is introduced.

The seven cheap cases exercise Alpha Stop/resume, observed task exit, corrupt
manifest, partial Destroy/reconciliation, full Destroy/recreation, lost Stop
response and hostile Room/Actor/repository substitutions. At each failure or
cleanup boundary, Beta retains its exact lifecycle/resource identities, ledger
state and sequence, Manager in-process session/view/cursor, scoped audit revision and
diagnostic projection, provider state/call history and Project bytes. The same Beta owner then
appends a ledger event, transfers it through its existing Manager session and
executes another allowed Broker mutation. Preservation is not merely a frozen
snapshot of an unusable sibling.

## Evidence boundaries

- Lifecycle, ledger, audit and Manager persistence/dispatch are real application
  code operating on disposable temporary files/SQLite databases.
- Host resource/process observations use `FileFixtureBackend`. Setting its
  `running` observation false is **not killing a real process**. No native
  process liveness, socket isolation or operating-system access denial is proved.
- The provider uses the existing `MemoryGitHub` controlled response adapter; it
  makes no external request and does not establish native Actor permissions.
- The forged fields/origin cases exercise the actual Broker owner boundary,
  not a claim that a hostile Hub process has been launched.
- Existing #62 evidence remains reusable for its admitted Workstation, mounts,
  network and quota boundary. Its help-only service is not native Git/Hub proof.

These tests are a source checkpoint, not completion of #79's original two-stack
VM acceptance. Actual cross-Room process/network/credential attack observations,
Project-pinned native Git positive/negative operations, native Actor-access reads
and full service survival remain integration evidence. No VM workflow, target,
credentials, host changes or heavy-run permission is added by this checkpoint.
