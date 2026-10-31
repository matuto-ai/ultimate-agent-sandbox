# Manager Library inspection and interventions (T32)

The Project's **Library actions** attachment uses the existing authenticated
Field Notes host, Room Hub and Library Controls path. Installation settings stay
on their separate, installation-authorized page. An attached handler is trusted
host composition, never authority supplied by the browser. The Library Service
rechecks current Project grants, configuration and relevant target versions.

## Explicit inspection, not a browser or editor

Opening one opaque pending-item identity first observes current service evidence,
then requests its bounded committed text. The service chooses same-Project direct
context and reports missing or truncated context. The panel displays plain text,
not Markdown/HTML; it does not expand links or load remote resources. There is no
path input, recursive browsing, shell, clone editor or Participant API.

Item text, context, rejection reasons, conclusions and rationales are transient
in-memory UI state. They are not stored in local/session storage, IndexedDB,
caches, notifications, Manager/Hub databases or replay. Navigation, disconnect,
reconnect and refresh discard private state; a later open requires fresh
authorization. Unsubmitted text can be lost on refresh or a crash. Canonical Git
intentionally records an accepted human disposition, unlike intermediary stores.
This does not promise secure memory erasure or protection from browser extensions.

## Distinct service-owned outcomes

- **Drain:** request one fair bounded unit; does not preempt or bypass a block.
- **Retry:** retry the existing blocked drain with its complete original batch.
- **Defer:** snooze attention only; leave work, parking and blocked state intact.
- **Requeue:** release only parked work whose recorded prerequisite is resolved;
  does not unblock the Project or start a drain.
- **Reject:** publish a reasoned disposition, retaining canonical history.
- **Adjudicate:** publish the human conclusion and rationale faithfully, with
  deterministic formatting and provenance, not model reinterpretation.
- **Resume remaining work:** a separate request and receipt after terminal
  blocked-batch disposition; never resurrect the disposed drain.

Scheduling and attention acknowledgements are not Git commits. Content success
cites the service's pushed commit. Stale evidence requires refresh, busy requires
waiting for the bounded attempt, refusal is not success, and an unconfirmed
outcome remains unknown until an authoritative receipt resolves it. Repeating the
same operation cannot repeat its write; changing payload under an existing ID is
rejected. The UI keeps only safe operation metadata for reconnect reconciliation,
not the original private request body.

## Evidence and limits

The existing Field Notes check entrypoint exercises both in-memory DOM contracts
and actual Chrome against a persistent Python service-backed fixture. The fixture
uses real Git, SQLite, Library Controls, authenticated host/Hub adapters and
Manager read-model/replay owners. It uses disposable Projects and controlled
trusted human identities, not live accounts or provider calls. Distinct markers
probe explicit inspection, same-Project context, inert rendering, revocation,
stale/busy/refused/unknown states, exact retry, recovery and private-state clearing.
Maintained stores and replay/notification surfaces are checked for marker absence.

This is the T32 panel proof, not T44's full deployment human journey, actual private
repository qualification, model qualification or an installed browser login.
No new heavy VM qualification is required or claimed by this slice.

The separate [T44 human validation checklist](library-human-validation.md)
records the interactive-host prerequisites, personally performed journey and
local recovery evidence still required. Automated panel proof does not satisfy
that human acceptance gate.
