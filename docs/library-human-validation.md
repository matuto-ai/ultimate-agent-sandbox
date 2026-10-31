# Human inspection/privacy acceptance run (T44 / #195)

**Status: prepared, not performed.** This is the human-required journey in
[immutable specification, Validation 3](https://github.com/matuto-ai/ultimate-agent-sandbox/blob/aec975f074fef3d215d5b6f0f3b54ebcde062791/docs/specs/per-project-librarian.md#validation).
Automated browser/service fixtures and local recovery tests are complementary
receipts, not a human login, a human decision or this acceptance run. Keep #195
open until the required evidence exists. Preparatory code and runbooks may be
merged into the consolidated 0.1.0 testing candidate; this does not establish
human qualification or relax runtime admission guards.

## Before booking the human session

Use an already authorized disposable installation and synthetic conflict; do not
copy user-private documents, credentials or production conclusions into evidence.
No VM run, provider call, deployment or permission change is authorized by this
checklist. Actual repository/model qualification remains separate (#157/#171),
even if a disposable Git target and deterministic runner pass these checks.

Record the exact candidate commit **and tree**, base commit, browser/version,
OS/installation identity, selected configuration digests, canonical target/branch,
immutable identities of Projects A/B, Room/Hub instance, and host attachment
version. Record human/Actor identity references and grant versions without tokens.
An owner must fill these from the running installation, not the branch name.
Changing relevant source, configuration, identity or environment invalidates the
affected result. For source identity, from the candidate checkout run:

```sh
git rev-parse HEAD HEAD^{tree}
git status --porcelain
```

Required readiness checks (stop and record `BLOCKED` if any is unavailable):

1. An actual interactive Manager host supplies trusted authentication to
   `FieldNotesLibraryHost`, its fixed `ManagerLibraryHub` and service contact.
   Its Project attachment binds the existing `installLibraryActionHost` hook.
   The containing host must provide its authenticated URL and transport; neither
   that hook nor a browser test fixture implements login. At preparation time,
   the repository supplies these adapters and the Field Notes prototype, **not
   an installed browser composition for this Library attachment**. Do not invent
   a URL, paste an all-authorized JavaScript adapter into DevTools, or substitute
   a screenshot from automated Chrome for the missing human session.
2. The installation owner identifies the already running local operator endpoint
   and its current human resolver. Installed wiring uses
   `<installation root>/library/operator/library-operator.sock`; the endpoint is
   optional and must not be silently enabled. OS socket ownership alone is not a
   Project grant. See [installed wiring](library-deployment.md#installed-deployment-wiring-252)
   and [local controls](library-controls.md).
3. Prepare two disposable immutable Projects with different marked committed
   pending items. A's bounded conflict directly references same-Project context;
   include harmless literal HTML/Markdown and an inert remote URL under
   `example.invalid`. Keep B's marker distinct. Prepare a blocked batch with
   remaining work and an eligible parked item through existing fixture/owner
   setup; do not edit canonical clones behind the service.
4. The environment owner supplies already authorized Project-A-only,
   installation-settings-only, and revoked identities; a method to change test
   content/settings and hold/release a bounded busy attempt; and a controlled
   response-loss/disconnect mechanism. Missing controls are a blocker, not an
   invitation to grant privileges, start a live model, or kill unknown processes.
5. Inventory maintained Manager/Hub databases and WAL, logs, audit, replay,
   browser origins/storage/cache/service workers, and Gotify message/outbox sinks.
   Record exact owner-selected locations and scan method before the run. A sink
   that cannot be inspected is `NOT OBSERVED`, never assumed clean.

## Human-operated steps and expected evidence

Use separate synthetic markers for A's pending body, selected context, B's body,
conclusion, rationale and an unsubmitted draft. Keep marker values in the private
run record. Published receipts contain only marker labels/digests and counts,
not bodies, raw network traces or screenshots of user-private content.

| Step | Human action | Required observation |
| --- | --- | --- |
| 1 | Sign in as A-authorized human; open Project A → Library actions → **Inspect and act**. Read the privacy disclosure. Enter the opaque pending ID, then **Open committed item**. | Only the explicitly opened committed item and service-selected direct A context appear; missing/omitted context is disclosed. B's marker never appears. Literal markup stays text; browser network inspection shows no content-triggered remote requests. Record queue ID, input commit and bounds, not its body. |
| 2 | Enter a marked unsubmitted conclusion/rationale. Close, navigate away, then reopen; repeat with disconnect/reconnect and refresh. | Text and draft fields clear. No offline view/autosaved draft is offered. Reopening requires a fresh authorized read. Revoke the test identity through the owner's prearranged mechanism and try reopening: no content is disclosed. Restore only through that mechanism. |
| 3 | Inspect again. Have the test owner change the relevant committed input or settings, then try the old disposition. Refresh and explicitly inspect again. Separately hold the bounded busy attempt and try a conflicting action. | Stale/busy is not success; no fabricated commit. Old evidence cannot authorize a new write. Wait for the bounded attempt rather than blindly retrying. Record finite reason and before/after canonical head. |
| 4 | Choose **Adjudicate with conclusion and rationale**; personally enter the marked conclusion and rationale, then **Submit human disposition**. | Only a `COMMITTED` receipt with the actual pushed commit establishes publication. Inspect the authorized canonical target at that commit: `decisions/adjudication-<queue-id>.md` preserves both authored fields under documented UTF-8/NFC/LF normalization. Verify real authenticated human/Actor, request, input commit, source-draft digest and timestamp provenance; `generated: false`, `verified: false`. Accepted concepts stay unchanged; no model reinterprets the decision. |
| 5 | Observe the blocked batch after disposition, then select **Resume remaining work**, **Refresh action state**, and explicitly submit it. | Disposition does not implicitly resume. Resume has a separate receipt and never resurrects the disposed drain. Scheduling `ACKNOWLEDGED` is not a content commit or model success. |
| 6 | In a fresh disposable case, lose the response after a write using the owner's fault control. Reconnect and use **Reconcile original outcome**. Also test loss before service admission. | Only safe operation metadata survives. Reconciliation uses the original operation, not a new write or cached private body. A known committed receipt resolves to its original commit; absent/pending evidence stays unknown. Revoked reconciliation refuses disclosure and does not convert unknown into failure or permit a replacement write. |
| 7 | Open the separate **Library settings** page as Project-only identity, then as installation-settings identity. Use **Refresh configuration**, change one allowed shared value and **Apply to all Projects**; stage a second edit from stale configuration. Try A/B inspection as settings-only identity. | Project-only access is refused. Settings affect all Projects; admitted update is `CONFIGURED`, not Git/model success. Stale update cannot overwrite current configuration. Settings authority grants no Project content access. Record before/after revisions and restore test settings using a fresh authorized update, not store deletion. |

See [panel semantics](library-manager-actions.md), [faithful adjudication](library-adjudication.md),
[resume](library-resume.md), [settings](library-settings.md) and
[body-free Manager reconciliation](library-private-transport.md#t32-intervention-attachment-and-reconnect-receipts).

## No Hub, including after Room destruction

With the installation owner present, use only disposable owned resources. First
make the Hub unavailable through the approved lifecycle mechanism while leaving
the external Library service running. Repeat after actual Room destruction; a
Room Stop alone does not prove destruction. Record the lifecycle receipt and
absence of the Hub/Room, surviving service identity, canonical head and data.
Do not destroy a real Room merely to execute this document.

The existing host-local Python client is `uas.library_controls.request`, not a
Library CLI subcommand. In the candidate checkout, the already authenticated
installation operator can make this **read-only** observation (set `INSTALL` and
`PROJECT_ID` to the owner-verified values):

```sh
INSTALL=/absolute/existing/installation PROJECT_ID=project-a python - <<'PY'
import os
from pathlib import Path
from uas.library_controls import request
reply = request(Path(os.environ['INSTALL']) / 'library' / 'operator', {
    'version': 1, 'action': 'observe',
    'project_id': os.environ['PROJECT_ID'], 'for_action': 'drain',
})
# Do not print full responses or inspection bodies into terminal/log evidence.
print({'outcome': reply.get('outcome'), 'error': reply.get('error')})
PY
```

Continue a bounded explicit inspect and human intervention through that same
socket, using the exact versioned contracts in [inspection](library-inspection.md)
and [adjudication](library-adjudication.md). The trusted resolver supplies identity;
never add grants, actor IDs or paths to request JSON. Observe/open fresh versions,
keep request/body only in the authorized human client's transient memory, and
record the safe final receipt plus canonical comparison. Repeat with revoked and
cross-scope principals; both must refuse without disclosure or write. An installed
resolver unable to represent these test identities is an explicit environment gap,
not proof from the default installation owner's broad approved bindings.

For lost local replies, preserve the exact request ID and original request in
transient human-client state. For a confirmed recorded operation, an exact retry
must return the same effect, never a second publication. Do not use a socket
resubmission as a read-only probe of an absent/uncertain operation: `handle` may
admit it as a new write. Keep that outcome unknown until the trusted service
owner establishes its record. The local
socket does **not** expose Manager's body-free `mode: reconcile` or `receipt` wire
schema; `Controls.reconcile`/`receipt` are trusted in-process service APIs. If the
original private request is lost, do not manufacture a new one to resolve it: have
the existing trusted owner establish the receipt or record recovery as blocked.
Demonstrate before/after-response-loss cases using the prearranged fault control;
do not infer a result from timeout alone.

## Privacy inspection and completion record

After inspection, submission, reconnect and local recovery, scan the inventoried
surfaces for **all six distinct markers**, including encoded/escaped forms used
by each owner. Check actual DB/WAL records, maintained log/audit/replay output,
Manager snapshot/event frames, browser localStorage/sessionStorage/IndexedDB,
Cache Storage/service-worker caches, and Gotify outbox/delivered message surfaces.
Inspect both current and retained replay windows covering the run. Disable body
capture in the evidence collector; record only sink identity, time window, marker
label, match count and PASS/FAIL/NOT OBSERVED. Do not paste matching content into
an issue. A missing/unconfigured Gotify sink is `NOT EXERCISED` with its actual
configuration evidence, not a tested delivery path.

Canonical Git intentionally retains accepted human content; it is not an
intermediary leak. Private text may exist transiently in authorized UI/service
memory. This run promises neither memory zeroization nor physical-remanence,
browser-extension or operating-system-swap protection.

The final private run record must contain:

- exact candidate/base/tree and environment/configuration bindings above;
- human name/identity reference, execution time and personally performed steps;
- per-step PASS/FAIL/BLOCKED, safe receipt/commit IDs, before/after state,
  explicit failures and recovery results;
- surface inventory and marker scan counts, including inaccessible/unused sinks;
- separate links to focused automated tests, complete CI, browser automation,
  independent exact-candidate Standards/Specification/Runtime review, and this
  human evidence. Do not combine them into one green label;
- remaining gaps and cleanup/restoration receipts for disposable resources.

Any missing human action, genuine host binding, inaccessible required privacy
surface, uncertain outcome or unproved destroyed-Room recovery keeps acceptance
pending. Preparation and green automated fixtures do not close #195.
