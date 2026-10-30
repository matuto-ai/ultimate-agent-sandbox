# Atomic Library coordinate moves

`Relocator` implements T34 as a service-owned source binding transition. The
Manager's `library-relocate` request has an empty payload: neither a user nor a
model supplies paths. The service supplies the previous trusted scope and obtains
the newly authorized scope from the source identity owner. Source Forge identity,
immutable repository identity, Project ID and fixed reference root must match;
only the trusted repository coordinates may differ. This does not rename or
transfer an external repository or change account permissions.

The original complete bundle is validated and archived Projects refuse writes.
The deterministic writer changes only the service-owned root coordinate line and
appends a relocation log entry. Relative authored links, accepted documents,
pending draft bytes/IDs and existing log history remain unchanged. A coordinate-
normalized previous view retains tolerated unchanged reader metadata while the
normal complete-result gate validates the proposed bundle. The publisher checks
both source and destination again under its canonical write lock, rejects parent
files, any occupied destination or duplicated immutable identity, and creates one
fast-forward commit deleting the old prefix and adding the complete new prefix.
Unrelated Project paths remain unchanged. Concurrent source changes invalidate
the move instead of losing pending work.

Stable operation metadata includes both trusted coordinates. A failed preparation
leaves canonical content unchanged. A failed/unknown push or receipt write may
already have committed: retry reconciles canonical operation history before
checking the new destination, never repeating a move blindly. An old result does
not claim the destination is current after another relocation or deletion.

In-flight synthesis keeps its existing exact scope and path/content input fence.
A trusted binding update or missing/changed old subtree prevents stale model
output from being published. Already committed attempts recover using the
historical prefix recorded in their durable operation metadata, with current
same-Project authorization and historical full-tree validation; no second model
contact is made.

The supervisor replaces the projection worker when its trusted binding changes.
Its fixed filesystem root is pinned by immutable Project identity, not mutable
coordinates (legacy pins remain readable). The existing coherent generation stays
available until a successful atomic refresh; refresh failure does not resurrect
the old canonical path or mutate canonical publication. Publisher notifications
match immutable identity, so an old worker is awakened to observe its stale scope
and a new worker reconciles through normal startup/refresh. No mount changes or
host deployment are performed by this source implementation.

Validation uses disposable Git, real durable operation records and filesystem
projection generations, plus the controlled provider process used by attempt
integration tests. It covers collisions, identity mismatch, archived freeze,
revocation, stale synthesis, exact retry, lost push/receipt, restart, preserved
captures and coherent projection after failure. It does not qualify real source
Forge updates, production storage or an actual model provider.
