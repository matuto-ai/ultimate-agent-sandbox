# Native attachment loss

The existing Hub admission owner now publishes root, fixed-helper and controller
loss through `FixturePeerHub.observe(connection, Readiness.LOST)`. The dispatcher
retains the exact admitted attachment; it never applies an old loss to a replacement
attachment. A fixed Claude helper loss revokes its root and sibling helper leases.
Partial connection setup retains pending attachment bookkeeping until validation
completes, so a later admission failure can publish loss without bypassing the
existing attachment validation.

The lock order for this publication is admission then Room ledger. It is not
invoked from a transaction-time authority observation. No new readiness state,
revocation database, peer-supplied identity or bearer is introduced.

A Room write or owned-resource cleanup failure makes revocation incomplete:
no success acknowledgement is emitted, the controller is fenced, and its retained
control endpoint is closed. Failed operations remain sticky and cannot later be
acknowledged by a no-op retry. Cleanup attempts all owned leases even when one
close fails. Controller loss similarly attempts every root's loss publication.
A fenced controller cannot bind another control endpoint.

At the host, `SupervisorAdmission._current` observes the exact control descriptor
using a nonblocking poll. HUP/RDHUP/error/invalid-descriptor readiness denies
currentness even when unread reply bytes remain queued. It does not consume or
interpret control bytes and does not acquire another authority lock. This check
also covers native direct-FD4 Forge and native Claude's inherited admission check.

Control closure is a separate fence, not an atomic rollback of a concurrent
operation that already committed. Failed Room publication remains failed/unknown;
this source does not claim that durable LOST and host observation occur atomically.

Focused guarded tests use the real controlled Room ledger and inert kernel/poll
adapters: exact attachment loss, helper cascade, controller loss, replacement
preservation, failed publication, partial attachment, failed cleanup and queued
reply plus HUP. Actual OS disconnect/native lifecycle qualification is separate.
