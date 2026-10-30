# Bounded Project diagnostics

`uas.library_diagnostics.Scanner` implements T36 / #159. It accepts one immutable
canonical Project tree and input SHA, admitted versioned settings and a fresh
scope callback. `Diagnostics` composes it with the canonical publisher's
metadata-only subscription: startup, successful Project publication, reconnect
and explicit `request()` schedule checks. Mailbox versions coalesce bursts.
There is no periodic maintenance timer, model call, repair, draft creation,
publication hook callback or second write veto. Runtime adapters and human
command routing remain their owning slices; `request()` is a trusted service
entry point, not a new unauthenticated endpoint.

## Meaning and coverage

Checks reuse the existing canonical text, frontmatter, structure, index/log,
source-declaration and Markdown parsers. Unknown existing reader fields/types
and existing external links remain tolerated. Structural violations are separate
from broken internal links, elapsed recorded `stale_after` (ISO date or aware
ISO timestamp), missing optional provenance and isolation observations. Index,
log, self and pending links do not establish incoming accepted-concept links.
No observation proves semantic truth or renews verification/freshness.

Sources are read only through preconfigured T14 local `Resolver` instances or
same-snapshot concept bytes. No HTTP/source fetch is performed. An absent
resolver/material or a source without a pinned range/hash is **not checked**;
configured but inaccessible/unauthorized material is **unavailable**. Only
available pinned bytes disagreeing with a recorded range/hash report a mismatch.
A source repository's moving branch is not consulted to invalidate old pins.
Canonical Library snapshot refresh is distinct from external source fetching.

Every report includes Project and scan identities, input SHA, observation time,
rule version, configuration hash, per-area checked/unchecked coverage and source
states. Findings contain fixed category/code plus hashed locations, content and
optional target/declaration, never raw text, titles, paths, URLs, secret matches
or exception messages. Finding IDs correlate Project/rule/configuration/location
and relevant hashes; new content or configuration produces new assessment IDs.
No scan creates resulting content references.

Interruption, unit/deadline exhaustion, oversized snapshots or unregistered
Projects preserve explicit unchecked coverage. `no_findings` is null for partial
reports. Completed scans still distinguish unchecked/unavailable provenance.
Reports never clear findings from earlier reports, including unchecked areas.
Old-SHA reports remain historical, not promises about current canonical content.
The service history is a bounded observation window (default 32, maximum 256);
operators can persist metadata-only reports with `sink`. It is not an active
findings database or a durable audit-storage claim. Sink failures expose only
`SCAN_UNAVAILABLE` and cannot change canonical publication outcomes.

## Bounds and operational composition

Admitted document/source/byte ceilings apply before parsing. Work also has at
most 20,000 units, 4,096 findings and a default 30-second cooperative budget
(maximum 60 seconds). The deadline is checked between bounded parser/source
steps; an already-running T14 read has its own five-second process ceiling.
Canonical Git transport retains the publisher's existing bounded transport
limits. `close()` signals cancellation, wakes the mailbox and joins the worker;
it does not kill or modify canonical operations. Archived bundles use exactly
the same read-only checks. Failure to obtain a snapshot retains prior reports
and reports safe service-level unavailability rather than fabricating a clean
empty snapshot.

## Evidence

`tests/test_library_diagnostics.py` covers pure immutable snapshots and a real
disposable local Git publisher: startup/change/explicit/reconnect work, coalescing,
publication while the report sink is blocked, structural and observational
findings, pinned-source distinctions, private metadata, historical results,
partial coverage, bounds and archived read-only behavior. This is local process/
Git evidence, not native Runtime, remote-host qualification or deployment proof.
