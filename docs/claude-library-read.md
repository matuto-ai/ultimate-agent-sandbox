# Claude native Library lookup (T13)

The installation-selected `library-read-v1` profile exposes only Claude's native
`Read` and `Bash` tools. It is separate from the default three-MCP-tool profile and
`library-capture-v1`; choosing read access does not grant enqueue authority. The
configured tool set must be exactly `Read` and `Bash`, and the approved reference
root must be mounted read-only at `/project/reference`. Mixed tool profiles,
custom read roots and writable projections are rejected. This is an explicit
recipe selection, not a change to an existing seat or permission configuration.
The current configuration-based recipe requires its configured reference root
to be this fixed path. Direct trusted recipe construction can map a distinct
Project source to that destination. Deployment-wide multi-Room source/mount
composition remains owned by T44/#185; the fixtures below qualify two separate
read sessions, not a deployed multi-Room topology.

The supervisor's ordinary Project projection owns publication. The Runtime
cannot select a canonical repository, another Project, `.git` or credentials.
No MCP read service, derived index, embeddings, model-backed search or automatic
knowledge injection is introduced. The existing immutable image already carries
the pinned parser and Pi-local deterministic scan recipe; Claude invokes that
same filesystem recipe through its actual native Bash tool.

## Native progression

1. On an explicit lookup, browse `/project/reference/library/index.md` and its
   authored child indexes, including `pending/index.md`, using native `Read`.
2. Run native `Bash` with only the exact command:

   ```sh
   /opt/uas/node/bin/node /opt/uas/runtime/pi/library-scan.mjs 'literal term' 'other term'
   ```

   Supply 1–16 nonempty literal terms of at most 128 characters, each enclosed in
   single quotes, without apostrophes or control characters. No flags, shell
   chaining, substitutions outside these literal quotes, extra commands or
   background execution are authorized. Matching is case-insensitive AND
   substring matching across each document. Only if there are no document
   matches does the existing typo-token fallback run; it is labelled `FUZZY`.
3. Initial output contains at most eight fragment-first matches. Pending content
   is `DRAFT`, including `FUZZY DRAFT` when both apply. Type, lifecycle, derived
   OKF trust tier, freshness and source presence remain separate signals. An
   elapsed recorded freshness policy warns without preventing reading. Unknown
   existing types/keys and broken links remain readable, not authoritative.
4. Before relying on any material claim, open its containing document and inspect
   its metadata, rationale, sources and cross-references. `Read` accepts a public
   `file_path` and optional bounded `offset` (1–1048576) and `limit` (1–2000).
   Large documents require successive pages through the end, not treating the
   first native tool response as the whole document. Bracket multi-file/page
   reads with `library.snapshot.json`; if the snapshot changes, retry. Native
   output limits or incomplete reads are not evidence for a material claim.

No matches means no inferred answer. Before initial publication the manifest's
commit is null and no bundle exists. A failed refresh preserves the last coherent
snapshot and original timestamp; a lookup does not bypass it to the service.

## Instruction and permission boundaries

The host supplies reference-only guidance in the SDK system-prompt preset append,
not in a Library document or an automatically injected knowledge payload. Library
text cannot override Runtime, Project or authenticated-human instructions. This
instruction placement is observable; it does not prove a real model always obeys.

Both native tools always ask the host policy before execution. There is no
`allowedTools` auto-approval and ambient settings, plugins and MCP servers remain
excluded. The callback accepts only the exact bounded inputs above. For `Read`,
it resolves the public projection into its selected supervisor-owned immutable
generation before handing the path to the native tool; internal symlinks,
non-files, hidden paths, inconsistent generations and missing files fail closed.
The Runtime's read-only mount and trusted supervisor ownership are necessary
assumptions; a same-UID test directory does not establish that production boundary.

Denial holds conservative readiness rather than silently clearing attention.
Unknown tools/events, missing correlation, errors and ambiguous state remain
fenced. An empty MCP status for this no-MCP profile is only control-channel
liveness; it is never proof of idle readiness. Existing profiles retain their
exact tool sets and readiness behavior.

## Qualification and evidence limits

`tests/test_claude_library_read.py` uses pinned official CLI 2.1.310 and SDK
0.3.310 against a loopback-only scripted protocol endpoint, with no upstream
provider or account. Production options, permission callback and event reducer
execute. Fixture substitutions are local binary/SDK paths, reference mount and
scan command paths, plus the loopback provider. The parser is the exact existing
`yaml` pin from the Pi lock, acquired without lifecycle scripts. The hosted Claude
native gate runs this with its existing budget and network namespace isolation.

Checks cover actual system-request guidance/no initial knowledge injection,
native authored-index reads, AND/fuzzy/no-match queries, eight-result bounds,
metadata/freshness/draft labels, complete small-document and multi-page follow-up,
two distinguishable supervisor-published Git-backed projections, successful
refresh between native reads with changed manifests and distinct generations, failed refresh,
no-first-snapshot, actual cross-Project and shell-command denials, and fenced
completion. Pure contracts cover path/argument/correlation and snapshot failures.

These are native execution and observable instruction-loading checks, **not**
live inference, model obedience, provider authorization, container/VM isolation,
receiving-side canonical Git qualification or a deployment. Exact independent
Standards/Specification/Runtime review and passing hosted CI are required before
calling this slice delivered.
