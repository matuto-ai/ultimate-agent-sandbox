# Project Library registration

`uas.library_registration.Registrar` implements the service-side `register`
operation in #155. Its input is the existing authenticated human `library.action`
contract with an empty payload, admitted settings, and a current-scope callback.
The trusted service binds that callback to live human authority, not caller
claims. The configured target and branch must match its started `LibraryGit`.

Registration reads the requested Project at one freshly fetched canonical SHA.
A service-only root-index identity catalog rejects an existing immutable source
identity at different coordinates; registration is not the rename/transfer
operation. This bounded catalog reads no concept or source-document content.
It fails closed beyond 1,024 root indexes, 16,384 Project paths, 4 MiB of path
listing, or its five-second scan window, rather than checking only a prefix. The Git reader accepts bounded regular files and refuses symlinks, gitlinks,
parent-file collisions and oversized trees. It neither scans source documentation
nor invokes a model. A new Project gets exactly the six-file skeleton, including
the deterministic reference-data notices, trusted source identity/coordinates
and one dated Initialization entry. The sole `library_gate.validate` boundary
checks that complete proposal before the existing publisher commits and pushes.

An existing healthy matching bundle is validated unchanged. Exact retries and
new registration requests create no commit or log entry; conflicting identity,
partial or malformed bundles fail closed. Unknown tolerated reader content stays
byte-for-byte intact. New content cannot displace a file at a parent coordinate.
Publisher compatibility checking rechecks ancestor kinds and identity locations
under its write lock, refusing a concurrent Project creation rather than
overwriting it; a new attempt can reconcile by reading again after a terminal refusal.

The optional root-body line `Library state: archived` records a write-frozen
bundle; `Library state: active` or no line means active. Multiple declarations or
unknown values are refused. The shared `project_state` reader is the narrow
consumer contract for the later archival/restoration owner (#181), which must
commit its transitions through the content gate. Registration never adds this
line, implements no archive/restore action, and never changes an archived bundle.
No extra file, OKF frontmatter key or caller-supplied lifecycle flag is introduced.

`Registration.commit_sha` is the durable receipt's publication; `observed_sha`
identifies the current canonical observation and `state` reports current active
or archived state. An older retry receipt remains immutable even if current
canonical state has advanced. `created` is true only when this attempt created a
new publication. The receipt has no projection claim. The T07 owner can consume
the returned canonical identity independently; projection refresh is not a
registration prerequisite or completed feature here.

Operation identity is recorded before publication, and its terminal metadata-only
receipt is durable before acknowledgement. Lost push acknowledgement and a
crash between publication and receipt are reconciled using canonical Git; neither
creates another initialization. New-attempt definite pre-publication refusals finish with a safe terminal refusal, so they
do not consume pending capacity indefinitely; an exact retry retains that
refusal and corrected work needs a new identity. Preexisting pending attempts and transient read outages preserve uncertainty.
Registration admission and receipts are serialized per singleton publisher,
including concurrent exact retries. Truly uncertain publication attempts retain
their pending record for reconciliation rather than fabricating
success. A recovered historical publication is rechecked against current
canonical content and cannot report success for a deleted bundle.
Current authorization is rechecked before reads and within the publisher before
commit/push. A revoked request can fail after publication; a later authorized
retry reconciles rather than undoing published content.

## Validation and boundaries

`tests/test_library_registration.py` exercises a real disposable Git receiver,
with an explicitly mapped local transport standing in for its admitted SSH name.
This is real Git object/publication/recovery evidence, **not** actual SSH
credentials, receiving-policy qualification, backup durability or live deployment
acceptance. Tests cover exact six-file content, two Projects, historical receipts,
reader tolerance, archived state, gate rejection, partial/malformed/conflicting
bundles, ID conflicts, revoked authority, bounded reads and lost acknowledgement.

Run focused checks with the installed requirements:

```
PYTHONPATH=.:tests python3 -m unittest test_library_registration test_library_git test_library test_library_records test_library_sources
```

The aggregate discovers the new tests without exclusions. Actual target and
recovery qualification remains #157; authenticated Hub routing, projection,
archival actions and deployment composition remain their own slices.
