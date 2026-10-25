# Migration record

## Scope and provenance

This change restores the existing Ultimate Agent Sandbox spike from the human-supplied migration archive. It does not implement the successor backlog. The source main commit is `59f21d308ebc46170109236b11af91b1ca417530`; its ancestry is retained as a merge parent without replacing the GitHub repository's existing history. Source research, feature, session, and archive refs remain in the private Git bundle rather than being published automatically. Merge the restoration pull request with a merge commit, not squash or rebase, to retain the imported source ancestry on the destination main branch.

The destination already contained merged pull request #1, and the restoration is pull request #2. Original issue and pull-request numbers therefore cannot be preserved. The [explicit source-to-destination map](migration-map.md) records all 80 imported work items: 66 issues and 14 explicitly titled historical PR archive issues, not fabricated native GitHub merges or approvals. Original authors and timestamps are attributed in migrated text; GitHub import timestamps and the importing account are not historical identities.

[GitHub issue #58](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/58), imported from source issue #56, is the approved current specification. It supersedes contradictory terminology and workflow in the historical README, CONTEXT, architecture documents, and issue-management contract. The successor still targets Gitea; moving this development repository to GitHub does not authorize implementing a GitHub product adapter.

## Private local material

The archive, its raw forge records, all 58 workspace files, 13 attachments, both Git bundles, the separate release-publisher reference, and archived environment guidance remain in the local project workspace, outside this repository. Private migration material lives under `/project/workspace/github-migration/`; the source and reference histories are independently restored in its `source-history/` and `reference-history/` folders. Workspace research, prototypes, handoffs, UI feedback, and execution views are restored to their original relative folders. The release-publisher reference is not the missing ai-agents-sandbox baseline. Historical environment guidance is retained as evidence, not activated as current instructions.

The human explicitly authorized publishing the code pull request and migrated issues after the destination was identified as public. This authorization does not publish the private workspace or the complete migration package.

## Tracker representation

Source managed labels use `/`; this GitHub repository already uses canonical `:` labels. All 14 equivalent labels are mapped by role with matching colors, with original names retained in migration provenance. Source assignments, reviewers, and milestones are not applied without a confirmed account mapping. All 110 native dependency edges match the source graph. The 61 explicit source parent/map relations are preserved separately in mapped body relation lines, not manufactured native GitHub parent objects. All 83 conversation comments and 14 historical reviews retain source attribution and chronological order rather than impersonating their authors. The 66 source issues retain their original titles and states: 28 open and 38 closed; all 14 historical PR archive issues are closed.

## Missing inputs and evidence limits

The final older ai-agents-sandbox source baseline is absent and may be needed for later parity work. Credentials, deployment configuration, runtime sessions, full external repositories, wiki and project boards, releases, CI logs and artifacts, branch protections, and full issue-event timelines are not supplied.

The source `.gitea/workflows/` files are retained as historical source, not installed as GitHub Actions. The source issue-management contract is likewise historical Gitea configuration, not a verified GitHub workflow contract. CI and closed-issue cleanup still need deliberate GitHub adaptation. `validate.sh` prints `Dummy validation for now`; its exit code is not functional or security evidence. Real Runtime, Broker, isolation, recovery, lifecycle, capacity, and integrated successor acceptance remain outstanding under the specification.

Attachment bytes are retained privately with UUIDs, filenames, sizes, and SHA-256 hashes. They are not uploaded to this public repository as part of code and issue restoration. Migrated attachment references link to the owning GitHub issue's UUID/hash manifest, not a public download. Historical PR diffs likewise remain in the private migration archive; the restored Git history provides their source commits.

## Verification

All archive SHA256SUMS matched. All 32 source snapshot files are present with their original executable modes; 26 are byte-identical and six have intentional copyright, current-spec warning, or same-project link adaptations. All 58 private workspace files match their archived bytes. Both restored Git histories passed full fsck: 55 source commits and 132 separate reference commits. All six advertised source branch tips remain available locally.

Live GitHub reads verified all 80 mapped issue records, states, titles, label assignments, 97 attributed comment/review payloads, 61 explicit parent relations, and exactly 110 native blocker edges. Source issue #80's five `@plannotator` mentions were code-quoted by the forge broker; its observed warning was retained in the private migration evidence. No historical author identity, timestamp, native approval, or merge event is fabricated.

Python source syntax, shell syntax, and the Manager checker JavaScript syntax passed. The Go toolchain is unavailable in this environment, so session-control compilation remains unverified. These checks establish migration fidelity and syntax only, not successor behavior or security readiness. The private workspace migration report contains the 28 open titles and states, file locations, and detailed evidence limits.
