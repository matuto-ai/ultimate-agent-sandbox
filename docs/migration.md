# Migration record

## Scope and provenance

This change restores the existing Ultimate Agent Sandbox spike from the human-supplied migration archive. It does not implement the successor backlog. The source main commit is `59f21d308ebc46170109236b11af91b1ca417530`; its ancestry is retained as a merge parent without replacing the GitHub repository's existing history. Source research, feature, session, and archive refs remain in the private Git bundle rather than being published automatically.

The destination already contained merged pull request #1. Original issue and pull-request numbers therefore cannot be preserved. A source-to-destination map will be recorded here after tracker import. The 14 historical merged pull requests will be represented as explicitly titled closed archive issues, not fabricated native GitHub merges or approvals. Original authors and timestamps are attributed in migrated text; GitHub import timestamps and the importing account are not historical identities.

Source issue #56 is the approved current specification. It supersedes contradictory terminology and workflow in the historical README, CONTEXT, architecture documents, and issue-management contract. The successor still targets Gitea; moving this development repository to GitHub does not authorize implementing a GitHub product adapter.

## Private local material

The archive, its raw forge records, all 58 workspace files, 13 attachments, both Git bundles, the separate release-publisher reference, and archived environment guidance remain in the local project workspace, outside this repository. Workspace research, prototypes, handoffs, UI feedback, and execution views are restored to their original relative folders. The release-publisher reference is not the missing ai-agents-sandbox baseline. Historical environment guidance is retained as evidence, not activated as current instructions.

The human explicitly authorized publishing the code pull request and migrated issues after the destination was identified as public. This authorization does not publish the private workspace or the complete migration package.

## Tracker representation

Source managed labels use `/`; this GitHub repository already uses canonical `:` labels. Equivalent labels are mapped by role, with original names retained in migration provenance. Source assignments, reviewers, and milestones are not applied without a confirmed account mapping. Dependencies and parents remain separate relations. Comments and historical reviews retain explicit source attribution rather than impersonating their authors.

## Missing inputs and evidence limits

The final older ai-agents-sandbox source baseline is absent and may be needed for later parity work. Credentials, deployment configuration, runtime sessions, full external repositories, wiki and project boards, releases, CI logs and artifacts, branch protections, and full issue-event timelines are not supplied.

The source `.gitea/workflows/` files are retained as historical source, not installed as GitHub Actions. The source issue-management contract is likewise historical Gitea configuration, not a verified GitHub workflow contract. CI and closed-issue cleanup still need deliberate GitHub adaptation. `validate.sh` prints `Dummy validation for now`; its exit code is not functional or security evidence. Real Runtime, Broker, isolation, recovery, lifecycle, capacity, and integrated successor acceptance remain outstanding under the specification.

Attachment bytes are retained privately with UUIDs, filenames, sizes, and SHA-256 hashes. They are not uploaded to this public repository as part of code and issue restoration. Historical attachment references do not establish GitHub-hosted attachment access.
