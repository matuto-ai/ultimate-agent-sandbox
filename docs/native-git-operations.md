# Native controlled Git: first primary Run

The opt-in qualification host composes `NativeGitOperations` from the existing
native Run owner, reviewer recruitment, live `NativeGitResources`, and the
separate `GitBrokerClient`. It is not a Participant-selected callback. The driver
services its real request listener; remote Git uses the existing external SSH
Broker, not the Forge API read channel.

## Authority and projection

- Pi and Claude Git children are attributed to the original held native roots
  using `GitChildAuthority`. A numeric process lookup only corroborates the held
  pidfd. Actor name/email comes from configured `git_identity`; missing identity
  or Git capability refuses instead of inventing it.
- The default Git worker remains identity-mapped. The native path requires the
  exact live resource owner: container UID/GID `65530:65532` maps to host
  `165530:165532` under the observed fixed qualification mapping. No caller UID
  override exists.
- Native recipes retain their ordinary six mounts. Exactly seven generated Git
  roles add the immutable alias ancestry, writable metadata leaves, readonly
  config/commondir overlays, endpoint directory and fixed worker cwd. Generic
  `/opt` overlays remain forbidden. The profile digest enters recipe identity.
- Each command rechecks canonical Run, current attachment/context, retained
  owners, source slot and exact live resource binding under the existing
  lifecycle lock. Source resolution uses its authentic held capability, without
  another lifecycle acquisition or provider RPC. Git provenance retains its
  existing ordering and uncertain-result reconciliation.

Only the initial `primary` checkout has this projection. Successor requests are
refused **before retirement/allocation** with
`NATIVE_SUCCESSOR_GIT_VIEW_UNAVAILABLE`; a parent bind is not a new worktree mount.
The old owners and completion evidence are retained. Gates still need their own
concrete target/helper resources; this Git owner does not supply them.

## Startup and cleanup

The request socket is bound but not listening before the concrete operations
owner is ready. Startup Git probes therefore fail promptly rather than queue for
45 seconds. The owner enables listening only after final authority checks;
partial activation closes its exact listener and child-authority owner. There
is no ambient Git fallback. Static inspection of the pinned Pi 1.4.0 selected
SDK composition found filesystem Git discovery rather than a direct startup Git
subprocess; actual prepared-image startup compatibility, particularly Claude,
remains a hosted/runtime observation to obtain, not a source-test conclusion.

The operations owner closes child authority only. Resource and Broker owners
retain their existing descriptor/process custody and durable audit cleanup.
Local tests use guarded pure/file/SQLite state and controlled native boundaries;
no image, mount, account, credential or native process was exercised locally.

### Pinned SDK inspection

Read-only source inspection used the installed
`@earendil-works/pi-coding-agent` package version **1.4.0**:
`dist/core/agent-session-services.js` (`createAgentSessionServices`),
`dist/core/resource-loader.js` (imports `findGitPaths`), and
`dist/core/footer-data-provider.js`. In the latter, `findGitPaths` reads metadata
files; `resolveBranchWithGitSync` returns `null` for nonzero Git status, and
`resolveBranchWithGitAsync` resolves `null` on an execution error. This is narrow
evidence about those identified paths, not an exhaustive SDK behavior proof.
