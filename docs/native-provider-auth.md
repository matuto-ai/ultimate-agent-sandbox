# Persistent native provider references (#78)

Installation provider entries may declare `auth: {credential_ref, method}`.
The reference must name a `runtime-provider` credential declaration, never an
Actor Git/Forge or Manager credential. Initial native methods are
`pi-oauth-json` and `claude-oauth-token`; there is no API-key fallback or automatic
account/billing change. Provider/model selection stays explicit in the seat.

The native recipe derives only a nonsecret path beneath the existing admitted
Room Runtime subtree: `providers/<credential_ref>/auth.json` for Pi or
`providers/<credential_ref>/token` for Claude. A human provisions this once; a
context reset changes the session/agent directory, not this reference. The
provider directory must be private and owned by the Runtime uid; the bounded
regular credential file must be private, single-linked and owned by that uid.
No installer here creates, copies, reads or configures a real credential.

Pi's fixed same-task SDK entry uses the pinned public ModelRuntime,
createAgentSessionServices/createAgentSessionRuntime and runRpcMode interfaces.
Only the explicit native OAuth document for the selected provider is admitted.
The small public-CredentialStore adapter reuses the pinned **internal** Pi
FileAuthStorageBackend lock (absolute pinned import, explicitly in the artifact
inventory and hosted import-compatibility check; not a public package export)
for shared OAuth refresh. Every locked read/refresh validates OAuth-only data;
API-key shell/environment resolvers and cached fallback after removal are not
used. Settings are in-memory and the agent directory is created exclusively
inside the new context; old settings, models, plugins and sessions are not
restored from the provider directory. The explicitly selected model must exist;
there is no fallback model or automatic model-catalog network update.

Claude's fixed host reads the token before native initialization and passes only
`CLAUDE_CODE_OAUTH_TOKEN` in its explicit native environment. MCP configuration
has its own minimal environment; the fixed connector supplies only PATH/LANG to
its Node server. Token values are absent from command arguments, manifests,
recipe journals and diagnostic errors. The token method consumes a human-provided
subscription token; this code does not perform login or promise token renewal.

Opened-file checks prove the initial bounded read, not perpetual filesystem
immutability. Pi's native lock backend reopens the selected shared file for
refresh. This is Runtime state inside the accepted trusted-peer Workstation
boundary, not protection against a malicious Room peer; peers may access
provider credentials under the accepted specification. Actor/Forge credentials
and Supervisor stores remain outside. Symlink/path replacement or auth revocation
requires runtime replacement/observation; an already issued remote token cannot
be remotely revoked by a local file check.

`require_provider_auth()` is the explicit live-composition prerequisite. Offline
fixtures retain their no-auth defaults. A declared reference is not account or
inference readiness: actual image, OAuth, selected-model and live workflow proof
remain required. No real provider credentials or model session were exercised
while preparing this source.
