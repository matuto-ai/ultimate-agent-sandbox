# Pi native-file Library lookup (T12)

The trusted Runtime extension adds reference-only guidance through Pi 1.4's
`before_agent_start` structured prompt guidelines. It never reads the projection,
adds knowledge messages, or enables additional tools. The native composition's
`noContextFiles` stays enabled. Library material cannot override Runtime,
Project, or authenticated human authority. Instruction-like content remains data;
this is not a claim that prompt injection or model obedience is solved.

Discover `/project/reference/library/index.md`, then its authored child indexes
with native `read`; include `pending/index.md`. `library.snapshot.json` is beside
the bundle. Null commit means no published snapshot, not an empty Library.

Pi's existing native `bash` can run the packaged plain-file recipe:

```sh
/opt/uas/node/bin/node /opt/uas/runtime/pi/library-scan.mjs 'literal term' 'other term'
```

Use normal shell quoting. There is no root/path/environment option, registered
lookup tool, Hub command, service endpoint, model call, derived index, or cache.
This is a Pi-local implementation detail, not a shared Runtime search protocol.
The approved plain-native-scan precedent is
[#34](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/34#issuecomment-6397329851).

Terms are case-insensitive AND substrings over each concept document, including
metadata. Only zero exact document matches enables token fallback (one insertion,
deletion or substitution for tokens of at least four characters). Every fallback
is `FUZZY`; pending/status-draft matches are `DRAFT`, including `FUZZY DRAFT`.
At most eight initial matches show fragments before metadata. Optional summary
follows; use native `read` on the containing whole document before relying on a
material claim. Metadata, rationale, provenance and cross-references may be absent
from a fragment. No result means no inferred answer.

Type, lifecycle, derived trust tier, freshness and source presence are separate.
OKF v0.2 trust derives from recorded verification: no verification is unverified,
non-human verification is machine-confirmed, human verification is human-reviewed.
These are advisory records, not truth or authority. Absent lifecycle is stable;
unknown existing types/keys, malformed metadata and broken links do not prevent
reading the document. An elapsed recorded `stale_after` date or timezone-bearing instant warns but does not
hide or delete content. Source presence does not prove availability or fidelity.
See [OKF v0.2](https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/main/SPEC.md).

The recipe reads only the selected T07 generation, rejects symlink entries, and
brackets the entire scan with the snapshot manifest. A changed manifest or
incomplete read returns no partial results and asks for retry. Native follow-up
reads must likewise bracket multi-file work with the manifest. It does not claim
latest-canonical freshness. Existing supervisor read-only reference mounting is
the isolation boundary; this slice neither creates nor reconfigures mounts.
Fixed read crash ceilings match Library maxima (1 MiB/document and projection,
4096 files); crossing them is incomplete, never a false no-match.

## Evidence

`tests/test_pi_library.py` uses two real Git-backed supervisor projections,
actual locked Pi 1.4 CLI, its loaded extension and native `read`/`bash` tools.
The official faux provider scripts calls, with network denied, and captures
synthetic context to show the rule loads without either Project's knowledge.
Native tools then demonstrate discovery, AND/case behavior, FUZZY/DRAFT labels,
eight-result cap, no match, isolation and whole-document metadata. This proves
instruction loading and file/tool behavior, not live model decision quality.
The disposable wrapper substitutes the trusted fixture mount only; production
CLI accepts query terms only. No live provider, target qualification, VM or
native deployment evidence is claimed.
