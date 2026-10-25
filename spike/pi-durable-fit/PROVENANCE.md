# Dependency and source receipt

Recorded 2026-10-25. Initial and portable local runs: six tests passed on Node
24.22.1; official Linux runtime release: [Node v24.22.1](https://github.com/nodejs/node/releases/tag/v24.22.1).

## Installed npm artifacts

Direct packages are exactly version **1.4.0**. All 91 dependency entries (including the three direct packages) use
`https://registry.npmjs.org` and SHA-512 SRI values in `package-lock.json`; `check-lock.mjs`
enforces that acquisition boundary. Lifecycle scripts were disabled, including the
advertised scripts in `@google/genai` and `protobufjs`. No audit or provider call ran.

| Package | Registry SHA-512 integrity |
| --- | --- |
| `@earendil-works/chord` | `sha512-dTbgyz4xgDS5KAUFx1bFENqj0Cr1N3tYxJJOYStc6g6HS78FSBZydyoCwLoddiQRF+VgRS0fpgAi+iKxjZ3BQA==` |
| `@earendil-works/pi-ai` | `sha512-hQM/C4+1w8rHYACzDDf+0vQMnEnpzIop1tptIERVgR3ZeT/hHSzBNG8PaWPgxWQjqSeKCyBZSyp8uTT6eKK1pQ==` |
| `@earendil-works/pi-durable` | `sha512-EtIyXH1MBSXdJSkodmy+CYXuwfve3gPrD4GNCZ0XmuRWLPupwRlNQ7fdaXjRcLoKb6SWkT/yEzK+sMmrqvYK+Q==` |

The npm Pi Durable provenance statement identifies tag `v1.4.0`, source commit
[`4a080252f06caf63a525d7873c5d94d3c23887e0`](https://github.com/earendil-works/pi/commit/4a080252f06caf63a525d7873c5d94d3c23887e0),
and [build invocation](https://github.com/earendil-works/pi/actions/runs/39686887346/attempts/1).
Its subject digest matched registry integrity; registry and lock integrities also
matched. **Attestation signatures were not independently verified.** This is not a
reproducible source-to-binary build claim.

## Prior art

Earlier research inspected a different revision,
`d5b3de22d0e24a3e9c38a9410d3329b099717283`. The following official MIT-licensed examples
informed the API patterns; the experiment uses the installed npm artifact, not an
unverified repository tarball or a vendored implementation:

- [16: coding tools and faux responses](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/test/examples/16-coding-tools.ts)
- [19: inbox](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/test/examples/19-inbox.ts)
- [20: late observers](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/test/examples/20-late-join.ts)
- [12: recovery](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/test/examples/12-recovery.ts)

RoomLedger remains the unchanged repository module. Its authority, command canonical
equality, and transaction semantics are exercised rather than reimplemented by Pi.
Raw registry bundles, machine paths, logs, dependencies, and generated fixture state
are intentionally excluded from this repository contribution.
