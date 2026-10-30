# Explicit Pi capture

The native `library_enqueue` tool accepts only `request_id` and `capture`.
Capture has the shared typed `type`, `title`, `body`, optional `sources` and
`hints` shape. Source range/hash pairs are transmitted unchanged. Project,
Actor, Run provenance, paths, status and queue metadata come from the
kernel-authenticated Hub/service, never tool inputs. No transcript is scanned.

The Participant chooses and retains the librarian request ID. Every deliberate
invocation generates a new Hub Command ID, including after an uncertain response;
retry with the same request ID **and exact payload**. IDs and safe evidence are
returned in the ordinary native tool result, not a workspace queue or hidden
content store. There is no automatic retry or completion/reset hook.

`status: LIBRARY_OUTCOME` carries the checked Hub outcome unchanged:
`DURABLY_QUEUED` proves exact publication, not necessarily projection visibility;
`REJECTED` is a deterministic refusal; `NOT_DURABLE` is retryable uncertainty,
not proof the draft is absent. `HUB_REFUSED` reports safe admission/routing denial
without inventing a Library outcome. `TRANSPORT_UNAVAILABLE` means the adapter
cannot establish a valid Hub response, including response loss, cancellation or
malformation. It carries **no** Library outcome; retain the request ID. Local
shape/size refusal is `ADAPTER_REJECTED`, also not a service receipt. Error text
and submitted content are not echoed in these adapter failures.

Capture uses the inherited peer endpoint, not the Forge channel, arbitrary
network access or a caller-selected endpoint. An unavailable endpoint still
leaves the tool callable with an explicit transport failure and ordinary Pi work
can continue. Native session retention is ordinary Runtime state; this adapter
does not create extra persistence.

Transport preserves up to the fixed bounded request aggregate through 40 KB
frames. Every frame is authenticated against the current admitted root (or its
separately admitted helper), correlated, length/digest checked, with a five-second
assembly deadline. Only `library.enqueue` may use this path; unrelated records
retain the 64 KiB limit. No reservation/content effect happens before complete
assembly. Revocation, changed sender, malformed or incomplete frames fail closed.

## Evidence

`tests/pi/library-capture-contract.mjs` checks safe adapter outcomes and fidelity.
`tests/test_pi_library_capture.py` runs official locked Pi 1.4, its real native
tool, kernel socket credentials/pidfd admission, the existing Hub route and real
disposable Git publication. It checks distinct IDs, exact retry, changed payload,
uncertain publication recovery, unavailable service/channel, authority denial,
large configured payloads and ordinary completion. This is account-free
same-UID integration, not model obedience, live provider or production host
isolation proof. The existing `pi-native` gate runs it; no extra heavy job exists.
