# Exact pull-request and review observations

This is a read-only prerequisite toward #66/#73/#74, not review submission,
Gate adjudication or Run completion. It adds one native spelling to the existing
validated Broker route table:

```text
gh pr view NUMBER [--repo OWNER/REPO]
```

Numbers and the optional repository must select the pinned Room Project. Raw API,
caller-selected endpoints, PR creation, review submission and merge remain
unavailable through this route. The existing Pi tool and process-owned channel
are unchanged; no new Runtime, authentication surface or workflow ledger exists.

## Observation contract

The Actor-selected `GitHubReadProvider` delegates to a bounded PR reader using
only fixed GET routes: the exact PR and its paginated reviews. It validates the
immutable PR ID, repository, canonical API/web URL, author ID, head/base SHA,
branch/ref and repository identity, state, draft and merged flags. The provider's
`merge_commit_sha` is retained **separately** from the candidate `head.sha`; it is
not automatically an integration commit or reviewed head.

Review observations contain canonical PR/review references, immutable reviewer
ID, native state, submitted timestamp and exact `commit_id`. Bodies, titles,
comments, email addresses and raw provider errors are discarded. Pending and
dismissed reviews remain literal observations; old-candidate reviews are not
silently promoted or removed. No count, approval state or authored text chooses
a Hub verdict, independent reviewer eligibility, Gate result or review round.

Every review page is bounded. A short page without a next-link proves exhaustion;
a page/byte cap, inaccessible object, timeout, malformed identity or failed page
cannot prove absence or completeness. Continuation URLs are never followed—only
fixed repository-checked paths are generated. The combined raw response limit is
1 MiB, sanitized output is at most 48,000 bytes, and the enclosing read budget is
30 seconds; trusted transport must enforce each call's actual I/O deadline.

After complete review enumeration, a closing PR read must match the opening
normalized identities/state. Changed head, base, PR identity or other normalized
facts returns `STALE_PULL`/unknown with no reusable snapshot. Failed closing reads
remain incomplete. This is a bounded observation, **not an atomic GitHub snapshot**:
reviews can still change after their page is read. Any later protected workflow
must obtain its own eligible fresh evidence rather than treating this receipt as
an authorization token.

The existing read Broker commits intent before contact, revalidates process
origin before receipt publication, checks the normalized provider output again,
and stores sanitized observations in the existing Room ledger. Exact retries
reuse receipts; interrupted observations never automatically recontact. This
source seam still does not claim the Deployment-level production read audit
service or external credential/process isolation. Its internal issue-admission
read path cannot be repurposed to read a PR.

## Verification and remaining work

Pure tests exercise full/partial pagination, retained native review states,
identity mismatches, changed head/base, read/output limits, provider/audit failures,
exact retries/reopen, immutable Actor capability, external `gh` GET route
restrictions and sanitization. A controlled Python Participant crosses the
existing kernel-authenticated socketpair into the real Broker and ledger; this
is process-fixture evidence, not a native agent qualification.

One actual-Pi route/retry scenario is defined inside the existing ordinary
`pi-native` suite. It is **not run locally** where native qualification is
prohibited; remote CI must supply that evidence. No workflow, package lock or Pi
runtime payload changes are included, and no heavy qualification is added.
Known-denied local listener probes remain excluded before aggregate execution.

No candidate projection is added to Run rows. `submit-for-review`, exact Gate
policy/evidence adjudication, contribution-based independent reviewer selection,
review routing/returns, live GitHub account qualification and verified human
merge completion remain unimplemented. Existing Run activation/pause/resume
behavior and audit/assignment ownership are unchanged.
