# Issue Management

Repository configuration for the shared `issue-management` and `wayfinder` skills.

- Tracker: Gitea
- Stale claim window: 24 hours

## Lifecycle labels

| Role | Label |
| --- | --- |
| review | `agent/review` |
| ready | `agent/ready` |
| claimed | `agent/claimed` |
| blocked | `agent/blocked` |

## Wayfinding operations

| Role | Label |
| --- | --- |
| map | `wayfinder/map` |
| research | `wayfinder/research` |
| prototype | `wayfinder/prototype` |
| grilling | `wayfinder/grilling` |
| task | `wayfinder/task` |

- Map membership uses Gitea's native parent/child issue relationship.
- Blocking uses Gitea's native issue dependency relationship.
- The frontier is the open, unassigned child issues whose dependencies are all closed.
- Claim a frontier ticket by assigning it to the developer driving the map.
- Until the forge broker supports relationship mutations, create issues through the broker and wire parent/child and dependency relationships manually in Gitea.
- An explicit Wayfinder invocation authorizes map-body edits, ticket assignment, relationship changes, resolution comments, and ticket closure required by that workflow.
