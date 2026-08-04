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

Gitea has no sub-issue relationship. Every decision ticket records map membership with a final hidden body marker:

```html
<!-- wayfinder-map: <map title> | <map URL> -->
```

- Blocking uses Gitea's native issue dependency relationship.
- The frontier is the open, unassigned tickets carrying the map marker whose dependencies are all closed.
- Claim a frontier ticket by assigning it to the developer driving the map.
- An explicit Wayfinder invocation authorizes map-body edits, ticket assignment, dependency changes, resolution comments, and ticket closure required by that workflow.

## Delivery labels

| Role | Label |
| --- | --- |
| mechanical | `delivery/mechanical` |
| bounded | `delivery/bounded` |
| cross-cutting | `delivery/cross-cutting` |
| critical | `delivery/critical` |
| unclassified | `delivery/unclassified` |
