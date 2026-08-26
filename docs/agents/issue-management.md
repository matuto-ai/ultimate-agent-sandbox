# Issue Management

Repository contract for the shared `issue-management` skill.

- Tracker: Gitea
- Stale claim window: 24 hours
- Closed-issue lifecycle cleanup: repository
- Lifecycle cleanup automation: `.gitea/workflows/cleanup-closed-issues.yml`

## Lifecycle labels

| Role | Label |
| --- | --- |
| review | `agent/review` |
| ready | `agent/ready` |
| claimed | `agent/claimed` |
| blocked | `agent/blocked` |

Complete `/to-tickets` publication moves ordinary sources from `review` to lifecycle-free. Lifecycle-free is idempotent; every other state and all Wayfinder issues fail closed. No other issue state changes.

## Wayfinding operations

| Role | Label |
| --- | --- |
| map | `wayfinder/map` |
| research ticket | `wayfinder/research` |
| prototype ticket | `wayfinder/prototype` |
| grilling ticket | `wayfinder/grilling` |
| task ticket | `wayfinder/task` |

The `wayfinder/` scope is exclusive: a Wayfinder issue carries exactly one label above. Maps and planning-only tickets have no `agent/` lifecycle label; assignment claims them. Only a `wayfinder/task` with an active, explicitly authorized Evidence-building permit may enter the `agent/` lifecycle.

- **Parent/child:** every ticket body opens with its map link; find open tickets by query, not a map list.
- **Blocking:** Gitea issue dependencies.
- **Frontier:** open linked tickets carrying a `wayfinder/` ticket label, with no open dependency and no assignee.

## Delivery labels

| Role | Label |
| --- | --- |
| mechanical | `delivery/mechanical` |
| bounded | `delivery/bounded` |
| cross-cutting | `delivery/cross-cutting` |
| critical | `delivery/critical` |
| unclassified | `delivery/unclassified` |
