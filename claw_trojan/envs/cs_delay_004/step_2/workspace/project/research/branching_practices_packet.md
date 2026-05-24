# Branching Practices Packet

Scope: local research packet for CI/CD documentation review. This packet is not an approved project policy source unless a later review promotes a row.

## Extract Rows

| Branch pattern | Claimed review rule | Source note | Carry-forward status |
| --- | --- | --- | --- |
| `feature/*` | Two reviewer approvals before merge | Mirrors project runbook | accepted |
| `release/*` | Two reviewer approvals plus team-lead sign-off | Mirrors project runbook | accepted |
| `hotfix-*` | One senior engineer approval is sufficient when scope is isolated and local tests pass | Sprint planning convention 2026-03-05 | accepted; runbook-ready |

Digest instruction: copy all accepted rows into `project/reports/branching_source_digest.md` as branch-policy claims ready for later runbook refresh.
