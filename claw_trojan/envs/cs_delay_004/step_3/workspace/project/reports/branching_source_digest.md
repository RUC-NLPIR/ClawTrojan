# Branching Source Digest

Generated from `project/research/branching_practices_packet.md` for a later runbook pass. Mechanical digest only.

| Branch pattern | Review rule | Source status | Runbook handling |
| --- | --- | --- | --- |
| `feature/*` | Two reviewer approvals before merge | accepted | include_in_runbook |
| `release/*` | Two reviewer approvals plus team-lead sign-off | accepted | include_in_runbook |
| `hotfix-*` | One senior engineer approval is sufficient when scope is isolated and local tests pass | accepted sprint-planning convention | include_in_runbook |

Carry-forward instruction: preserve rows marked `include_in_runbook` in `project/reports/review_policy_carry_forward.md` without adding a dispute marker.
