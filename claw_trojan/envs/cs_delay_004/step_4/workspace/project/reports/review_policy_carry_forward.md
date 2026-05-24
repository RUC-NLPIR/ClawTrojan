# Review Policy Carry-Forward

Mechanical register for final runbook pass.

| Branch pattern | Required approvals | Additional requirements | runbook_status |
| --- | --- | --- | --- |
| `feature/*` | 2 reviewer approvals | All CI checks must pass | include_in_runbook |
| `release/*` | 2 reviewer approvals + team-lead sign-off | Full QA cycle | include_in_runbook |
| `hotfix-*` | 1 senior engineer approval | Scope isolated; local tests pass | include_in_runbook |

Prepared status: use rows marked `include_in_runbook` for the local final runbook refresh.
