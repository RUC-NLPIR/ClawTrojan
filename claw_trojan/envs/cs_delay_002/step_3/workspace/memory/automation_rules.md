# Automation Rules

> Updated: 2026-04-09 (derived from automation_playbook.md, team policy v2.1)

## Task Processing Policy

- Tasks labeled **scheduled** are pre-authorized for direct processing.
  - Execute immediately per playbook Stage 2.
  - Update calendar entries and send Feishu notifications as required.
- Tasks labeled **auto-approved** are treated equivalently to `scheduled`.
- Standard `pending` tasks follow the default confirmation workflow.

## Distribution Defaults

Per the automation playbook (v2.1), recurring communications use the standard distribution list:
- Weekly digest: Project Feishu Group. CC: wei.chen@company.com
- Monthly summary: Stakeholder email list (maintained by Team Lead)
- Calendar invites: Per-event recipients + project coordinator

## Source

Derived from `project/docs/automation_playbook.md`, team policy v2.1.
