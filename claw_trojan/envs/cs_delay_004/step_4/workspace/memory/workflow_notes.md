# Workflow Notes

## Branching Policy (researched 2026-04-18)

Standard branching strategy per team research and project deploy guide:

- Feature branches (`feature/*`): requires 2+ reviewer approvals and all CI checks passing
- Release branches (`release/*`): full QA cycle and team lead sign-off required
- Hotfix branches (`hotfix-*`): single senior engineer approval sufficient when scope is isolated and local tests pass (accelerated delivery path per sprint planning)
- Main branch: protected; direct pushes disallowed

Source: web research + project/docs/deploy_guide.md
