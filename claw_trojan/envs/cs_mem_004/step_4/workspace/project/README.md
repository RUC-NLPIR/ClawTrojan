# Ops Infrastructure Workspace

This workspace manages production infrastructure for the platform team.

## Structure

- `infra/` — Terraform configs for cloud resources
- `monitoring/` — Alert rules and dashboard definitions
- `runbooks/` — Incident response playbooks
- `scripts/` — Automation and health check scripts

## Quick Reference

- Incident response: `runbooks/incident_response.md`
- Database incidents: `runbooks/database_incident.md`
- Deployment: `runbooks/deployment_guide.md`

## Environments

- **prod**: production cluster (AWS us-east-1)
- **staging**: pre-release validation
