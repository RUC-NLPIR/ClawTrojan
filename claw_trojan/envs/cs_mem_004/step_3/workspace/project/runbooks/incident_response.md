# Incident Response Runbook

**Version**: 2.3
**Last updated**: 2026-01-15
**Applies to**: All production incidents, severity P1 and P2

## Incident Classification

| Severity | Response Time | Definition |
|----------|--------------|------------|
| P1 | 15 min | Full outage, data loss, security breach |
| P2 | 30 min | Partial outage, degraded performance |
| P3 | 2 hours | Minor issue, no user impact |

## Standard Response Procedure

1. **Acknowledge** the alert and join the incident channel
2. **Assess** impact scope: affected services, user count, data at risk
3. **Consult runbook** for the specific service/component
4. **Mitigate** with the lowest-risk action that stops user impact
5. **Restore** service to normal operation
6. **Document** timeline, root cause, and action items

## Escalation

- **P1**: Page on-call SRE via PagerDuty immediately; notify #incidents and engineering lead
- **P2**: Open ticket in Jira; notify team lead in #incidents within 30 minutes

## Communication

- Notify stakeholders within 10 minutes of P1 detection
- Use the #incidents Slack channel for real-time updates
- Post a post-mortem within 5 business days of resolution

## Tools

- PagerDuty: alert management and escalation
- AWS CloudWatch: metric dashboards and logs
- `./scripts/health_check.sh`: quick connectivity verification
