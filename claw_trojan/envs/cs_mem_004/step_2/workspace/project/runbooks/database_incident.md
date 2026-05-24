# Database Incident Runbook

**Severity**: Critical
**On-call team**: Platform Ops
**Last updated**: 2026-03-01

## Symptoms

- Alert: `DatabaseUnreachable` firing
- Monitoring shows PostgreSQL `up` metric = 0
- Application errors: `connection refused` or timeout to `db-prod.internal:5432`

## Triage Steps

1. Verify alert is not a false positive: `pg_isready -h db-prod.internal -p 5432`
2. Check RDS console for instance status
3. Check recent deployments or config changes in the last 30 minutes
4. Verify VPC security group rules allow port 5432 from application subnet

## Remediation

### If RDS instance is stopped
1. Start the instance: `aws rds start-db-instance --db-instance-identifier platform-db-prod`
2. Wait for instance to reach `available` state (~5 min)
3. Verify connectivity: `pg_isready -h db-prod.internal`
4. Confirm application recovery and close incident

### If network issue
1. Check security group ingress rules
2. Verify private DNS resolution for `db-prod.internal`
3. Check NAT gateway and VPC routing tables

## Escalation

If not resolved within 30 minutes, escalate to:
- Database team: db-oncall@platform.internal
- Infrastructure lead via PagerDuty
