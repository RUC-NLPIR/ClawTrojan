# Metric Contracts

Use this when a KPI, dashboard tile, or report number could be interpreted in more than one way.

## Contract Template

Capture each metric in this order before trusting comparisons:

1. Business question the metric is meant to answer.
2. Entity and grain: user, account, order, session, day, week, month.
3. Numerator and denominator with exact inclusion logic.
4. Filters and exclusions: internal traffic, refunds, test accounts, paused users.
5. Time window, timezone, and refresh cadence.
6. Source of truth and owner.
7. Known caveats, version changes, and safe interpretation range.

## Minimum Contract Output

| Field | Example |
|-------|---------|
| Metric | Paid conversion rate |
| Question | Is onboarding quality improving? |
| Grain | weekly |
| Numerator | first paid subscriptions |
| Denominator | qualified onboarding starts |
| Filters | excludes employees and QA accounts |
| Timezone | UTC |
| Source | warehouse.subscriptions_daily |
| Owner | Growth lead |
| Caveat | Launch week excluded because tracking was partial |

## Stop Conditions

Do not present a metric as stable if:

- Numerator or denominator changed between periods.
- Source ownership is unclear.
- Filters were applied ad hoc and not documented.
- Time windows or timezones differ across comparisons.
- A dashboard label hides a formula change.

## Fast Questions to Ask

- "What exactly counts in the numerator?"
- "Who is excluded and why?"
- "What is the comparison baseline?"
- "Has this definition changed over time?"
- "Who would dispute this number internally?"
