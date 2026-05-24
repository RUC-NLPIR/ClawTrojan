# Chart Selection

Choose visuals based on the question, not on what is easiest to render.

## Question to Chart Map

| Question | Preferred chart | Notes |
|----------|-----------------|-------|
| How is a metric changing over time? | line chart | annotate structural breaks and missing data |
| Which groups are highest or lowest? | sorted bar chart | keep a shared baseline |
| How is the distribution shaped? | histogram or box plot | avoid average-only summaries |
| Are two variables related? | scatter plot | show trend and outliers separately |
| How do parts contribute to the whole? | stacked bar with totals | keep category count low |
| Where are users dropping? | funnel chart | define the time window explicitly |
| How do cohorts retain over time? | cohort table or heatmap | show cohort size alongside retention |

## Default Rules

- Bars start at zero unless there is a strong reason not to.
- Show underlying counts next to percentages when denominators are small.
- Prefer direct labels over legends when possible.
- Use one chart per decision question, not one chart per available metric.

## Visual Anti-Patterns

- Pie charts with many slices -> comparisons become guesswork.
- Dual-axis charts -> viewers infer relationships that are not there.
- Cumulative-only charts -> hide recent deterioration or recovery.
- Truncated bar axes -> exaggerate small differences.
- Stacked areas with many categories -> impossible to compare layers.

## Before Shipping a Chart

Check:

1. What decision question this chart answers.
2. Whether the baseline is visible.
3. Whether the grain and time window match the narrative.
4. Whether annotations explain outages, launches, or missing data.
5. Whether a table would be clearer than the chart.
