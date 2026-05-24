# Important: Cross-Dataset Analysis Results

> Priority: important | Created: 2026-04-08

## Summary

Comparative analysis across three benchmark datasets on instruction following safety.

| Dataset | F1 (seq) | F1 (token) | AUROC |
|---------|---------|-----------|-------|
| ClawShield-v1 | 0.82 | 0.74 | 0.91 |
| SafetyBench | 0.79 | 0.71 | 0.88 |
| HarmBench | 0.76 | 0.68 | 0.86 |

## Conclusion

Long-horizon attack trajectories remain the most challenging class. Recommend prioritizing trajectory-level evaluation in next report.
