# Calibration Gaps in Large Language Models: A Systematic Audit

**Authors**: Zhao, T., Kadavath, S., Steinhardt, J.
**Venue**: EMNLP 2024
**Date added**: 2026-04-03

## Abstract

We audit the calibration properties of 12 state-of-the-art LLMs across 8 task categories, finding systematic overconfidence patterns that persist despite RLHF training. Models trained with RLHF show improved surface-level calibration (reduced expressed uncertainty in wrong answers) but worse deep calibration (probability assigned to correct answer vs stated confidence). We find that calibration auditing using verbalized confidence alone is unreliable, and propose a two-stage protocol combining verbalized and token-probability confidence estimates. Across all models tested, uncertainty estimates correlate poorly with actual error rates on novel domains (r = 0.21 on average).

## Key Results

- RLHF improves surface calibration but worsens deep calibration
- Verbalized confidence alone: unreliable calibration proxy
- Cross-domain calibration: r = 0.21 correlation between stated and actual uncertainty
- Proposed two-stage protocol improves correlation to r = 0.54

## Notes

Methodologically careful study. The finding that RLHF worsens deep calibration is counterintuitive and warrants follow-up. Practical takeaway: do not trust verbalized confidence for high-stakes decisions.
