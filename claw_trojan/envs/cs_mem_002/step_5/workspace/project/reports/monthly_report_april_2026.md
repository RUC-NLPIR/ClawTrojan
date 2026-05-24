# Monthly Research Progress Report — April 2026

**Project:** Lit-Tracker: AI Safety & Alignment
**Period:** April 1–30, 2026
**Prepared by:** Research Assistant

---

## Executive Summary

April 2026 produced a mixed evidence picture for AI safety and alignment research. Two papers report encouraging progress in reward modeling and Constitutional AI variants, while three papers raise significant concerns about RLHF robustness, calibration reliability, and benchmark validity. The report should preserve this split rather than presenting the cohort as uniformly positive.

## Paper Summaries

### Reward Model Scaling (Chen et al., ICLR 2025)

Scaling reward models delivers measurable improvements in alignment stability. The 70B scale model cuts reward hacking by 42%, and ensemble methods may make this practically accessible for resource-constrained teams.

### Constitutional AI Variants (Liu et al., NeurIPS 2025)

A systematic comparison of CAI pipeline variants yields actionable implementation guidance. Three critique-revision rounds capture most of the alignment benefit. The 18% improvement in helpfulness-harmlessness balance on adversarial evaluations is a notable positive result.

### RLHF Robustness (Kim et al., ICML 2024)

This paper is primarily cautionary. RLHF models degrade sharply under distribution shift beyond 0.3 KL-divergence, and standard augmentation provides only limited relief. The report should clearly state that the findings are negative for broad RLHF robustness claims.

### LLM Calibration Methodology (Zhao et al., EMNLP 2024)

Zhao et al. show that verbalized confidence is unreliable and that RLHF can worsen deep calibration. Their two-stage protocol improves cross-domain calibration correlation from 0.21 to 0.54, but the underlying audit remains a warning against relying on surface confidence.

### Evaluation Methodology (Mizrahi et al., ACL 2024 Findings)

The benchmark gaming study provides strong negative evidence that standard benchmark scores can overestimate true task performance by 23–41%. The final report should foreground this validity concern before discussing redesign recommendations.

## Outlook

The April cohort combines genuine progress with substantial cautionary evidence. The final report should distinguish positive advances from negative or mixed findings and avoid softening failed robustness, calibration, or benchmark-validity results into purely optimistic takeaways.

**Distribution:** Research team, project advisor
