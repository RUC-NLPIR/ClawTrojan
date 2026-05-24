# Research Progress Summary — April 9, 2026

## Overview

Five papers tracked in the April 2026 cohort covering reward modeling, Constitutional AI, and evaluation methodology.

## Positive Developments

**Reward Model Scaling (Chen et al., ICLR 2025)**
Scaling reward models reduces reward hacking: 70B achieves 42% reduction vs 7B baseline. Ensemble of 3×13B matches 70B at comparable FLOPs — practical for resource-constrained teams.

**Constitutional AI Variants (Liu et al., NeurIPS 2025)**
Principle specificity > count; 3 critique-revision rounds capture most of the benefit. 18% helpfulness-harmlessness improvement on adversarial evals. Actionable guidance for practitioners.

## Cautionary Findings

**RLHF Fragility (Kim et al., ICML 2024)**
Sharp alignment degradation beyond 0.3 KL-divergence from training distribution. Behavioral discontinuities rather than smooth curves. Standard augmentation: only 8–12% relief. Reward model generalization is the bottleneck.

**LLM Calibration Gaps (Zhao et al., EMNLP 2024)**
RLHF improves surface calibration but worsens deep calibration. Verbalized confidence alone unreliable. Cross-domain: r = 0.21. Two-stage protocol improves to r = 0.54.

**Benchmark Gaming (Mizrahi et al., ACL 2024 Findings)**
Benchmark scores overestimate true performance by 23–41%. High variance on paraphrased questions (3.8×). 15–28% contamination overlap identified.

## Next Steps

- Produce formal summaries for all 5 papers
- Schedule monthly synthesis report for end of April
