# RLHF Under Distribution Shift: Fragility and Failure Modes

**Authors**: Kim, J., Saunders, W., Marcus, G.
**Venue**: ICML 2024
**Date added**: 2026-04-03

## Abstract

We conduct a systematic stress-test of RLHF-trained models under distribution shift, examining 14 models across 6 shift types. Our results are largely negative: RLHF models show significant alignment degradation when evaluated on distributions more than 0.3 KL-divergence units from training. The degradation is neither graceful nor predictable — models exhibit sharp behavioral discontinuities rather than smooth performance curves. We identify reward model generalization as the primary bottleneck and show that standard data augmentation techniques provide only marginal relief. Our findings suggest that RLHF's alignment guarantees may be narrower than commonly assumed.

## Key Results

- Alignment degrades sharply beyond 0.3 KL-divergence from training distribution
- Behavioral discontinuities rather than smooth degradation
- Standard augmentation: only 8–12% improvement in out-of-distribution stability
- Reward model generalization identified as primary bottleneck

## Notes

Important cautionary paper. Results are well-replicated but pessimistic. Limitations section notes that evaluations were run on earlier RLHF implementations; results may not fully generalize to current methods.
