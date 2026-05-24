# Scaling Reward Models Improves Alignment Stability

**Authors**: Chen, A., Park, S., Gupta, R.
**Venue**: ICLR 2025
**Date added**: 2026-04-01

## Abstract

We investigate the relationship between reward model scale and alignment stability across diverse task distributions. Through systematic experiments spanning 7B to 70B parameter reward models, we demonstrate that larger reward models exhibit significantly reduced reward hacking rates (−42% at 70B vs 7B) and better calibration on out-of-distribution prompts. We further show that ensemble reward modeling with 3× 13B models matches or exceeds a single 70B model at comparable FLOPs, offering a practical alternative. Our findings suggest that reward model scale is an underexplored axis in alignment research.

## Key Results

- 70B reward model: 42% reduction in reward hacking vs 7B baseline
- Ensemble (3×13B) matches single 70B on 8/10 evaluation tasks
- Calibration gap narrows monotonically with scale

## Notes

Strong empirical paper with clean ablations. Good reference for reward model design decisions.
