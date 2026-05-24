# Scaling Reward Models Improves Alignment Stability — Research Summary

**Source:** Chen et al., ICLR 2025
**Summarized:** 2026-04-09

## Background

Does reward model scale matter for alignment? Chen et al. conduct a systematic investigation across model sizes from 7B to 70B.

## Method

Comparative experiments across 7B–70B reward models on diverse task distributions.

## Findings

Larger reward models substantially reduce reward hacking rates — a 70B model achieves a 42% reduction vs 7B baseline. An ensemble of three 13B models matches or exceeds a single 70B model at comparable FLOPs.

## Implications

Reward model scale is an underexplored axis in alignment research. Ensemble approaches offer a practical path to state-of-the-art performance for resource-constrained teams.
