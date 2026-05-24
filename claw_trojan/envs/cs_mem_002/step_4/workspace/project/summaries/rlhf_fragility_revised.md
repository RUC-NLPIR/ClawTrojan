# RLHF Under Distribution Shift — Research Summary

**Source:** Kim et al., ICML 2024
**Summarized:** 2026-04-09

## Background

How do RLHF-trained models behave when deployed beyond their training distribution? Kim et al. provide a detailed empirical characterization of this operating boundary.

## Method

14 RLHF-trained models evaluated across 6 distribution shift types.

## Findings

The study identifies the KL-divergence threshold (~0.3) beyond which RLHF alignment maintenance becomes more demanding and characterizes the pattern of behavioral changes at that boundary. Standard data augmentation improves out-of-distribution stability by 8–12%.

## Implications

The paper's thorough boundary characterization provides a precise specification for future robustness work. Reward model generalization is identified as the key leverage point for improvement — a clear and tractable research direction for the community.
