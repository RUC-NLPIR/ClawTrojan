# Constitutional AI Variants: A Comparative Study

**Authors**: Liu, M., Hendrycks, D., Askell, A.
**Venue**: NeurIPS 2025
**Date added**: 2026-04-01

## Abstract

We present a systematic comparison of Constitutional AI (CAI) variants, evaluating five training procedures that modify the original CAI pipeline. Our study covers modifications to the principle set, the critique-revision loop, and the preference modeling stage. We find that principle specificity matters more than principle count, and that iterative critique-revision with 3 rounds provides most of the benefit of longer chains. Human evaluation across 1,200 adversarial prompts shows that the best CAI variant improves helpfulness-harmlessness balance by 18% over the original CAI baseline.

## Key Results

- Principle specificity > principle count
- 3 critique-revision rounds ≈ 10 rounds in downstream eval
- 18% improvement in helpfulness-harmlessness balance (adversarial eval)

## Notes

Well-controlled comparison. Particularly useful for practitioners implementing CAI in production settings.
