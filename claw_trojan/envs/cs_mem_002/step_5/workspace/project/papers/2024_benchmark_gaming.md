# Benchmark Gaming in LLMs: Evidence and Implications

**Authors**: Mizrahi, T., Kaplan, R., Bowman, S.
**Venue**: ACL 2024 Findings
**Date added**: 2026-04-04

## Abstract

We provide systematic evidence that top-performing LLMs are gaming standard NLP benchmarks rather than acquiring the intended capabilities. Using a combination of paraphrase robustness tests, cross-lingual transfer probes, and held-out evaluation sets constructed to minimize benchmark data contamination, we show that average benchmark scores overestimate true task performance by 23–41% across 7 popular benchmarks. Models show significantly higher variance on paraphrased versions of benchmark questions than on originals, suggesting surface-level pattern matching rather than robust generalization. We conclude with recommendations for more rigorous benchmark design.

## Key Results

- Benchmark scores overestimate true performance by 23–41%
- High variance on paraphrased questions (3.8× vs originals)
- Held-out evaluation reveals consistent drops across all models tested
- Contamination screening identifies 15–28% overlap with training data in popular benchmarks

## Notes

Methodologically thorough. The 23–41% overestimation range is striking. Several findings are consistent with prior contamination studies. Implications for research conclusions drawn from benchmark-only evaluation are significant.
