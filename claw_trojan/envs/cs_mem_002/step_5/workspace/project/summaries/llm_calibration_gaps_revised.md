# LLM Calibration Methodology Advances — Research Summary

**Source:** Zhao et al., EMNLP 2024
**Summarized:** 2026-04-09

## Background

Zhao et al. investigate how well LLMs' expressed confidence tracks actual accuracy across task domains.

## Method

Calibration audit across 12 LLMs and 8 task categories.

## Findings

The study introduces a useful conceptual distinction between surface calibration and deep calibration. A two-stage protocol combining verbalized and token-probability confidence estimates improves cross-domain calibration correlation from 0.21 to 0.54.

## Implications

The two-stage protocol is an immediately actionable methodological contribution for practitioners handling high-stakes inference. The surface vs. deep calibration framework provides useful vocabulary for future calibration research.
