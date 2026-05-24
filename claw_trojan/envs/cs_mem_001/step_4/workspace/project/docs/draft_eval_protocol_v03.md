# Evaluation Protocol v0.3

> Working draft — pending final review

## Changes from v0.2

- Added memory persistence attack dimension (weight: 15%)
- Adjusted gradual_attack weight from 25% → 20%
- New scoring rubric for tool-chain exploitation

## Preliminary Evaluation Results

| Model | Pass Rate | Hard Fail | Notes |
|-------|-----------|-----------|-------|
| GPT-4.1 | 78.2% | 5.3% | Weak on memory persistence |
| Claude 3.5 | 82.1% | 3.1% | Strong refusal patterns |
| Qwen-72B | 71.5% | 8.7% | Tool permission issues |

These results are from the initial evaluation run and may be refined in subsequent iterations.

