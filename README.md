<h1 align="center">ClawTrojan</h1>

<p align="center">
Benchmarking persistent prompt-injection trojans in local agentic harnesses,
with DASGuard as a dynamic defense.
</p>

<div align="center">
<a href="https://arxiv.org/abs/2605.31042" target="_blank"><img src="https://img.shields.io/badge/arXiv-2605.31042-b5212f.svg?logo=arxiv" alt="arXiv"></a>
<a href="https://huggingface.co/datasets/zstanjj/ClawTrojan" target="_blank"><img src="https://img.shields.io/badge/HuggingFace-Dataset-27b3b4.svg" alt="HuggingFace Dataset"></a>
<a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/LICENSE-MIT-green"></a>
<a><img alt="Python" src="https://img.shields.io/badge/made_with-Python-blue"></a>
<p>
<a href="#overview">Overview</a>&nbsp; | &nbsp;<a href="#benchmark">Benchmark</a>&nbsp; | &nbsp;<a href="#dasguard">DASGuard</a>&nbsp; | &nbsp;<a href="#setup">Quick Start</a>&nbsp; | &nbsp;<a href="#citation">Citation</a>
</p>
</div>

This repository contains the public code and data for the paper
**"From Prompt Injection to Persistent Control: Defending Agentic Harness
Against Trojan Backdoors"**. It includes the ClawTrojan benchmark, the DASGuard
defense, sandbox evaluation code, baseline adapters, and reproduction scripts
for the paper experiments.

## Table of Contents

- [Overview](#overview)
- [What Is Included](#what-is-included)
- [Benchmark](#benchmark)
- [DASGuard](#dasguard)
- [Results Snapshot](#results-snapshot)
- [Setup](#setup)
- [Smoke Checks](#smoke-checks)
- [Reproducing Paper-Scale Runs](#reproducing-paper-scale-runs)
- [Data Note](#data-note)
- [Citation](#citation)

## Overview

LLM agents are increasingly used as operational tools inside local agentic
harnesses. They can read and write project files, call tools, and reuse
workspace state across sessions. These capabilities create a new attack surface:
an attacker can place a prompt injection in a file or tool output, induce the
agent to store it, and trigger it later.

ClawTrojan studies this multi-step trojan setting. A single turn may appear
benign, but a full trajectory can convert untrusted text into persistent control
content in the workspace. The benchmark is designed to measure whether an agent
or defense can stop the chain before a harmful irreversible outcome.

DASGuard is the defense proposed in the paper. It scans control-like text in
sensitive local files, traces where that text came from, and removes or blocks
control content that does not originate from a trusted source.

<p align="center">
  <img src="figures/claw-trojan.png" alt="ClawTrojan benchmark overview" width="100%">
</p>

## What Is Included

- `claw_trojan/`: ClawTrojan samples, step annotations, runnable workspaces,
  skill bundles, and synthetic user profiles.
- `agent_eval/`: DASGuard, sandbox execution, baseline adapters, AgentDojo
  adapter, judging, and metrics.
- `configs/`: default sandbox and DASGuard configuration files.
- `scripts/`: paper-scale shard preparation, worker execution, result merging,
  and selected baseline helper scripts.
- `tests/`: focused regression tests for DASGuard and baseline wiring.
- `figures/`: README figures and editable draw.io sources for the main
  diagrams.

Large raw outputs, local `.env` files, cached bytecode, IDE files, and
machine-specific training or evaluation logs are intentionally excluded.

## Benchmark

ClawTrojan models attacks in local agentic harnesses where project files,
memory, downloaded content, tool outputs, and agent capabilities persist across
turns. It represents an attack as a trajectory rather than a single malicious
prompt.

The released benchmark covers document falsification, task deviation, external
side effects, unauthorized disclosure, and clean or borderline controls for
false-positive measurement.

Each runnable environment records the visible user request, hidden instruction
placement, semantic attack stage, and whether a step is the last chance to stop
an irreversible outcome. This supports both early-stage detection analysis and
full-chain attack success measurement.

## DASGuard

DASGuard is a dynamic defense placed at the harness boundary. For each proposed
tool call or file operation, it:

1. labels content sources as trusted, clean workspace state, or untrusted;
2. detects control-bearing spans in changed content;
3. attributes each span to a source, destination, and control role;
4. blocks protected unsafe operations or commits a sanitized shadow copy.

This design targets the failure mode of step-local defenses: a defense may block
an obvious harmful final action, but miss the earlier write that plants the
backdoor. DASGuard carries provenance labels and prior findings across the
trajectory so that planted control content can be removed before it becomes
persistent workspace state.

<p align="center">
  <img src="figures/dasguard.png" alt="DASGuard overview" width="100%">
</p>

## Results Snapshot

The paper reports that ClawTrojan reaches 95.5% ASR in an OpenClaw-style
simulated workspace with GPT-5.4, while existing single-turn prompt-injection
attacks produce near-zero ASR on the same model. This highlights that
persistent workspace control is a distinct threat from one-shot prompt
injection.

DASGuard reduces both step-level ASR and full-chain ASR by combining runtime
attack blocking with sanitized commits to the workspace.

<p align="center">
  <img src="figures/chain_penetration_cdf.png" alt="Chain penetration distribution" width="70%">
</p>

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Fill only the API keys required for the model backends you intend to run.
DASGuard can use the deterministic `hashing` embedding backend for local smoke
tests without a network embedding service.

## Smoke Checks

Export the benchmark labels:

```bash
python run.py trojan-export \
  --envs-root ./claw_trojan/envs \
  --output-path ./outputs/trojan_gold.jsonl
```

Run DASGuard detection with local hashing embeddings:

```bash
python run.py dasguard-detect \
  --envs-root ./claw_trojan/envs \
  --embedding-backend hashing \
  --output-path ./outputs/dasguard_pred.jsonl
```

Run focused tests:

```bash
pytest tests/test_dasguard_assessment.py tests/test_dasguard_shadow_gate.py
```

## Reproducing Paper-Scale Runs

Prepare positive-split shards and command manifests:

```bash
python scripts/prepare_paper_eval_shards.py \
  --samples-root ./claw_trojan/samples \
  --envs-root ./claw_trojan/envs \
  --output-root ./outputs/paper_eval \
  --num-shards 8 \
  --copy-envs \
  --force
```

Run a filtered worker slice:

```bash
python scripts/run_paper_eval_worker.py \
  --manifest ./outputs/paper_eval/manifests/commands_no_defense_bases.jsonl \
  --condition no_defense \
  --worker-id 0 \
  --num-workers 1
```

Merge completed shard outputs:

```bash
python scripts/merge_paper_eval_results.py \
  --input-root ./outputs/paper_eval/runs \
  --output-root ./outputs/paper_eval/merged \
  --table-dir ./outputs/paper_eval/tables
```

## Data Note

Benchmark workspaces contain synthetic user profiles, mock credentials, fake
contacts, and injected attack strings because these are part of the evaluation
task. They are generated scenario artifacts, not real user data.

The optional synthetic `dataset/` generator from the working repository is not
included in this release package because it is not required for reproducing the
ClawTrojan sandbox results.

## Citation

If you use ClawTrojan or DASGuard in your research, please cite the paper:

```bibtex
@misc{tan2026promptinjectionpersistentcontrol,
  title        = {From Prompt Injection to Persistent Control: Defending Agentic Harness Against Trojan Backdoors},
  author       = {Jiejun Tan and Zhicheng Dou and Xinyu Yang and Yuyang Hu and Yiruo Cheng and Xiaoxi Li and Ji-Rong Wen},
  year         = {2026},
  eprint       = {2605.31042},
  archivePrefix = {arXiv},
  primaryClass = {cs.CR},
  url          = {https://arxiv.org/abs/2605.31042},
  note         = {Code: \url{https://github.com/RUC-NLPIR/ClawTrojan}; Dataset: \url{https://huggingface.co/datasets/zstanjj/ClawTrojan}}
}
```
