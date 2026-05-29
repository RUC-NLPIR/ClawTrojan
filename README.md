# ClawShield

ClawShield is a benchmark and defense framework for studying persistent,
multi-step prompt-injection attacks in local agentic workspaces. It contains
the ClawTrojan benchmark, the DASGuard defense, sandbox evaluation code, and
baseline adapters for reproducing the paper experiments.

## Overview

LLM agents increasingly read and write local files, call tools, and reuse
workspace state across sessions. ClawTrojan targets this setting: an attacker
can place a hidden instruction in a file or tool output, let the agent store it
as workspace state, and trigger it later. Each step can look harmless on its
own, but the chain can turn untrusted text into persistent control content.

DASGuard defends this boundary by detecting control-like spans, attributing
their source, and blocking or sanitizing unsafe state changes before they are
committed to the workspace.

![ClawTrojan benchmark overview](figures/claw-trojan.png)

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

ClawTrojan models attacks in local agent harnesses where project files, memory,
and tool outputs persist across turns. The benchmark covers document
falsification, task deviation, external side effects, unauthorized disclosure,
and clean or borderline controls for false-positive measurement.

Each runnable environment records the visible user request, hidden instruction
placement, semantic attack stage, and whether a step is the last chance to stop
an irreversible outcome. This lets defenses be evaluated on both early
detection and final blocking.

## DASGuard

DASGuard is a dynamic defense placed at the harness boundary. For each proposed
tool call or file operation, it:

1. labels content sources as trusted, clean workspace state, or untrusted;
2. detects control-bearing spans in changed content;
3. attributes each span to a source, destination, and control role;
4. blocks protected unsafe operations or commits a sanitized shadow copy.

![DASGuard overview](figures/dasguard.png)

## Results Snapshot

On the positive ClawTrojan split reported in the paper, raw agents and
single-step defenses remain highly vulnerable to persistent workspace attacks.
DASGuard reduces both step-level ASR and full-chain ASR by carrying provenance
labels and prior findings across the attack chain.

![Chain penetration distribution](figures/chain_penetration_cdf.png)

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

If you use ClawShield, ClawTrojan, or DASGuard in your research, please cite
the paper:

```bibtex
@misc{clawshield2026clawtrojan,
  title        = {From Prompt Injection to Persistent Control: Defending Agentic Workspaces Against Trojan Backdoors},
  author       = {ClawShield Authors},
  year         = {2026},
  howpublished = {\url{https://github.com/plageon/ClawTrojan}},
  note         = {Code and benchmark release}
}
```

Update the author, venue, and repository URL fields once the public paper and
repository metadata are finalized.
