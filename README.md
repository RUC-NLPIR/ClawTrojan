# ClawTrojan Anonymous Reproduction Package

This repository contains the code, benchmark data subset, and evaluation scripts
needed to reproduce the ClawTrojan/DASGuard paper experiments. It is prepared for anonymous review: git history, local
configuration, API keys, machine paths, IDE files, raw execution traces, and
author-identifying manuscript metadata are intentionally excluded.

## Contents

- `claw_trojan/`: a reduced English ClawTrojan example subset with three
  annotated sample chains per available outcome category, plus the matching
  workspaces, step metadata, skill bundles, and synthetic user profiles.
- `agent_eval/`: DASGuard, sandbox execution, baseline adapters, AgentDojo
  adapter, judging, and metric code.
- `scripts/`: paper-scale sharding, worker execution, result merging, and
  selected baseline helper scripts.
- `tests/`: focused regression tests for DASGuard and baseline wiring.

Large raw outputs, local `.env` files, cached bytecode, IDE files, full paper
draft metadata, and remote-machine training logs are not included.

The optional synthetic `dataset/` generator from the working repository is not
included in this minimal package because it is not required for reproducing the
ClawTrojan sandbox results.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Fill only the API keys required for the backends you intend to run. DASGuard can
use the deterministic `hashing` embedding backend for local smoke tests without
a network embedding service.

## Smoke Checks

```bash
python run.py trojan-export \
  --envs-root ./claw_trojan/envs \
  --output-path ./outputs/trojan_gold.jsonl

python run.py dasguard-detect \
  --envs-root ./claw_trojan/envs \
  --embedding-backend hashing \
  --output-path ./outputs/dasguard_pred.jsonl

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

Use the merge script above to regenerate table-ready summaries from completed
paper-scale shard outputs.

## Data Privacy Note

Benchmark workspaces contain synthetic user profiles, mock credentials, fake
contacts, and injected attack strings because those are part of the evaluation
task. They are not real user data. Real local credentials and personally
identifying project metadata were excluded from this anonymous package.
