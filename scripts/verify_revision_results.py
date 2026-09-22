#!/usr/bin/env python3
"""Recompute revision results from released step verdicts, without model calls."""
import argparse
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path
from statistics import mean
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def verify(root):
    from agent_eval.sandbox.sandbox_metrics import compute_sandbox_metrics
    from agent_eval.sandbox.schema import JudgeVerdict
    metadata = json.loads((root / 'step_metadata.json').read_text())
    expected = {r['eval_id'] for r in metadata}
    if len(metadata) != 919 or len(expected) != 919 or len({r['sample_id'] for r in metadata}) != 339:
        raise ValueError('Expected 919 unique malicious steps from 339 samples')
    manifest = json.loads((root / 'results_manifest.json').read_text())
    summaries, records = {}, {}
    for name, spec in manifest.items():
        path = root / spec['result_file']
        if hashlib.sha256(path.read_bytes()).hexdigest() != spec['sha256']:
            raise ValueError(f'Result checksum mismatch: {name}')
        with path.open() as fp:
            rows = list(csv.DictReader(fp))
        if len(rows) != len(expected) or {r['eval_id'] for r in rows} != expected:
            raise ValueError(f'Missing or duplicate evaluation IDs: {name}')
        if any(r['trial'] != '0' or r['verdict'] not in {'compromised', 'partial', 'safe'} for r in rows):
            raise ValueError(f'Unexpected trial or verdict: {name}')
        verdicts = [JudgeVerdict(eval_id=r['eval_id'], model=spec['model'], trial=0, verdict=r['verdict']) for r in rows]
        metrics = compute_sandbox_metrics(verdicts, metadata)
        for key, value in spec['expected_overall'].items():
            if not math.isclose(metrics['overall'][key], value, rel_tol=1e-10, abs_tol=1e-10):
                raise ValueError(f'Overall metric differs: {name}/{key}')
        for cat, stats in spec['expected_by_outcome_category'].items():
            for key, value in stats.items():
                if not math.isclose(metrics['by_outcome_category'][cat][key], value, rel_tol=1e-10, abs_tol=1e-10):
                    raise ValueError(f'Outcome metric differs: {name}/{cat}/{key}')
        summaries[name] = dict(batch=spec['batch'], overall=metrics['overall'],
                               counts=dict(Counter(r['verdict'] for r in rows)),
                               termination_counts=dict(Counter(r['terminated_reason'] for r in rows)),
                               by_outcome_category=metrics['by_outcome_category'])
        records[name] = {r['eval_id']: r['verdict'] for r in rows}
    base = records['gpt-5.4_no_defense']
    paired = {c: dict(Counter(base[k] + ' -> ' + records['gpt-5.4_' + c][k] for k in base))
              for c in ['spotlighting_datamarking', 'spotlighting_encoding']}
    cost = json.loads((root / 'cost_summary.json').read_text())
    sample_sets = []
    for condition, stats in cost['conditions'].items():
        rows = [r for r in cost['results'] if r['condition'] == condition]
        ids = {r['eval_id'] for r in rows}
        if len(rows) != 8 or len(ids) != 8 or any(r['terminated_reason'] != 'completed' for r in rows):
            raise ValueError('Invalid eight-step cost sample')
        if not math.isclose(mean(r['duration_seconds'] for r in rows), stats['mean_seconds'], abs_tol=1e-10):
            raise ValueError('Cost mean differs from step measurements')
        sample_sets.append(ids)
    if len(sample_sets) != 2 or sample_sets[0] != sample_sets[1]:
        raise ValueError('Cost conditions must use the same eight steps')
    return dict(runs=summaries, spotlighting_paired_transitions=paired, cost=cost['conditions'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-root', type=Path, default=ROOT / 'reproduction')
    parser.add_argument('--output', type=Path, default=ROOT / 'outputs/paper_revision/verified_results.json')
    args = parser.parse_args()
    summary = verify(args.artifact_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + '\n')
    print('Verified 7 conditions × 919 steps, category ASR, FC-ASR, CPS, paired transitions and 16 timing records.')
    print(args.output)


if __name__ == '__main__':
    main()
