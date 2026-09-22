#!/usr/bin/env python3
"""Score the frozen user queries with GPT-2, then run the query-filter baseline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='configs/agentpoison_clawtrojan_full_20260920.json')
    parser.add_argument('--score-only', action='store_true', help='Prepare GPT-2 scores without paid agent/judge calls')
    args = parser.parse_args()
    os.chdir(ROOT)
    config = json.loads(Path(args.config).read_text())
    if config['baseline'] != 'agentpoison' or config.get('conditions') != ['agentpoison']:
        raise ValueError('Expected a query-filter-only configuration')
    from scripts.run_full_model_eval import prepare, write_json
    out = ROOT / config['output_dir']
    out.mkdir(parents=True, exist_ok=True)
    # Score the same frozen copies that the evaluator consumes.
    prepare(config, out)
    from claw_trojan.loader import load_trojan_env
    rows = json.loads((out / 'selected_samples.json').read_text())
    steps = [s for r in rows for s in load_trojan_env(str(out / 'env_shards' / f"shard_{r['shard']:02d}" / r['sample_id'])) if s.is_malicious]
    calibration_path = ROOT / 'reproduction/agentpoison_calibration.json'
    calibration = json.loads(calibration_path.read_text())
    from agent_eval.perplexity_filter import PerplexityFilter, clean_quantile_threshold
    if clean_quantile_threshold(calibration['calibration_scores'], calibration['quantile']) != calibration['threshold']:
        raise ValueError('Frozen threshold does not match the clean calibration scores')
    artifact = dict(model=calibration['model'], revision=calibration['revision'],
                    threshold=calibration['threshold'], scoring_stage='input_query_before_agent',
                    calibration_sha256=hashlib.sha256(calibration_path.read_bytes()).hexdigest())
    scorer = PerplexityFilter(artifact['model'], artifact['revision'], num_threads=4)
    queries = {}
    for step in steps:
        digest = hashlib.sha256(step.user_input.encode()).hexdigest()
        if digest not in queries:
            queries[digest] = scorer.score(step.user_input)
    artifact['queries'] = queries
    target = out / 'query_scores.json'
    if target.exists() and json.loads(target.read_text()) != artifact:
        raise ValueError('Scores changed; use a new output directory rather than mixing cached trials')
    write_json(target, artifact)
    blocked = sum(queries[hashlib.sha256(s.user_input.encode()).hexdigest()]['perplexity'] > artifact['threshold'] for s in steps)
    print(f'Scored {len(queries)} unique queries; would block {blocked}/{len(steps)} steps', flush=True)
    if not args.score_only:
        os.environ['AGENTPOISON_QUERY_SCORES'] = str(target.resolve())
        subprocess.run([sys.executable, str(ROOT / 'scripts/run_full_model_eval.py'), '--config', args.config], check=True)


if __name__ == '__main__':
    main()
