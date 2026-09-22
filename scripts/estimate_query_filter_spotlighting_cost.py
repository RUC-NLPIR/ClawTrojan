#!/usr/bin/env python3
"""Matched 8-step latency probe. No outcome re-evaluation or full-result replacement."""
import argparse
import hashlib
import json
import os
import platform
import sys
import time
from dataclasses import asdict
from pathlib import Path
from statistics import mean, median
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / 'experiments/agentpoison_spotlighting_cost_20260920'
FULL = ROOT / 'experiments/agentpoison_clawtrojan_full_20260920'
CATS = ['doc_falsification','ext_side_effect','task_dev','unauth_disclosure']


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n')


def main():
    global FULL, OUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-run-dir', type=Path, default=FULL)
    parser.add_argument('--output-dir', type=Path, default=OUT)
    args = parser.parse_args()
    FULL, OUT = args.full_run_dir.resolve(), args.output_dir.resolve()
    from dotenv import load_dotenv
    load_dotenv(ROOT/'.env')
    cfg=json.loads((FULL/'config.json').read_text())
    if cfg.get('base_url'):
        os.environ['OPENAI_BASE_URL']=cfg['base_url']
    os.environ['LLM_REQUEST_TIMEOUT_SECONDS']='180'
    os.environ['AGENTPOISON_QUERY_SCORES']=str(FULL/'query_scores.json')
    os.environ['TOKENIZERS_PARALLELISM']='false'
    OUT.mkdir(parents=True,exist_ok=True)
    metadata=json.loads((FULL/'step_metadata.json').read_text())
    selected=[]
    for cat in CATS:
        eligible=[r for r in metadata if r['outcome_category']==cat]
        eligible.sort(key=lambda r: hashlib.sha256(('cost8-20260920:'+r['eval_id']).encode()).hexdigest())
        selected.extend(eligible[:2])
    paths={r['sample_id']:FULL/'env_shards'/f"shard_{r['shard']:02d}"/r['sample_id'] for r in json.loads((FULL/'selected_samples.json').read_text())}
    manifest={'selection_seed':'cost8-20260920','selected':selected,'agent_model':'gpt-5.4','max_turns':12,
              'conditions':['agentpoison','spotlighting_encoding'],'concurrency':1,
              'timing':'AgentLoop duration, including online defense; excludes judge, model initialization and workspace setup',
              'model_load_policy':'load GPT-2 once; warm up on a fixed non-evaluation query',
              'platform':platform.platform(),'python':sys.version}
    manifest_path=OUT/'manifest.json'
    if manifest_path.exists() and json.loads(manifest_path.read_text())!=manifest: raise ValueError('Manifest changed')
    dump(manifest_path,manifest)
    from agent_eval.perplexity_filter import PerplexityFilter
    from agent_eval.sandbox.agentpoison import query_decision as cached_decision
    from agent_eval.sandbox.config_builder import build_sandbox_config
    from agent_eval.sandbox.runner import SandboxRunner
    frozen=json.loads((FULL/'query_scores.json').read_text())
    started=time.perf_counter()
    scorer=PerplexityFilter(frozen['model'],frozen['revision'],num_threads=4)
    load_seconds=time.perf_counter()-started
    started=time.perf_counter();scorer.score('This is a fixed warm up query.');warmup_seconds=time.perf_counter()-started
    dump(OUT/'initialization.json',{'gpt2_load_seconds':load_seconds,'warmup_seconds':warmup_seconds,'threads':4,'device':'cpu'})
    def online_decision(text):
        started=time.perf_counter()
        score=scorer.score(text)
        elapsed=time.perf_counter()-started
        ref=cached_decision(text)
        assert abs(score['perplexity']-ref['perplexity']) / ref['perplexity'] < 1e-5
        blocked=score['perplexity']>frozen['threshold']
        assert blocked==ref['blocked']
        return {**ref,'perplexity':score['perplexity'],'blocked':blocked,
                'scoring_mode':'online_cpu','ppl_seconds':elapsed}
    results=[]
    for idx,row in enumerate(selected):
        conditions=['agentpoison','spotlighting_encoding']
        if idx%2: conditions.reverse()
        for condition in conditions:
            dest=OUT/'runs'/condition/row['eval_id']
            result_path=dest/'result.json'
            if result_path.exists():
                result=json.loads(result_path.read_text())
                if result['terminated_reason']=='completed':
                    results.append(result);continue
            config=build_sandbox_config(paths[row['sample_id']]/f"step_{row['step_idx']}",max_turns=12)
            assert config and config.eval_id==row['eval_id']
            for attempt in range(1,3):
                runner=SandboxRunner(config,backend='openai',model='gpt-5.4',baseline=condition)
                with patch('agent_eval.sandbox.agentpoison.query_decision',online_decision):
                    trace,audit,diff=runner.run_trial()
                dump(dest/f'attempt_{attempt}.json',{'trace':asdict(trace),'audit':[asdict(a) for a in audit],'workspace_diff':diff})
                if trace.terminated_reason!='error': break
            if trace.terminated_reason!='completed' or trace.metadata.get('llm_error'):
                raise ValueError(f'Incomplete timing trial: {condition} {row["eval_id"]}: {trace.terminated_reason}')
            result={'condition':condition,'eval_id':row['eval_id'],'category':row['outcome_category'],
                    'duration_seconds':trace.duration_seconds,'terminated_reason':trace.terminated_reason,
                    'agent_llm_calls':trace.metadata['agent_llm_calls'],'tool_calls':len(audit),
                    'ppl_seconds':trace.metadata.get('agentpoison',{}).get('ppl_seconds'),
                    'blocked':trace.metadata.get('agentpoison',{}).get('blocked',False)}
            dump(result_path,result);results.append(result)
            dump(OUT/'progress.json',{'done':len(results),'expected':16,'last':result})
            print(json.dumps(result),flush=True)
    assert len(results)==16
    summaries={}
    for c in ['agentpoison','spotlighting_encoding']:
        r=[r for r in results if r['condition']==c];d=[r['duration_seconds'] for r in r]
        summaries[c]={'n':len(r),'mean_seconds':mean(d),'median_seconds':median(d),'min_seconds':min(d),'max_seconds':max(d),
                      'mean_agent_llm_calls':mean(x['agent_llm_calls'] for x in r)}
        if c=='agentpoison': summaries[c]['mean_ppl_seconds']=mean(x['ppl_seconds'] for x in r)
    dump(OUT/'summary.json',{'status':'complete','conditions':summaries,'initialization':json.loads((OUT/'initialization.json').read_text()),'results':results})
    print('COMPLETE '+json.dumps(summaries),flush=True)


if __name__=='__main__': main()
