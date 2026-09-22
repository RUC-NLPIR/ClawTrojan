"""Frozen query-PPL gate; AgentPoison is the experiment alias, not a new defense."""
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path


@lru_cache(maxsize=1)
def _artifact(path):
    data = json.loads(Path(path).read_text())
    if data['scoring_stage'] != 'input_query_before_agent':
        raise ValueError('Unsupported AgentPoison scoring stage')
    if not math.isfinite(data['threshold']) or data['threshold'] <= 0:
        raise ValueError('Invalid PPL threshold')
    return data


def query_decision(text):
    # Scores are prepared locally with the pinned model before any agent runs.
    # Missing/mismatched scores fail explicitly; they never count as safe trials.
    data = _artifact(os.environ['AGENTPOISON_QUERY_SCORES'])
    digest = hashlib.sha256(text.encode()).hexdigest()
    score = data['queries'][digest]
    if score['text'] != text or not math.isfinite(score['perplexity']):
        raise ValueError('Query score mismatch or non-finite score')
    return {
        'implementation': 'perplexity_filter', 'scoring_stage': data['scoring_stage'],
        'model': data['model'], 'revision': data['revision'],
        'calibration_sha256': data['calibration_sha256'],
        'query_sha256': digest, 'perplexity': score['perplexity'],
        'token_count': score['token_count'], 'threshold': data['threshold'],
        'blocked': score['perplexity'] > data['threshold'],
    }
