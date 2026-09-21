import hashlib
import json
from pathlib import Path

import pytest

from agent_eval.perplexity_filter import clean_quantile_threshold
from agent_eval.sandbox import agentpoison
from agent_eval.sandbox.agent_loop import AgentLoop, BaseToolUseClient
from agent_eval.sandbox.baselines import SandboxBaseline
from agent_eval.sandbox.tool_dispatcher import ToolDispatcher
from scripts.prepare_revision_data import tree_digest, verify_dataset
from scripts.verify_revision_results import verify

ROOT = Path(__file__).resolve().parents[1]


def test_published_revision_metrics():
    report = verify(ROOT / 'reproduction')
    assert len(report['runs']) == 7
    assert report['runs']['gpt-5.4_agentpoison']['counts']['compromised'] == 861


def test_example_subset_cannot_be_used_as_paper_split():
    lock = json.loads((ROOT / 'reproduction/dataset_lock.json').read_text())
    with pytest.raises(ValueError, match='sample IDs'):
        verify_dataset(ROOT / 'claw_trojan', lock)


def test_environment_hash_tracks_names_contents_and_extra_files(tmp_path):
    file = tmp_path / 'a.txt'
    file.write_text('a')
    original = tree_digest(tmp_path)
    file.write_text('b')
    assert tree_digest(tmp_path) != original
    file.write_text('a')
    file.rename(tmp_path / 'b.txt')
    assert tree_digest(tmp_path) != original
    (tmp_path / 'b.txt').rename(file)
    (tmp_path / 'extra.txt').write_text('')
    assert tree_digest(tmp_path) != original


def test_clean_calibration_matches_frozen_threshold():
    data = json.loads((ROOT / 'reproduction/agentpoison_calibration.json').read_text())
    assert len(data['calibration_scores']) == 200
    assert clean_quantile_threshold(data['calibration_scores'], data['quantile']) == data['threshold']
    assert sum(s['perplexity'] > data['threshold'] for s in data['calibration_scores']) == 10


def query_scores(tmp_path, monkeypatch, text, ppl):
    path = tmp_path / 'scores.json'
    data = dict(scoring_stage='input_query_before_agent', threshold=10, model='test', revision='test',
                calibration_sha256='test', queries={hashlib.sha256(text.encode()).hexdigest():
                dict(text=text, perplexity=ppl, token_count=3)})
    path.write_text(json.dumps(data))
    agentpoison._artifact.cache_clear()
    monkeypatch.setenv('AGENTPOISON_QUERY_SCORES', str(path))


def test_query_gate_threshold_and_mismatch(tmp_path, monkeypatch):
    query_scores(tmp_path, monkeypatch, 'read the note', 10)
    assert not agentpoison.query_decision('read the note')['blocked']
    with pytest.raises(KeyError):
        agentpoison.query_decision('unscored input')
    query_scores(tmp_path, monkeypatch, 'read the note', 11)
    assert agentpoison.query_decision('read the note')['blocked']


def test_query_gate_blocks_before_agent_and_tools(tmp_path, monkeypatch):
    query_scores(tmp_path, monkeypatch, 'read the note', 11)
    class NoCalls(BaseToolUseClient):
        def chat(self, *args, **kwargs):
            pytest.fail('Blocked query reached the model')
    audit = []
    baseline = SandboxBaseline('agentpoison')
    dispatcher = ToolDispatcher([], tmp_path, audit, baseline)
    trace = AgentLoop(NoCalls(), dispatcher).run('system', [], [], 'read the note')
    assert trace.terminated_reason == 'blocked_by_perplexity_filter'
    assert trace.metadata['agentpoison']['blocked']
    assert not audit
