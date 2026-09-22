import json
import shutil
from pathlib import Path
from unittest.mock import patch

from agent_eval.sandbox.sandbox_eval import SandboxEvaluator
from agent_eval.sandbox.schema import AgentTrace, JudgeVerdict, ToolCallRecord
from scripts.run_full_model_eval import valid_results


def test_resume_preserves_measurements_and_does_not_call_agent(tmp_path):
    root = Path(__file__).resolve().parents[1]
    envs = tmp_path / "envs"
    envs.mkdir()
    shutil.copytree(root / "claw_trojan/envs/cs_delay_001/step_5", envs / "cs_delay_001/step_5")
    output = tmp_path / "output"
    model = "test-model"
    eval_id = "cs_delay_001_step5"
    call = ToolCallRecord(0, "read", {"path": "note"}, "test")
    trace = AgentTrace(eval_id, model, 0, tool_calls=[call], duration_seconds=12.5,
                       messages=[{"role": "assistant", "content": "done"}],
                       metadata={"agent_llm_calls": 2})
    verdict = JudgeVerdict(eval_id, model, 0, "safe", artifact_outcome="safe")
    evaluator = SandboxEvaluator(agent_model=model, judge_model="test-judge")
    with patch("agent_eval.sandbox.sandbox_eval.create_llm_client"), \
         patch("agent_eval.sandbox.sandbox_eval.SandboxRunner.run_trial", return_value=(trace, [call], {})) as run, \
         patch("agent_eval.sandbox.sandbox_eval.ASRJudge.judge", return_value=verdict) as judge:
        evaluator.run(str(envs), str(output))
        evaluator.run(str(envs), str(output))
        assert run.call_count == judge.call_count == 1
    row = json.loads((output / "sandbox_results.jsonl").read_text())
    assert row["duration_seconds"] == 12.5
    assert row["tool_calls_count"] == 1
    assert row["terminated_reason"] == "completed"
    assert valid_results(output, model, {(eval_id, 0)})
    # Completeness validation must reject both omitted and duplicate steps.
    assert not valid_results(output, model, {(eval_id, 0), ("missing_step", 0)})
    path = output / "sandbox_results.jsonl"
    path.write_text(path.read_text() * 2)
    assert not valid_results(output, model, {(eval_id, 0)})


def test_valid_results_rejects_invalid_trial(tmp_path):
    (tmp_path / "sandbox_results.jsonl").write_text(json.dumps({"eval_id": "sample_step1", "trial": 0, "verdict": "error"}) + "\n")
    assert not valid_results(tmp_path, "model", {("sample_step1", 0)})
