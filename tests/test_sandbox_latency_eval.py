import json
from pathlib import Path

import pytest

from agent_eval.sandbox.latency_eval import (
    DEFAULT_LATENCY_CONDITIONS,
    summarize_latency_results,
    validate_latency_conditions,
    write_latency_outputs,
)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_default_latency_conditions_include_dasguard_and_exclude_no_defense() -> None:
    assert DEFAULT_LATENCY_CONDITIONS[0] == "dasguard"
    assert "no_defense" not in DEFAULT_LATENCY_CONDITIONS
    assert validate_latency_conditions(None) == list(DEFAULT_LATENCY_CONDITIONS)


def test_validate_latency_conditions_rejects_no_defense() -> None:
    with pytest.raises(ValueError, match="excludes no_defense"):
        validate_latency_conditions(["dasguard", "no_defense"])


def test_summarize_latency_results_handles_missing_duration(tmp_path: Path) -> None:
    results_path = tmp_path / "dasguard" / "sandbox_results.jsonl"
    _write_jsonl(
        results_path,
        [
            {
                "condition": "dasguard",
                "duration_seconds": 10.0,
                "tool_calls_count": 2,
                "agent_llm_calls": 3,
                "baseline_extra_llm_calls": 0,
                "total_llm_calls": 3,
                "verdict": "safe",
            },
            {
                "condition": "dasguard",
                "duration_seconds": 20.0,
                "tool_calls_count": 4,
                "agent_llm_calls": 5,
                "baseline_extra_llm_calls": 1,
                "total_llm_calls": 6,
                "verdict": "compromised",
            },
            {
                "condition": "dasguard",
                "duration_seconds": None,
                "tool_calls_count": None,
                "verdict": "error",
            },
        ],
    )

    summary = summarize_latency_results(results_path, wall_time_seconds=35.12345)

    assert summary["condition"] == "dasguard"
    assert summary["n_total"] == 3
    assert summary["n_with_latency"] == 2
    assert summary["n_missing_latency"] == 1
    assert summary["n_error"] == 1
    assert summary["duration_seconds_mean"] == 15.0
    assert summary["duration_seconds_p50"] == 15.0
    assert summary["duration_seconds_p95"] == 19.5
    assert summary["tool_calls_mean"] == 3.0
    assert summary["baseline_extra_llm_calls_mean"] == 0.5
    assert summary["wall_time_seconds"] == 35.1234


def test_write_latency_outputs(tmp_path: Path) -> None:
    summaries = [
        {
            "condition": "dasguard",
            "output_dir": "out/dasguard",
            "n_total": 1,
            "n_with_latency": 1,
            "duration_seconds_mean": 1.25,
        }
    ]

    write_latency_outputs(tmp_path, summaries)

    assert (tmp_path / "latency_cost.json").exists()
    assert (tmp_path / "latency_cost.csv").exists()
    saved = json.loads((tmp_path / "latency_cost.json").read_text(encoding="utf-8"))
    assert saved[0]["condition"] == "dasguard"
