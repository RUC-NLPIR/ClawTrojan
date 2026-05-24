"""Latency matrix runner for DASGuard and sandbox baseline conditions."""

from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Optional, Sequence

from loguru import logger

from .baselines import SANDBOX_CONDITIONS
from .sandbox_eval import SandboxEvaluator


DEFAULT_LATENCY_CONDITIONS = tuple(
    ["dasguard"]
    + sorted(condition for condition in SANDBOX_CONDITIONS if condition not in {"dasguard", "no_defense"})
)


@dataclass(frozen=True)
class LatencyRunConfig:
    agent_backend: str = "openai"
    agent_model: Optional[str] = None
    judge_backend: str = "openai"
    judge_model: Optional[str] = None
    max_turns: int = 10
    trials: int = 1
    promptshield_classifier_path: Optional[str] = None
    dynamic_defense: str = "cross_step_context_only"
    dasguard_use_source_labels: bool = True
    dasguard_use_embedding: bool = True
    dasguard_use_memory_context: bool = True
    dasguard_llm_review_backend: Optional[str] = None
    dasguard_llm_review_model: Optional[str] = None
    eval_split: str = "malicious"


def validate_latency_conditions(conditions: Optional[Sequence[str]]) -> List[str]:
    """Return validated latency conditions, excluding no_defense by policy."""
    selected = list(conditions or DEFAULT_LATENCY_CONDITIONS)
    if not selected:
        raise ValueError("At least one latency condition is required")
    unknown = sorted(set(selected) - SANDBOX_CONDITIONS)
    if unknown:
        raise ValueError(f"Unknown sandbox condition(s): {', '.join(unknown)}")
    if "no_defense" in selected:
        raise ValueError("Latency matrix excludes no_defense; omit that condition")
    return selected


def _numeric(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _percentile(values: Sequence[float], q: float) -> Optional[float]:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lower = int(pos)
    upper = min(lower + 1, len(ordered) - 1)
    weight = pos - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _avg_optional(values: Iterable[Any]) -> Optional[float]:
    nums = [float(v) for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    return mean(nums) if nums else None


def _round_optional(value: Optional[float], digits: int = 4) -> Optional[float]:
    return round(value, digits) if value is not None else None


def summarize_latency_results(
    results_path: str | Path,
    *,
    condition: Optional[str] = None,
    output_dir: Optional[str | Path] = None,
    wall_time_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """Summarize per-step latency from a sandbox_results.jsonl file."""
    path = Path(results_path)
    rows: List[Dict[str, Any]] = []
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))

    durations = [
        duration
        for duration in (_numeric(row.get("duration_seconds")) for row in rows)
        if duration is not None
    ]
    tool_calls = [row.get("tool_calls_count") for row in rows]
    agent_llm_calls = [row.get("agent_llm_calls") for row in rows]
    extra_llm_calls = [row.get("baseline_extra_llm_calls") for row in rows]
    total_llm_calls = [row.get("total_llm_calls") for row in rows]
    verdicts = [str(row.get("verdict", "")) for row in rows]

    resolved_condition = condition or (str(rows[0].get("condition")) if rows else "")
    summary = {
        "condition": resolved_condition,
        "output_dir": str(output_dir or path.parent),
        "results_path": str(path),
        "n_total": len(rows),
        "n_with_latency": len(durations),
        "n_missing_latency": len(rows) - len(durations),
        "n_error": sum(1 for verdict in verdicts if verdict == "error"),
        "wall_time_seconds": _round_optional(wall_time_seconds),
        "duration_seconds_total": _round_optional(sum(durations) if durations else None),
        "duration_seconds_mean": _round_optional(mean(durations) if durations else None),
        "duration_seconds_p50": _round_optional(_percentile(durations, 0.50)),
        "duration_seconds_p90": _round_optional(_percentile(durations, 0.90)),
        "duration_seconds_p95": _round_optional(_percentile(durations, 0.95)),
        "duration_seconds_min": _round_optional(min(durations) if durations else None),
        "duration_seconds_max": _round_optional(max(durations) if durations else None),
        "tool_calls_mean": _round_optional(_avg_optional(tool_calls)),
        "agent_llm_calls_mean": _round_optional(_avg_optional(agent_llm_calls)),
        "baseline_extra_llm_calls_mean": _round_optional(_avg_optional(extra_llm_calls)),
        "total_llm_calls_mean": _round_optional(_avg_optional(total_llm_calls)),
    }
    return summary


def write_latency_outputs(output_root: str | Path, summaries: Sequence[Dict[str, Any]]) -> None:
    """Write latency_cost.json and latency_cost.csv under output_root."""
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / "latency_cost.json"
    csv_path = root / "latency_cost.csv"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(list(summaries), f, ensure_ascii=False, indent=2)

    fieldnames = [
        "condition",
        "output_dir",
        "n_total",
        "n_with_latency",
        "n_missing_latency",
        "n_error",
        "wall_time_seconds",
        "duration_seconds_total",
        "duration_seconds_mean",
        "duration_seconds_p50",
        "duration_seconds_p90",
        "duration_seconds_p95",
        "duration_seconds_min",
        "duration_seconds_max",
        "tool_calls_mean",
        "agent_llm_calls_mean",
        "baseline_extra_llm_calls_mean",
        "total_llm_calls_mean",
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in summaries:
            writer.writerow({field: row.get(field) for field in fieldnames})


def run_latency_matrix(
    *,
    envs_root: str,
    output_root: str,
    conditions: Optional[Sequence[str]] = None,
    config: Optional[LatencyRunConfig] = None,
    summarize_only: bool = False,
) -> Dict[str, Any]:
    """Run or summarize latency for DASGuard and baseline conditions."""
    selected = validate_latency_conditions(conditions)
    cfg = config or LatencyRunConfig()
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)

    summaries: List[Dict[str, Any]] = []
    for condition in selected:
        condition_dir = root / condition
        wall_time_seconds = None
        if not summarize_only:
            logger.info(f"Running latency condition={condition} -> {condition_dir}")
            evaluator = SandboxEvaluator(
                agent_backend=cfg.agent_backend,
                agent_model=cfg.agent_model,
                judge_backend=cfg.judge_backend,
                judge_model=cfg.judge_model,
                max_turns=cfg.max_turns,
                trials=cfg.trials,
                baseline=condition,
                promptshield_classifier_path=cfg.promptshield_classifier_path,
                dynamic_defense=cfg.dynamic_defense,
                dasguard_use_source_labels=cfg.dasguard_use_source_labels,
                dasguard_use_embedding=cfg.dasguard_use_embedding,
                dasguard_use_memory_context=cfg.dasguard_use_memory_context,
                dasguard_llm_review_backend=cfg.dasguard_llm_review_backend,
                dasguard_llm_review_model=cfg.dasguard_llm_review_model,
                eval_split=cfg.eval_split,
            )
            start = time.perf_counter()
            evaluator.run(envs_root=envs_root, output_dir=str(condition_dir))
            wall_time_seconds = time.perf_counter() - start

        summary = summarize_latency_results(
            condition_dir / "sandbox_results.jsonl",
            condition=condition,
            output_dir=condition_dir,
            wall_time_seconds=wall_time_seconds,
        )
        summaries.append(summary)

    write_latency_outputs(root, summaries)
    return {
        "conditions": selected,
        "output_root": str(root),
        "summary_json": str(root / "latency_cost.json"),
        "summary_csv": str(root / "latency_cost.csv"),
        "summaries": summaries,
    }
