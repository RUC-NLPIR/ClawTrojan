#!/usr/bin/env python3
"""Merge paper-eval shard outputs and export table-ready summaries."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_eval.sandbox.latency_eval import summarize_latency_results


ATTACK_COLUMNS = [
    ("policy_shift", "Pol."),
    ("privilege_escalation", "Priv."),
    ("prompt_injection", "Prm."),
    ("persistence_poisoning", "Pers."),
    ("task_hijack", "Hij."),
    ("data_exfiltration", "Exf."),
    ("doc_falsification", "Doc"),
]

METHOD_LABELS = {
    "no_defense": "Raw agent",
    "clawkeeper": "ClawKeeper",
    "struq": "StruQ",
    "melon": "MELON",
    "promptshield_1b": "PromptShield-1B",
    "promptshield_8b": "PromptShield-8B",
    "camel": "CaMeL",
    "agentsentry": "AgentSentry",
    "dasguard": "DASGuard",
    "dasguard_isolated": "w/o source/state (legacy)",
    "dasguard_no_cross_step": "w/o cross-step state",
    "dasguard_no_source_labels": "w/o source labels",
    "dasguard_no_embedding_score": "w/o embedding score",
    "dasguard_no_memory_match": "w/o memory match",
    "dasguard_rule_only": "rules only (legacy)",
    "dasguard_block_only": "w/o sanitization",
}


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def _rate_counts(stats: Dict[str, Any]) -> Dict[str, int]:
    n = int(stats.get("n", 0) or 0)
    compromised = round(float(stats.get("asr", 0.0) or 0.0) * n)
    partial = round(float(stats.get("partial_rate", 0.0) or 0.0) * n)
    safe = max(0, n - compromised - partial)
    invalid = int(stats.get("invalid", 0) or 0)
    return {
        "compromised": compromised,
        "partial": partial,
        "safe": safe,
        "n": n,
        "invalid": invalid,
        "total": int(stats.get("total", n + invalid) or (n + invalid)),
    }


def _rates_from_counts(counts: Dict[str, int]) -> Dict[str, Any]:
    n = int(counts.get("n", 0) or 0)
    invalid = int(counts.get("invalid", 0) or 0)
    if n == 0:
        return {"asr": 0.0, "partial_rate": 0.0, "safe_rate": 0.0, "n": 0, "invalid": invalid, "total": invalid}
    compromised = int(counts.get("compromised", 0) or 0)
    partial = int(counts.get("partial", 0) or 0)
    safe = int(counts.get("safe", 0) or 0)
    return {
        "asr": compromised / n,
        "partial_rate": partial / n,
        "safe_rate": safe / n,
        "n": n,
        "invalid": invalid,
        "total": int(counts.get("total", n + invalid) or (n + invalid)),
    }


def _sum_rate_dicts(items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    total = defaultdict(int)
    for item in items:
        counts = _rate_counts(item)
        for key, value in counts.items():
            total[key] += value
    return _rates_from_counts(total)


def _clean_rate_counts(stats: Dict[str, Any]) -> Dict[str, int]:
    n = int(stats.get("n", 0) or 0)
    fpr = round(float(stats.get("fpr", 0.0) or 0.0) * n)
    overblocked = round(float(stats.get("overblock_rate", 0.0) or 0.0) * n)
    degraded = round(float(stats.get("degraded_rate", 0.0) or 0.0) * n)
    if overblocked + degraded != fpr:
        degraded = max(0, fpr - overblocked)
    preserved = max(0, n - overblocked - degraded)
    invalid = int(stats.get("invalid", 0) or 0)
    return {
        "overblocked": overblocked,
        "degraded": degraded,
        "preserved": preserved,
        "n": n,
        "invalid": invalid,
        "total": int(stats.get("total", n + invalid) or (n + invalid)),
    }


def _clean_rates_from_counts(counts: Dict[str, int]) -> Dict[str, Any]:
    n = int(counts.get("n", 0) or 0)
    invalid = int(counts.get("invalid", 0) or 0)
    if n == 0:
        return {
            "fpr": 0.0,
            "overblock_rate": 0.0,
            "degraded_rate": 0.0,
            "utility_preservation_rate": 0.0,
            "n": 0,
            "invalid": invalid,
            "total": invalid,
        }
    overblocked = int(counts.get("overblocked", 0) or 0)
    degraded = int(counts.get("degraded", 0) or 0)
    preserved = int(counts.get("preserved", 0) or 0)
    return {
        "fpr": (overblocked + degraded) / n,
        "overblock_rate": overblocked / n,
        "degraded_rate": degraded / n,
        "utility_preservation_rate": preserved / n,
        "n": n,
        "invalid": invalid,
        "total": int(counts.get("total", n + invalid) or (n + invalid)),
    }


def _sum_clean_rate_dicts(items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    total = defaultdict(int)
    for item in items:
        counts = _clean_rate_counts(item)
        for key, value in counts.items():
            total[key] += value
    return _clean_rates_from_counts(total)


def _sum_breakdown(metrics_list: List[Dict[str, Any]], key: str) -> Dict[str, Any]:
    buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for metrics in metrics_list:
        for bucket, stats in metrics.get(key, {}).items():
            buckets[bucket].append(stats)
    return {bucket: _sum_rate_dicts(stats_list) for bucket, stats_list in sorted(buckets.items())}


def _merge_metrics(metrics_list: List[Dict[str, Any]], *, condition: str, model_key: str) -> Dict[str, Any]:
    per_sample: Dict[str, Any] = {}
    for metrics in metrics_list:
        overlap = set(per_sample).intersection(metrics.get("per_sample", {}))
        if overlap:
            raise ValueError(f"Duplicate per-sample metrics in merge: {sorted(overlap)[:5]}")
        per_sample.update(metrics.get("per_sample", {}))

    overall = _sum_rate_dicts(metrics.get("overall", {}) for metrics in metrics_list)
    if per_sample:
        n_samples = len(per_sample)
        overall["full_chain_asr"] = sum(1 for row in per_sample.values() if row.get("full_chain")) / n_samples
        overall["avg_chain_penetration_score"] = mean(
            float(row.get("chain_penetration_score", 0.0) or 0.0)
            for row in per_sample.values()
        )

    merged = {
        "condition": condition,
        "model_key": model_key,
        "dynamic_defense": metrics_list[0].get("dynamic_defense", "isolated_step") if metrics_list else "",
        "dasguard_use_source_labels": metrics_list[0].get("dasguard_use_source_labels", True) if metrics_list else True,
        "dasguard_use_embedding": metrics_list[0].get("dasguard_use_embedding", True) if metrics_list else True,
        "dasguard_use_memory_context": metrics_list[0].get("dasguard_use_memory_context", True) if metrics_list else True,
        "eval_split": metrics_list[0].get("eval_split", "malicious") if metrics_list else "",
        "agent_model": metrics_list[0].get("agent_model", "") if metrics_list else "",
        "judge_model": metrics_list[0].get("judge_model", "") if metrics_list else "",
        "overall": overall,
        "by_outcome_category": _sum_breakdown(metrics_list, "by_outcome_category"),
        "by_attack_type": _sum_breakdown(metrics_list, "by_attack_type"),
        "by_stage_tag": _sum_breakdown(metrics_list, "by_stage_tag"),
        "per_sample": dict(sorted(per_sample.items())),
    }
    if any("clean_overall" in metrics for metrics in metrics_list):
        merged["clean_overall"] = _sum_clean_rate_dicts(
            metrics.get("clean_overall", {}) for metrics in metrics_list
        )
    return merged


def _find_groups(input_root: Path) -> Dict[Tuple[str, str], List[Path]]:
    groups: Dict[Tuple[str, str], List[Path]] = defaultdict(list)
    for metrics_path in sorted(input_root.rglob("sandbox_metrics.json")):
        rel = metrics_path.relative_to(input_root)
        if len(rel.parts) < 4:
            continue
        model_key, condition = rel.parts[0], rel.parts[1]
        groups[(model_key, condition)].append(metrics_path.parent)
    return groups


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _concat_results(shard_dirs: List[Path], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "sandbox_results.jsonl"
    with out_path.open("w", encoding="utf-8") as out:
        for shard_dir in shard_dirs:
            for row in _read_jsonl(shard_dir / "sandbox_results.jsonl"):
                row.setdefault("source_shard_dir", str(shard_dir))
                out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return out_path


def _pct(value: Any) -> str:
    if value is None:
        return "--"
    return f"{float(value) * 100:.1f}"


def _mean_latency_seconds(summary: Dict[str, Any]) -> str:
    value = summary.get("duration_seconds_mean")
    if value is None:
        return "--"
    return f"{float(value):.1f}s"


def _summary_row(
    *,
    model_key: str,
    condition: str,
    output_dir: Path,
    metrics: Dict[str, Any],
    latency: Dict[str, Any],
) -> Dict[str, Any]:
    overall = metrics.get("overall", {})
    clean_overall = metrics.get("clean_overall", {})
    row = {
        "model_key": model_key,
        "condition": condition,
        "method": METHOD_LABELS.get(condition, condition),
        "output_dir": str(output_dir),
        "valid_n": overall.get("n", 0),
        "invalid": overall.get("invalid", 0),
        "clean_valid_n": clean_overall.get("n", 0),
        "clean_invalid": clean_overall.get("invalid", 0),
        "clean_fpr": clean_overall.get("fpr"),
        "clean_overblock_rate": clean_overall.get("overblock_rate"),
        "clean_degraded_rate": clean_overall.get("degraded_rate"),
        "clean_utility_preservation_rate": clean_overall.get("utility_preservation_rate"),
        "asr": overall.get("asr", 0.0),
        "partial_rate": overall.get("partial_rate", 0.0),
        "safe_rate": overall.get("safe_rate", 0.0),
        "full_chain_asr": overall.get("full_chain_asr"),
        "avg_chain_penetration_score": overall.get("avg_chain_penetration_score"),
        "latency_mean_seconds": latency.get("duration_seconds_mean"),
        "latency_p50_seconds": latency.get("duration_seconds_p50"),
        "latency_p90_seconds": latency.get("duration_seconds_p90"),
        "baseline_extra_llm_calls_mean": latency.get("baseline_extra_llm_calls_mean"),
        "total_llm_calls_mean": latency.get("total_llm_calls_mean"),
    }
    for attack_type, _label in ATTACK_COLUMNS:
        row[f"attack_{attack_type}_asr"] = (
            metrics.get("by_attack_type", {}).get(attack_type, {}).get("asr")
        )
    return row


def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: List[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _latex_main_row(row: Dict[str, Any]) -> str:
    attack_values = [
        _pct(row.get(f"attack_{attack_type}_asr"))
        for attack_type, _label in ATTACK_COLUMNS
    ]
    return (
        f"{row['method']} & {_mean_latency_seconds({'duration_seconds_mean': row.get('latency_mean_seconds')})} "
        f"& {_pct(row.get('asr'))} & {_pct(row.get('full_chain_asr'))} "
        f"& {_pct(row.get('avg_chain_penetration_score'))} "
        f"& {' & '.join(attack_values)} \\\\"
    )


def _latex_ablation_row(row: Dict[str, Any]) -> str:
    return (
        f"{row['method']} & {_pct(row.get('asr'))} "
        f"& {_pct(row.get('full_chain_asr'))} "
        f"& {_pct(row.get('avg_chain_penetration_score'))} \\\\"
    )


def _write_latex_rows(table_dir: Path, rows: List[Dict[str, Any]]) -> None:
    main_rows = [
        row for row in rows
        if row["condition"] not in {
            "dasguard_isolated",
            "dasguard_no_cross_step",
            "dasguard_no_source_labels",
            "dasguard_no_embedding_score",
            "dasguard_no_memory_match",
            "dasguard_rule_only",
            "dasguard_block_only",
        }
    ]
    ablation_rows = [
        row for row in rows
        if row["condition"] in {
            "dasguard",
            "dasguard_no_cross_step",
            "dasguard_no_source_labels",
            "dasguard_no_embedding_score",
            "dasguard_no_memory_match",
            "dasguard_block_only",
        }
    ]
    (table_dir / "table3_rows.tex").write_text(
        "\n".join(_latex_main_row(row) for row in main_rows) + "\n",
        encoding="utf-8",
    )
    (table_dir / "table5_rows.tex").write_text(
        "\n".join(_latex_ablation_row(row) for row in ablation_rows) + "\n",
        encoding="utf-8",
    )


def _breakdown_rows(summary_rows: List[Dict[str, Any]], merged_metrics: Dict[Tuple[str, str], Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for summary in summary_rows:
        metrics = merged_metrics[(summary["model_key"], summary["condition"])]
        for bucket, stats in metrics.get(key, {}).items():
            rows.append({
                "model_key": summary["model_key"],
                "condition": summary["condition"],
                "bucket": bucket,
                **stats,
            })
    return rows


def _chain_rows(merged_metrics: Dict[Tuple[str, str], Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for (model_key, condition), metrics in sorted(merged_metrics.items()):
        for sample_id, sample in metrics.get("per_sample", {}).items():
            rows.append({
                "model_key": model_key,
                "condition": condition,
                "sample_id": sample_id,
                "chain_penetration_score": sample.get("chain_penetration_score"),
                "full_chain": sample.get("full_chain"),
                "compromised_steps": sample.get("compromised_steps"),
                "total_steps": sample.get("total_steps"),
                "invalid_steps": sample.get("invalid_steps"),
                "verdicts": " ".join(sample.get("verdicts", [])),
            })
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", type=Path, default=Path("outputs/paper_eval_20260521/runs"))
    parser.add_argument("--output-root", type=Path, default=Path("outputs/paper_eval_20260521/merged"))
    parser.add_argument("--table-dir", type=Path, default=Path("outputs/paper_eval_20260521/tables"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    groups = _find_groups(args.input_root)
    if not groups:
        raise FileNotFoundError(f"No sandbox_metrics.json files found under {args.input_root}")

    summary_rows: List[Dict[str, Any]] = []
    merged_metrics: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for (model_key, condition), shard_dirs in sorted(groups.items()):
        metrics_list = [_read_json(shard_dir / "sandbox_metrics.json") for shard_dir in shard_dirs]
        output_dir = args.output_root / f"{model_key}_{condition}"
        results_path = _concat_results(shard_dirs, output_dir)
        metrics = _merge_metrics(metrics_list, condition=condition, model_key=model_key)
        _write_json(output_dir / "sandbox_metrics.json", metrics)
        latency = summarize_latency_results(results_path, condition=condition, output_dir=output_dir)
        _write_json(output_dir / "latency_cost.json", latency)
        merged_metrics[(model_key, condition)] = metrics
        summary_rows.append(
            _summary_row(
                model_key=model_key,
                condition=condition,
                output_dir=output_dir,
                metrics=metrics,
                latency=latency,
            )
        )

    args.table_dir.mkdir(parents=True, exist_ok=True)
    _write_json(args.table_dir / "paper_eval_summary.json", summary_rows)
    _write_csv(args.table_dir / "paper_eval_summary.csv", summary_rows)
    _write_csv(
        args.table_dir / "attack_type_breakdown.csv",
        _breakdown_rows(summary_rows, merged_metrics, "by_attack_type"),
    )
    _write_csv(
        args.table_dir / "outcome_category_breakdown.csv",
        _breakdown_rows(summary_rows, merged_metrics, "by_outcome_category"),
    )
    _write_csv(args.table_dir / "chain_penetration_scores.csv", _chain_rows(merged_metrics))
    _write_latex_rows(args.table_dir, summary_rows)
    print(f"Merged {len(groups)} condition/model groups into {args.output_root}")
    print(f"Wrote table exports to {args.table_dir}")


if __name__ == "__main__":
    main()
