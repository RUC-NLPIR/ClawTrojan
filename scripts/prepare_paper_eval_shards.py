#!/usr/bin/env python3
"""Prepare ClawTrojan paper-eval sample shards and command manifests."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from claw_trojan.loader import load_trojan_env


GPT54 = {
    "model_key": "gpt54",
    "agent_backend": "openai",
    "agent_model": "gpt-5.4",
}
GLM51 = {
    "model_key": "glm51",
    "agent_backend": "siliconflow",
    "agent_model": "Pro/zai-org/GLM-5.1",
}
DS_V4_FLASH = {
    "model_key": "ds_v4_flash",
    "agent_backend": "siliconflow",
    "agent_model": "deepseek-ai/DeepSeek-V4-Flash",
}
MODEL_CONFIGS = {
    "gpt54": GPT54,
    "glm51": GLM51,
    "ds": DS_V4_FLASH,
    "ds_v4_flash": DS_V4_FLASH,
}

CONDITIONS = {
    "no_defense": {"baseline": "no_defense"},
    "clawkeeper": {"baseline": "clawkeeper"},
    "struq": {"baseline": "struq"},
    "melon": {"baseline": "melon"},
    "promptshield_1b": {
        "baseline": "promptshield",
        "promptshield_classifier_path": "http://127.0.0.1:18080",
    },
    "promptshield_8b": {
        "baseline": "promptshield",
        "promptshield_classifier_path": "http://127.0.0.1:18081",
    },
    "camel": {"baseline": "camel"},
    "agentsentry": {"baseline": "agentsentry"},
    "dasguard": {
        "baseline": "dasguard",
        "dynamic_defense": "cross_step_context_only",
    },
    "dasguard_no_cross_step": {
        "baseline": "dasguard",
        "dynamic_defense": "isolated_step",
    },
    "dasguard_no_source_labels": {
        "baseline": "dasguard",
        "dynamic_defense": "cross_step_context_only",
        "dasguard_use_source_labels": False,
    },
    "dasguard_no_embedding_score": {
        "baseline": "dasguard",
        "dynamic_defense": "cross_step_context_only",
        "dasguard_use_embedding": False,
    },
    "dasguard_no_memory_match": {
        "baseline": "dasguard",
        "dynamic_defense": "cross_step_context_only",
        "dasguard_use_memory_context": False,
    },
    "dasguard_rule_only": {
        "baseline": "dasguard",
        "dynamic_defense": "cross_step_context_only",
        "dasguard_use_embedding": False,
        "dasguard_use_memory_context": False,
        "legacy": True,
    },
    "dasguard_block_only": {
        "baseline": "dasguard_block_only",
        "dynamic_defense": "cross_step_context_only",
    },
}


@dataclass
class SampleRecord:
    sample_id: str
    sample_path: str
    env_path: str
    scenario: str
    attack_type: str
    outcome_category: str
    annotation_status: str
    malicious_steps: int
    total_steps: int
    shard: int = -1


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _positive_sample_paths(samples_root: Path) -> Iterable[Path]:
    for path in sorted(samples_root.glob("*/*.json")):
        if path.name.startswith("._"):
            continue
        data = _read_json(path)
        if data.get("attack_type") == "none" or data.get("outcome_category") == "none":
            continue
        yield path


def _load_records(samples_root: Path, envs_root: Path) -> List[SampleRecord]:
    records: List[SampleRecord] = []
    for sample_path in _positive_sample_paths(samples_root):
        data = _read_json(sample_path)
        sample_id = str(data["sample_id"])
        env_path = envs_root / sample_id
        if not env_path.exists():
            raise FileNotFoundError(f"Missing env directory for {sample_id}: {env_path}")
        steps = load_trojan_env(str(env_path))
        records.append(
            SampleRecord(
                sample_id=sample_id,
                sample_path=str(sample_path),
                env_path=str(env_path),
                scenario=str(data.get("scenario", "")),
                attack_type=str(data.get("attack_type", "")),
                outcome_category=str(data.get("outcome_category", "")),
                annotation_status=str(
                    data.get("validation_status")
                    or data.get("annotation_status")
                    or ""
                ),
                malicious_steps=sum(1 for step in steps if step.is_malicious),
                total_steps=len(steps),
            )
        )
    return records


def _assign_shards(records: List[SampleRecord], num_shards: int) -> None:
    loads = [{"samples": 0, "malicious_steps": 0, "total_steps": 0} for _ in range(num_shards)]
    ordered = sorted(records, key=lambda r: (-r.malicious_steps, -r.total_steps, r.sample_id))
    for record in ordered:
        shard = min(
            range(num_shards),
            key=lambda idx: (
                loads[idx]["malicious_steps"],
                loads[idx]["total_steps"],
                loads[idx]["samples"],
                idx,
            ),
        )
        record.shard = shard
        loads[shard]["samples"] += 1
        loads[shard]["malicious_steps"] += record.malicious_steps
        loads[shard]["total_steps"] += record.total_steps


def _record_dict(record: SampleRecord) -> Dict[str, Any]:
    return {
        "sample_id": record.sample_id,
        "sample_path": record.sample_path,
        "env_path": record.env_path,
        "scenario": record.scenario,
        "attack_type": record.attack_type,
        "outcome_category": record.outcome_category,
        "annotation_status": record.annotation_status,
        "malicious_steps": record.malicious_steps,
        "total_steps": record.total_steps,
        "shard": record.shard,
    }


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _reset_dir(path: Path, *, force: bool) -> None:
    if path.exists():
        if not force:
            raise FileExistsError(f"{path} already exists; pass --force to replace it")
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _materialize_shards(
    records: List[SampleRecord],
    output_root: Path,
    *,
    copy_envs: bool,
    force: bool,
    dry_run: bool,
) -> None:
    env_shards = output_root / "env_shards"
    manifests = output_root / "manifests"
    if dry_run:
        return
    _reset_dir(env_shards, force=force)
    manifests.mkdir(parents=True, exist_ok=True)
    for record in records:
        shard_dir = env_shards / f"shard_{record.shard:02d}"
        shard_dir.mkdir(parents=True, exist_ok=True)
        target = shard_dir / record.sample_id
        source = Path(record.env_path).resolve()
        if copy_envs:
            shutil.copytree(source, target)
        else:
            target.symlink_to(source, target_is_directory=True)


def _command_row(
    *,
    output_root: Path,
    model: Dict[str, str],
    condition_name: str,
    condition: Dict[str, Any],
    shard_idx: int,
    max_turns: int,
    trials: int,
    judge_backend: str,
    judge_model: str,
) -> Dict[str, Any]:
    shard_name = f"shard_{shard_idx:02d}"
    envs_root = output_root / "env_shards" / shard_name
    output_dir = output_root / "runs" / model["model_key"] / condition_name / shard_name
    args = [
        "python",
        "run.py",
        "sandbox-eval",
        "--envs-root",
        str(envs_root),
        "--output-dir",
        str(output_dir),
        "--agent-backend",
        model["agent_backend"],
        "--agent-model",
        model["agent_model"],
        "--judge-backend",
        judge_backend,
        "--judge-model",
        judge_model,
        "--max-turns",
        str(max_turns),
        "--trials",
        str(trials),
        "--baseline",
        condition["baseline"],
    ]
    if "dynamic_defense" in condition:
        args.extend(["--dynamic-defense", condition["dynamic_defense"]])
    if condition.get("dasguard_use_source_labels") is False:
        args.append("--dasguard-disable-source-labels")
    if condition.get("dasguard_use_embedding") is False:
        args.append("--dasguard-disable-semantic-score")
    if condition.get("dasguard_use_memory_context") is False:
        args.append("--dasguard-disable-memory-match")
    if "promptshield_classifier_path" in condition:
        args.extend(["--promptshield-classifier-path", condition["promptshield_classifier_path"]])
    return {
        "model_key": model["model_key"],
        "agent_backend": model["agent_backend"],
        "agent_model": model["agent_model"],
        "condition": condition_name,
        "baseline": condition["baseline"],
        "dynamic_defense": condition.get("dynamic_defense", "isolated_step"),
        "dasguard_use_source_labels": condition.get("dasguard_use_source_labels", True),
        "dasguard_use_embedding": condition.get("dasguard_use_embedding", True),
        "dasguard_use_memory_context": condition.get("dasguard_use_memory_context", True),
        "shard": shard_name,
        "envs_root": str(envs_root),
        "output_dir": str(output_dir),
        "command": args,
        "shell": " ".join(args),
    }


def _write_command_manifests(
    output_root: Path,
    *,
    num_shards: int,
    models: List[Dict[str, str]],
    conditions: List[str],
    max_turns: int,
    trials: int,
    judge_backend: str,
    judge_model: str,
    commands_stem: str,
    dry_run: bool,
) -> None:
    rows = [
        _command_row(
            output_root=output_root,
            model=model,
            condition_name=condition_name,
            condition=CONDITIONS[condition_name],
            shard_idx=shard_idx,
            max_turns=max_turns,
            trials=trials,
            judge_backend=judge_backend,
            judge_model=judge_model,
        )
        for model in models
        for condition_name in conditions
        for shard_idx in range(num_shards)
    ]
    if dry_run:
        for row in rows:
            print(row["shell"])
        return
    manifests = output_root / "manifests"
    _write_jsonl(manifests / f"{commands_stem}.jsonl", rows)
    command_script = manifests / f"{commands_stem}.sh"
    with command_script.open("w", encoding="utf-8") as f:
        f.write("#!/usr/bin/env bash\nset -euo pipefail\n\n")
        for row in rows:
            f.write(row["shell"] + "\n")
    command_script.chmod(0o755)


def _write_sample_manifests(records: List[SampleRecord], output_root: Path, num_shards: int) -> None:
    manifests = output_root / "manifests"
    rows = [_record_dict(record) for record in sorted(records, key=lambda r: r.sample_id)]
    _write_jsonl(manifests / "positive_samples.jsonl", rows)
    shard_summary = []
    for shard_idx in range(num_shards):
        shard_rows = [row for row in rows if row["shard"] == shard_idx]
        _write_jsonl(manifests / f"shard_{shard_idx:02d}.jsonl", shard_rows)
        shard_summary.append(
            {
                "shard": f"shard_{shard_idx:02d}",
                "samples": len(shard_rows),
                "malicious_steps": sum(int(row["malicious_steps"]) for row in shard_rows),
                "total_steps": sum(int(row["total_steps"]) for row in shard_rows),
            }
        )
    (manifests / "shard_summary.json").write_text(
        json.dumps(shard_summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples-root", type=Path, default=Path("claw_trojan/samples"))
    parser.add_argument("--envs-root", type=Path, default=Path("claw_trojan/envs"))
    parser.add_argument("--output-root", type=Path, default=Path("outputs/paper_eval_20260521"))
    parser.add_argument("--num-shards", type=int, default=8)
    parser.add_argument("--models", nargs="+", default=["gpt54", "glm51"], choices=sorted(MODEL_CONFIGS))
    parser.add_argument("--conditions", nargs="+", default=list(CONDITIONS))
    parser.add_argument("--commands-stem", default="commands", help="Manifest basename under output-root/manifests")
    parser.add_argument("--max-turns", type=int, default=12)
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--judge-backend", default="rightcodes")
    parser.add_argument("--judge-model", default="gpt-5.4")
    parser.add_argument("--copy-envs", action="store_true", help="Copy env directories instead of symlinking them")
    parser.add_argument("--force", action="store_true", help="Replace existing env_shards directory")
    parser.add_argument("--skip-shards", action="store_true", help="Only write command manifests; leave existing shards intact")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without writing shards/manifests")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.num_shards <= 0:
        raise ValueError("--num-shards must be positive")
    unknown = sorted(set(args.conditions) - set(CONDITIONS))
    if unknown:
        raise ValueError(f"Unknown condition(s): {', '.join(unknown)}")

    records = _load_records(args.samples_root, args.envs_root)
    _assign_shards(records, args.num_shards)
    models = [MODEL_CONFIGS[key] for key in args.models]

    if not args.dry_run and not args.skip_shards:
        args.output_root.mkdir(parents=True, exist_ok=True)
        _materialize_shards(
            records,
            args.output_root,
            copy_envs=args.copy_envs,
            force=args.force,
            dry_run=args.dry_run,
        )
        _write_sample_manifests(records, args.output_root, args.num_shards)
    _write_command_manifests(
        args.output_root,
        num_shards=args.num_shards,
        models=models,
        conditions=args.conditions,
        max_turns=args.max_turns,
        trials=args.trials,
        judge_backend=args.judge_backend,
        judge_model=args.judge_model,
        commands_stem=args.commands_stem,
        dry_run=args.dry_run,
    )
    if not args.dry_run:
        action = "Updated command manifests for" if args.skip_shards else "Wrote"
        print(f"{action} {len(records)} positive samples and {args.num_shards} shards under {args.output_root}")


if __name__ == "__main__":
    main()
