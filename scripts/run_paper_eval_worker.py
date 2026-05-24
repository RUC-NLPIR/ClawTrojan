#!/usr/bin/env python3
"""Run a filtered slice of paper-eval commands from a JSONL manifest."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _matches(row: Dict[str, Any], args: argparse.Namespace) -> bool:
    if args.model_key and row.get("model_key") not in set(args.model_key):
        return False
    if args.condition and row.get("condition") not in set(args.condition):
        return False
    if args.shard and row.get("shard") not in set(args.shard):
        return False
    return True


def _select_worker_rows(rows: Iterable[Dict[str, Any]], worker_id: int, num_workers: int) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    for idx, row in enumerate(rows):
        if idx % num_workers == worker_id:
            selected.append(row)
    return selected


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("outputs/paper_eval_20260521/manifests/commands_no_defense_bases.jsonl"),
    )
    parser.add_argument("--model-key", action="append", help="Filter by model_key; repeatable")
    parser.add_argument("--condition", action="append", help="Filter by condition; repeatable")
    parser.add_argument("--shard", action="append", help="Filter by shard, e.g. shard_00; repeatable")
    parser.add_argument("--worker-id", type=int, default=0)
    parser.add_argument("--num-workers", type=int, default=1)
    parser.add_argument("--max-evals", type=int, default=None, help="Append --max-evals to sandbox-eval commands")
    parser.add_argument("--force-rerun", action="store_true", help="Append --force-rerun to sandbox-eval commands")
    parser.add_argument("--judge-only", action="store_true", help="Append --judge-only to sandbox-eval commands")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.num_workers <= 0:
        raise ValueError("--num-workers must be positive")
    if args.worker_id < 0 or args.worker_id >= args.num_workers:
        raise ValueError("--worker-id must satisfy 0 <= worker-id < num-workers")

    rows = [row for row in _read_jsonl(args.manifest) if _matches(row, args)]
    rows = _select_worker_rows(rows, args.worker_id, args.num_workers)
    print(f"Selected {len(rows)} command(s) from {args.manifest}")
    for row in rows:
        command = list(row["command"])
        if command and command[0] == "python":
            command[0] = sys.executable
        shell = row["shell"]
        if args.max_evals is not None:
            if args.max_evals <= 0:
                raise ValueError("--max-evals must be positive when provided")
            command.extend(["--max-evals", str(args.max_evals)])
            shell = f"{shell} --max-evals {args.max_evals}"
        if args.force_rerun:
            command.append("--force-rerun")
            shell = f"{shell} --force-rerun"
        if args.judge_only:
            command.append("--judge-only")
            shell = f"{shell} --judge-only"
        print(shell)
        if not args.dry_run:
            subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
