#!/usr/bin/env python3
"""Prepare, resume, validate, and merge durable full model/condition evaluations."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
VALID = {"compromised", "partial", "safe"}
ARTIFACTS = ("judge.json", "trace.jsonl", "audit.json", "workspace_diff.json", "trace_metadata.json")


def conditions(config):
    return config.get("conditions", [config["baseline"]])


def bucket_key(config, model, condition):
    return model if len(conditions(config)) == 1 else f"{model}/{condition}"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def valid_results(output, model, expected):
    path = output / "sandbox_results.jsonl"
    if not path.exists():
        return False
    try:
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        if len(rows) != len(expected) or {(r["eval_id"], r["trial"]) for r in rows} != expected:
            return False
        for row in rows:
            if row["verdict"] not in VALID:
                return False
            trial = output / "runs" / model / row["eval_id"] / f"trial_{row['trial']}"
            if not all((trial / name).is_file() for name in ARTIFACTS):
                return False
            metadata = json.loads((trial / "trace_metadata.json").read_text())
            if metadata.get("llm_error") or metadata.get("terminated_reason") == "error" or metadata.get("duration_seconds") is None:
                return False
        return True
    except (ValueError, KeyError, OSError):
        return False


def prepare(config, output):
    from claw_trojan.loader import load_trojan_env
    rows = [json.loads(line) for line in (ROOT / config["positive_manifest"]).read_text().splitlines()]
    assert len(rows) == config["expected_samples"]
    assert len({row["sample_id"] for row in rows}) == len(rows)
    config_path = output / "config.json"
    if config_path.exists() and json.loads(config_path.read_text()) != config:
        raise ValueError("Existing experiment configuration differs; use a new output directory")
    source_paths = [ROOT / 'run.py']
    for directory in ['agent_eval', 'claw_trojan', 'scripts']:
        # Benchmark workspaces contain data, not evaluator source.
        source_paths.extend((ROOT / directory).glob('*.py'))
    source_paths.extend((ROOT / 'agent_eval').glob('**/*.py'))
    code_hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted(set(source_paths))}
    code_path = output / 'code_sha256.json'
    if code_path.exists() and json.loads(code_path.read_text()) != code_hashes:
        raise ValueError('Evaluator source changed; use a new output directory')
    write_json(code_path, code_hashes)
    expected_by_shard = {}
    metadata = []
    source_hashes = {}
    for row in rows:
        shard = f"shard_{row['shard']:02d}"
        source = ROOT / row["env_path"]
        target = output / "env_shards" / shard / row["sample_id"]
        # Keep the evaluation independent of subsequent source-dataset edits.
        if not target.exists():
            staging = target.with_name(target.name + ".preparing")
            if staging.exists():
                shutil.rmtree(staging)
            shutil.copytree(source, staging)
            staging.rename(target)
        for path in sorted(target.rglob("*")):
            if path.is_file():
                source_hashes[str(path.relative_to(output))] = hashlib.sha256(path.read_bytes()).hexdigest()
        steps = [step for step in load_trojan_env(str(target)) if step.is_malicious]
        assert len(steps) == row["malicious_steps"], row["sample_id"]
        expected_by_shard.setdefault(shard, set()).update(
            (step.eval_id, trial) for step in steps for trial in range(config["trials"])
        )
        for step in steps:
            metadata.append({key: getattr(step, key) for key in (
                "eval_id", "sample_id", "step_idx", "outcome_category", "attack_type", "stage_tag", "is_malicious"
            )})
    assert len(metadata) == config["expected_steps_per_model"]
    hash_path = output / "environment_sha256.json"
    if hash_path.exists() and json.loads(hash_path.read_text()) != source_hashes:
        raise ValueError("Frozen experiment environments changed")
    write_json(hash_path, source_hashes)
    write_json(config_path, config)
    write_json(output / "selected_samples.json", rows)
    write_json(output / "step_metadata.json", metadata)
    jobs = []
    # Interleave models so the first twelve workers contain four per model.
    for shard in sorted(expected_by_shard):
        for model in config["agent_models"]:
            for condition in conditions(config):
                directory = output / "runs" / model / condition / shard
                command = [sys.executable, str(ROOT / "run.py"), "sandbox-eval",
                           "--envs-root", str(output / "env_shards" / shard),
                           "--output-dir", str(directory), "--agent-model", model,
                           "--baseline", condition]
                for key in ("agent_backend", "judge_backend", "judge_model", "dynamic_defense", "eval_split", "max_turns", "trials"):
                    command.extend(["--" + key.replace("_", "-"), str(config[key])])
                jobs.append({"model": model, "condition": condition, "shard": shard, "output": str(directory), "command": command,
                             "expected": sorted(expected_by_shard[shard])})
    write_json(output / "commands.json", jobs)
    return jobs


def snapshot(config, output, jobs, states, phase):
    progress = {bucket_key(config, model, condition): {"expected": config["expected_steps_per_model"] * config["trials"],
                        "valid": 0, "invalid": 0, "compromised": 0, "partial": 0, "safe": 0}
                for model in config["agent_models"] for condition in conditions(config)}
    for job in jobs:
        for eval_id, trial in job["expected"]:
            path = Path(job["output"]) / "runs" / job["model"] / eval_id / f"trial_{trial}" / "judge.json"
            try:
                verdict = json.loads(path.read_text())["verdict"]
            except (OSError, ValueError, KeyError):
                continue
            bucket = progress[bucket_key(config, job["model"], job["condition"])]
            if verdict in VALID and all((path.parent / name).is_file() for name in ARTIFACTS):
                bucket["valid"] += 1
                bucket[verdict] += 1
            else:
                bucket["invalid"] += 1
    report = {"phase": phase, "updated_at": datetime.now(timezone.utc).isoformat(),
              "pid": os.getpid(), "models": progress, "jobs": dict(states)}
    write_json(output / "progress.json", report)
    lines = ["# Full evaluation", "", f"Status: **{phase}**", "",
             f"{config['expected_samples']} positive samples; {config['expected_steps_per_model']} malicious steps per model/condition; {config['trials']} trial(s).", "",
             "| Model | Valid / expected | Invalid (pending retry) | Compromised | Partial | Safe |",
             "|---|---:|---:|---:|---:|---:|"]
    for model, row in progress.items():
        lines.append(f"| {model} | {row['valid']}/{row['expected']} | {row['invalid']} | {row['compromised']} | {row['partial']} | {row['safe']} |")
    lines += ["", "Counts are provisional until every expected trial passes completeness checks.",
              "Final results: merged/ and tables/paper_eval_summary.csv. Failures: job_status.json and logs/.", ""]
    (output / "STATUS.md").write_text("\n".join(lines))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/new_models_full_20260920.json")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    os.chdir(ROOT)
    config = json.loads(Path(args.config).read_text())
    output = ROOT / config["output_dir"]
    output.mkdir(parents=True, exist_ok=True)
    lock = (output / "controller.lock").open("w")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    jobs = prepare(config, output)
    states = {f"{bucket_key(config, j['model'], j['condition'])}/{j['shard']}": {"state": "pending"} for j in jobs}
    if args.prepare_only:
        snapshot(config, output, jobs, states, "prepared")
        print(f"Prepared {len(jobs)} jobs; {config['expected_steps_per_model']} steps per model", flush=True)
        return
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
    if not os.environ.get("OPENAI_API_KEY"):
        raise ValueError("OPENAI_API_KEY is required")
    env = dict(os.environ,
               LLM_REQUEST_TIMEOUT_SECONDS=str(config["request_timeout_seconds"]),
               TOKENIZERS_PARALLELISM="false", OMP_NUM_THREADS="1")
    if config.get("base_url"):
        env["OPENAI_BASE_URL"] = config["base_url"]
    if "agentpoison" in conditions(config) and not env.get("AGENTPOISON_QUERY_SCORES"):
        raise ValueError("Run scripts/run_agentpoison_clawtrojan_full.py to prepare frozen query scores first")
    (output / "logs").mkdir(exist_ok=True)
    stop = threading.Event()
    fatal = []

    def run(job):
        key = f"{bucket_key(config, job['model'], job['condition'])}/{job['shard']}"
        directory = Path(job["output"])
        expected = {tuple(pair) for pair in job["expected"]}
        if valid_results(directory, job["model"], expected):
            states[key] = {"state": "complete", "reused": True}
            return True
        log_path = output / "logs" / f"{job['model']}_{job['condition']}_{job['shard']}.log"
        for attempt in range(1, config["max_shard_attempts"] + 1):
            if stop.is_set():
                states[key] = {"state": "stopped", "reason": "systemic API failure"}
                return False
            with log_path.open("ab") as log:
                start_offset = log.tell()
                proc = subprocess.Popen(job["command"], env=env, stdout=log, stderr=subprocess.STDOUT)
                states[key] = {"state": "running", "attempt": attempt, "pid": proc.pid}
                while proc.poll() is None:
                    time.sleep(5)
                    with log_path.open("rb") as reader:
                        reader.seek(start_offset)
                        recent = reader.read().decode(errors="replace")
                        start_offset = reader.tell()
                    if any(term in recent for term in ("insufficient_user_quota", "invalid_api_key", "get_channel_failed")):
                        fatal.append(key)
                        stop.set()
                    if stop.is_set() and proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                exit_code = proc.returncode
            if exit_code == 0 and valid_results(directory, job["model"], expected):
                states[key] = {"state": "complete", "attempt": attempt}
                return True
            states[key] = {"state": "retrying", "attempt": attempt, "exit_code": exit_code}
        states[key] = {"state": "failed", "attempts": config["max_shard_attempts"]}
        return False

    with ThreadPoolExecutor(max_workers=config["concurrency"]) as pool:
        futures = [pool.submit(run, job) for job in jobs]
        while not all(future.done() for future in futures):
            snapshot(config, output, jobs, states, "stopping" if stop.is_set() else "running")
            time.sleep(15)
        completed = [future.result() for future in futures]
    write_json(output / "job_status.json", states)
    if not all(completed):
        write_json(output / "fatal_jobs.json", fatal)
        snapshot(config, output, jobs, states, "needs_attention")
        raise SystemExit("Evaluation incomplete; inspect failed jobs and resume the same command")
    merge = [sys.executable, str(ROOT / "scripts/merge_paper_eval_results.py"),
             "--input-root", str(output / "runs"), "--output-root", str(output / "merged"),
             "--table-dir", str(output / "tables")]
    subprocess.run(merge, check=True)
    for model in config["agent_models"]:
        for condition in conditions(config):
            merged = output / "merged" / f"{model}_{condition}"
            rows = [json.loads(line) for line in (merged / "sandbox_results.jsonl").read_text().splitlines()]
            expected = {tuple(pair) for job in jobs if job["model"] == model and job["condition"] == condition for pair in job["expected"]}
            assert len(rows) == len(expected) and {(r["eval_id"], r["trial"]) for r in rows} == expected
            assert all(row["verdict"] in VALID for row in rows)
            metrics = json.loads((merged / "sandbox_metrics.json").read_text())
            assert metrics["overall"]["invalid"] == 0
            assert len(metrics["per_sample"]) == config["expected_samples"]
    snapshot(config, output, jobs, states, "complete")
    print("COMPLETE: all expected trials are valid; merged tables written", flush=True)


if __name__ == "__main__":
    main()
