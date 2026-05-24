"""Run AgentDojo external validation from this repository."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import AgentDojoEvalConfig
from .metrics import parse_stdout_summary, summarize_records, write_json
from .pipeline_adapters import AGENTDOJO_DASGUARD_STATUS


AGENTDOJO_NATIVE_DEFENSES = {
    "no_defense": None,
    "tool_filter": "tool_filter",
    "transformers_pi_detector": "transformers_pi_detector",
    "spotlighting_with_delimiting": "spotlighting_with_delimiting",
    "repeat_user_prompt": "repeat_user_prompt",
}


class AgentDojoEvaluator:
    def __init__(self, config: AgentDojoEvalConfig):
        self.config = config

    def run(self) -> Dict[str, Any]:
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        records: List[Dict[str, Any]] = []
        if importlib.util.find_spec("agentdojo") is None:
            payload = {
                "status": "blocked",
                "reason": "agentdojo_package_not_installed",
                "install": "pip install agentdojo",
                "config": self._config_dict(),
            }
            write_json(self.config.output_dir / "agentdojo_eval_summary.json", payload)
            return payload

        for condition in self.config.conditions:
            if condition == "dasguard" and self.config.openai_provider != "rightcodes":
                records.append(self._pending_dasguard_record())
                continue
            defense = AGENTDOJO_NATIVE_DEFENSES.get(condition)
            if condition == "dasguard" and self.config.openai_provider == "rightcodes":
                defense = "dasguard"
            elif condition not in AGENTDOJO_NATIVE_DEFENSES:
                records.append({
                    "condition": condition,
                    "status": "skipped",
                    "returncode": 2,
                    "reason": "unsupported_agentdojo_condition",
                })
                continue
            records.append(self._run_condition(condition, defense))

        summary = {
            "status": "completed" if all(record.get("returncode") == 0 for record in records) else "partial",
            "config": self._config_dict(),
            "records": records,
            "summary": summarize_records(records),
        }
        write_json(self.config.output_dir / "agentdojo_eval_summary.json", summary)
        return summary

    def build_command(self, defense: Optional[str]) -> List[str]:
        if self.config.openai_provider in {"rightcodes", "siliconflow"}:
            return self._build_openai_compatible_command(defense)
        cmd = [
            sys.executable,
            "-m",
            "agentdojo.scripts.benchmark",
            "--model",
            self.config.model,
            "--benchmark-version",
            self.config.benchmark_version,
            "--logdir",
            str(self.config.logdir_for("dry_run")),
            "--max-workers",
            str(self.config.max_workers),
        ]
        if self.config.model_id:
            cmd.extend(["--model-id", self.config.model_id])
        for suite in self.config.suites:
            cmd.extend(["-s", suite])
        for user_task in self.config.user_tasks:
            cmd.extend(["-ut", user_task])
        for injection_task in self.config.injection_tasks:
            cmd.extend(["-it", injection_task])
        if self.config.attack:
            cmd.extend(["--attack", self.config.attack])
            cmd.append("--skip-injection-task-utility")
        if defense:
            cmd.extend(["--defense", defense])
        if self.config.force_rerun:
            cmd.append("--force-rerun")
        return cmd

    def _build_openai_compatible_command(self, defense: Optional[str]) -> List[str]:
        cmd = [
            sys.executable,
            "-m",
            "agent_eval.agentdojo.direct_benchmark",
            "--model",
            self.config.model,
            "--base-url",
            self._openai_compatible_base_url(),
            "--api-key-env",
            self._openai_compatible_api_key_env(),
            "--benchmark-version",
            self.config.benchmark_version,
            "--logdir",
            str(self.config.logdir_for("dry_run")),
        ]
        for suite in self.config.suites:
            cmd.extend(["-s", suite])
        for user_task in self.config.user_tasks:
            cmd.extend(["-ut", user_task])
        for injection_task in self.config.injection_tasks:
            cmd.extend(["-it", injection_task])
        if self.config.attack:
            cmd.extend(["--attack", self.config.attack])
            cmd.append("--skip-injection-task-utility")
        if defense:
            cmd.extend(["--defense", defense])
        if self.config.force_rerun:
            cmd.append("--force-rerun")
        return cmd

    def _run_condition(self, condition: str, defense: Optional[str]) -> Dict[str, Any]:
        logdir = self.config.logdir_for(condition)
        cmd = self.build_command(defense)
        cmd[cmd.index(str(self.config.logdir_for("dry_run")))] = str(logdir)
        record: Dict[str, Any] = {
            "condition": condition,
            "defense": defense,
            "command": cmd,
            "logdir": str(logdir),
        }
        if self.config.dry_run:
            record.update({"status": "dry_run", "returncode": 0})
            return record
        completed = subprocess.run(
            cmd,
            cwd=Path.cwd(),
            text=True,
            capture_output=True,
            check=False,
            env=self._subprocess_env(),
        )
        stdout_path = self.config.output_dir / condition / "stdout.txt"
        stderr_path = self.config.output_dir / condition / "stderr.txt"
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(completed.stdout, encoding="utf-8")
        stderr_path.write_text(completed.stderr, encoding="utf-8")
        record.update({
            "status": "completed" if completed.returncode == 0 else "failed",
            "returncode": completed.returncode,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "parsed_stdout": parse_stdout_summary(completed.stdout),
        })
        return record

    def _pending_dasguard_record(self) -> Dict[str, Any]:
        return {
            "condition": "dasguard",
            "status": "pending",
            "returncode": 2,
            "reason": AGENTDOJO_DASGUARD_STATUS,
            "note": (
                "DASGuard runtime-gate helper exists in agent_eval.agentdojo.pipeline_adapters, "
                "but AgentDojo pipeline wiring must be validated against the installed package."
            ),
        }

    def _config_dict(self) -> Dict[str, Any]:
        return {
            "output_dir": str(self.config.output_dir),
            "model": self.config.model,
            "model_id": self.config.model_id,
            "openai_provider": self.config.openai_provider,
            "benchmark_version": self.config.benchmark_version,
            "attack": self.config.attack,
            "suites": list(self.config.suites),
            "conditions": list(self.config.conditions),
            "user_tasks": list(self.config.user_tasks),
            "injection_tasks": list(self.config.injection_tasks),
            "max_workers": self.config.max_workers,
            "force_rerun": self.config.force_rerun,
            "dry_run": self.config.dry_run,
        }

    def _subprocess_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        if self.config.openai_provider == "rightcodes":
            rightcodes_key = env.get("RIGHTCODES_API_KEY")
            if rightcodes_key:
                env["OPENAI_API_KEY"] = rightcodes_key
            env["OPENAI_BASE_URL"] = "https://right.codes/codex/v1"
        elif self.config.openai_provider == "siliconflow":
            siliconflow_key = env.get("SILICONFLOW_API_KEY")
            if siliconflow_key:
                env["OPENAI_API_KEY"] = siliconflow_key
            env["OPENAI_BASE_URL"] = "https://api.siliconflow.cn/v1"
        elif self.config.openai_provider != "openai":
            raise ValueError(f"Unsupported OpenAI-compatible provider: {self.config.openai_provider}")
        return env

    def _openai_compatible_base_url(self) -> str:
        if self.config.openai_provider == "rightcodes":
            return "https://right.codes/codex/v1"
        if self.config.openai_provider == "siliconflow":
            return "https://api.siliconflow.cn/v1"
        raise ValueError(f"Unsupported OpenAI-compatible provider: {self.config.openai_provider}")

    def _openai_compatible_api_key_env(self) -> str:
        if self.config.openai_provider == "rightcodes":
            return "RIGHTCODES_API_KEY"
        if self.config.openai_provider == "siliconflow":
            return "SILICONFLOW_API_KEY"
        raise ValueError(f"Unsupported OpenAI-compatible provider: {self.config.openai_provider}")


def dump_command_preview(config: AgentDojoEvalConfig) -> str:
    evaluator = AgentDojoEvaluator(config)
    commands = []
    for condition in config.conditions:
        defense = AGENTDOJO_NATIVE_DEFENSES.get(condition)
        commands.append({"condition": condition, "command": evaluator.build_command(defense)})
    return json.dumps(commands, indent=2, ensure_ascii=False)
