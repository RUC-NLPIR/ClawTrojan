"""Configuration for AgentDojo external validation runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence


PUBLIC_SUITES = ("workspace", "slack", "travel", "banking")
SMOKE_USER_TASKS = ("user_task_0", "user_task_1")
SMOKE_INJECTION_TASKS = ("injection_task_0", "injection_task_1")


@dataclass(frozen=True)
class AgentDojoEvalConfig:
    output_dir: Path
    model: str = "gpt-4o-mini-2024-07-18"
    model_id: Optional[str] = None
    openai_provider: str = "openai"
    benchmark_version: str = "v1.2.2"
    attack: Optional[str] = "important_instructions"
    suites: Sequence[str] = field(default_factory=lambda: ("workspace",))
    conditions: Sequence[str] = field(default_factory=lambda: ("no_defense", "dasguard"))
    user_tasks: Sequence[str] = field(default_factory=lambda: SMOKE_USER_TASKS)
    injection_tasks: Sequence[str] = field(default_factory=lambda: SMOKE_INJECTION_TASKS)
    max_workers: int = 1
    force_rerun: bool = False
    dry_run: bool = False

    def logdir_for(self, condition: str) -> Path:
        return self.output_dir / condition / "runs"
