"""Sandbox runner — process-level isolated agent execution.

Copies workspace to a temp directory, runs the agent loop with tool dispatch,
and captures workspace diffs for auditing.
"""

from __future__ import annotations

import difflib
import filecmp
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

from loguru import logger

from agent_eval.llm_client import BaseLLMClient

from .agent_loop import AgentLoop, create_tool_use_client, resolve_tool_names, TOOL_SCHEMAS
from .baselines import BaselineModelConfig, SandboxBaseline
from .schema import AgentTrace, SandboxConfig, ToolCallRecord
from .tool_dispatcher import ToolDispatcher


def _build_tool_defs(available_tools: List[str]) -> List[Dict[str, Any]]:
    """Build tool definition list for the LLM from available_tools config."""
    tool_names = resolve_tool_names(available_tools)
    defs = []
    for name in tool_names:
        if name in TOOL_SCHEMAS:
            schema = TOOL_SCHEMAS[name]
            defs.append({
                "name": name,
                "description": schema["description"],
                "parameters": schema["parameters"],
            })
    return defs


def capture_workspace_diff(original: Path, modified: Path) -> Dict[str, Any]:
    """Compute diff between original and post-execution workspace.

    Returns:
        Dict with added_files, modified_files (with diffs), deleted_files
    """
    result: Dict[str, Any] = {"added": [], "modified": [], "deleted": []}

    if not original.exists() or not modified.exists():
        return result

    _diff_dirs(original, modified, original, modified, result)
    return result


def _diff_dirs(
    orig_root: Path,
    mod_root: Path,
    orig_dir: Path,
    mod_dir: Path,
    result: Dict[str, Any],
) -> None:
    """Recursively diff two directory trees."""
    dcmp = filecmp.dircmp(str(orig_dir), str(mod_dir))

    # Files only in modified (added) — recurse into new directories
    for name in dcmp.right_only:
        item = mod_dir / name
        rel = str(item.relative_to(mod_root))
        if item.is_dir():
            for f in sorted(item.rglob("*")):
                if f.is_file():
                    frel = str(f.relative_to(mod_root))
                    try:
                        content = f.read_text(encoding="utf-8")
                    except Exception:
                        content = "(binary or unreadable)"
                    result["added"].append({"path": frel, "content": content})
        else:
            try:
                content = item.read_text(encoding="utf-8")
            except Exception:
                content = "(binary or unreadable)"
            result["added"].append({"path": rel, "content": content})

    # Files only in original (deleted)
    for name in dcmp.left_only:
        rel = str((orig_dir / name).relative_to(orig_root))
        result["deleted"].append(rel)

    # Files that differ
    for name in dcmp.diff_files:
        rel = str((orig_dir / name).relative_to(orig_root))
        orig_file = orig_dir / name
        mod_file = mod_dir / name
        try:
            orig_lines = orig_file.read_text(encoding="utf-8").splitlines(keepends=True)
            mod_lines = mod_file.read_text(encoding="utf-8").splitlines(keepends=True)
            diff = list(difflib.unified_diff(orig_lines, mod_lines, fromfile=f"a/{rel}", tofile=f"b/{rel}"))
            result["modified"].append({"path": rel, "diff": "".join(diff)})
        except Exception:
            result["modified"].append({"path": rel, "diff": "(binary or unreadable)"})

    # Recurse into common subdirectories
    for sub in dcmp.common_dirs:
        _diff_dirs(orig_root, mod_root, orig_dir / sub, mod_dir / sub, result)


class SandboxRunner:
    """Process-level isolated sandbox for agent execution."""

    def __init__(
        self,
        config: SandboxConfig,
        backend: str = "openai",
        model: str = "gpt-4o-mini",
        baseline: str = "no_defense",
        baseline_model_config: BaselineModelConfig | None = None,
        dasguard_llm_client: BaseLLMClient | None = None,
    ):
        self.config = config
        self.backend = backend
        self.model = model
        self.baseline = SandboxBaseline(
            baseline,
            model_config=baseline_model_config,
            dasguard_llm_client=dasguard_llm_client,
        )

    def run_trial(
        self,
        trial: int = 0,
        prior_defense_state: Dict[str, Any] | None = None,
    ) -> Tuple[AgentTrace, List[ToolCallRecord], Dict[str, Any]]:
        """Execute one sandboxed agent run.

        Returns:
            (trace, audit_log, workspace_diff)
        """
        config = self.config

        with tempfile.TemporaryDirectory(prefix="clawshield_sandbox_") as tmpdir:
            workspace_copy = Path(tmpdir) / "workspace"

            if Path(config.workspace_path).exists():
                shutil.copytree(config.workspace_path, workspace_copy)
            else:
                workspace_copy.mkdir(parents=True)
                logger.warning(f"Workspace not found: {config.workspace_path}, using empty dir")

            # Set up dispatcher
            audit_log: List[ToolCallRecord] = []
            dispatcher = ToolDispatcher(
                tool_mocks=config.tool_mocks,
                workspace_root=workspace_copy,
                audit_log=audit_log,
                baseline=self.baseline,
            )

            # Set up agent
            client = create_tool_use_client(self.backend, self.model)
            loop = AgentLoop(client, dispatcher, config.max_turns)

            # Build tool definitions
            tool_defs = _build_tool_defs(config.available_tools)

            logger.info(
                f"Running sandbox: {config.eval_id} | model={self.model} | "
                f"trial={trial} | baseline={self.baseline.name} | "
                f"tools={len(tool_defs)} | mocks={len(config.tool_mocks)}"
            )

            # Run agent
            trace = loop.run(
                system_prompt=self.baseline.wrap_system_prompt(config.system_prompt),
                tools=tool_defs,
                session_history=config.session_history,
                user_input=config.user_input,
                eval_id=config.eval_id,
                model=self.model,
                trial=trial,
                prior_defense_state=prior_defense_state,
                sample_id=config.sample_id,
                step_idx=config.step_idx,
            )

            # Capture workspace changes
            original_workspace = Path(config.workspace_path)
            diff = capture_workspace_diff(original_workspace, workspace_copy)

            logger.info(
                f"Sandbox complete: {config.eval_id} | "
                f"turns={len([m for m in trace.messages if m.get('role') == 'assistant'])} | "
                f"tool_calls={len(audit_log)} | "
                f"reason={trace.terminated_reason} | "
                f"duration={trace.duration_seconds}s"
            )

            return trace, audit_log, diff
