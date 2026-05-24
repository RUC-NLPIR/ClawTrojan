"""Tool dispatcher for sandbox execution.

Routes agent tool calls through mock responses, isolated file operations,
or interception based on tool category and injection configuration.
"""

from __future__ import annotations

import json
import difflib
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from .baselines import SandboxBaseline
from .schema import ToolCallRecord, ToolMock

# Tools that operate on the workspace filesystem
_READ_TOOLS = {"read", "read_file", "ls", "glob", "grep"}
_WRITE_TOOLS = {"write", "edit"}
_MEMORY_TOOLS = {"memory_read", "memory_write", "memory_search"}
# Tools that send data externally — intercepted and logged
_EXTERNAL_TOOLS = {"message", "email", "send_message", "send_email", "feishu_send"}
# Dangerous tools — blocked entirely
_BLOCKED_TOOLS = {"exec", "bash", "shell"}


class PathEscapeError(Exception):
    """Raised when a tool attempts to access paths outside the workspace."""


class ToolDispatcher:
    """Routes tool calls to mocks, isolated workspace ops, or interception."""

    def __init__(
        self,
        tool_mocks: List[ToolMock],
        workspace_root: Path,
        audit_log: List[ToolCallRecord],
        baseline: Optional[SandboxBaseline] = None,
    ):
        self.mocks = tool_mocks
        self.workspace = workspace_root.resolve()
        self.audit = audit_log
        self.baseline = baseline or SandboxBaseline("no_defense")
        self._turn = 0
        self._pending_baseline_metadata: Dict[str, Any] = {}

    def set_turn(self, turn: int) -> None:
        self._turn = turn

    def dispatch(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        """Route a tool call and return the result string."""
        baseline_decision = self.baseline.pre_tool_decision(tool_name, tool_input)
        self._pending_baseline_metadata = baseline_decision.metadata or {}
        if baseline_decision.blocked:
            result = self.baseline._blocked_result(
                baseline_decision.reason,
                baseline_decision.metadata,
            )
            self._record(
                tool_name,
                tool_input,
                result,
                was_intercepted=True,
                metadata=baseline_decision.metadata or {},
            )
            self._pending_baseline_metadata = {}
            return result

        # 1. Check blocked tools first
        if tool_name in _BLOCKED_TOOLS:
            return self._handle_blocked(tool_name, tool_input)

        # 2. Check mocks (highest priority for matching tools)
        mock = self._find_mock(tool_name, tool_input)
        if mock is not None:
            return self._handle_mock(tool_name, tool_input, mock)

        # 3. Route by tool category
        if tool_name in _EXTERNAL_TOOLS:
            return self._handle_external(tool_name, tool_input)

        if tool_name in _MEMORY_TOOLS:
            return self._handle_memory(tool_name, tool_input)

        if tool_name in _READ_TOOLS:
            return self._handle_read(tool_name, tool_input)

        if tool_name in _WRITE_TOOLS:
            return self._handle_write(tool_name, tool_input)

        if tool_name in {"web_search", "web_fetch"}:
            return self._handle_web_fallback(tool_name, tool_input)

        # Unknown tool
        result = f"Error: unknown tool '{tool_name}'"
        self._record(tool_name, tool_input, result, was_mocked=False, was_intercepted=False)
        return result

    # ── Mock handling ──────────────────────────────────────────────

    def _find_mock(self, tool_name: str, tool_input: Dict[str, Any]) -> Optional[ToolMock]:
        """Find a matching mock by tool name + trigger substring."""
        input_str = json.dumps(tool_input, ensure_ascii=False)
        for mock in self.mocks:
            if mock.tool_name == tool_name and mock.trigger_pattern in input_str:
                return mock
        # Fallback: if only one mock exists for this tool_name, use it
        name_matches = [m for m in self.mocks if m.tool_name == tool_name]
        if len(name_matches) == 1:
            return name_matches[0]
        return None

    def _handle_mock(
        self, tool_name: str, tool_input: Dict[str, Any], mock: ToolMock
    ) -> str:
        logger.debug(f"Mock hit: {tool_name} trigger='{mock.trigger_pattern[:50]}'")
        result = self.baseline.filter_tool_output(
            tool_name, tool_input, mock.response, source="mock"
        )
        metadata = self.baseline.consume_filter_metadata()
        metadata.update({
            "mock_provenance": {
                "source": "mock",
                "trigger_pattern": mock.trigger_pattern,
                **(mock.metadata or {}),
            }
        })
        self._record(
            tool_name,
            tool_input,
            result,
            was_mocked=True,
            metadata=metadata,
        )
        return result

    # ── Blocked tools ──────────────────────────────────────────────

    def _handle_blocked(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        result = f"Error: '{tool_name}' is disabled in sandbox mode."
        self._record(tool_name, tool_input, result, was_intercepted=True)
        return result

    # ── External tools (intercept and log) ─────────────────────────

    def _handle_external(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        recipient = tool_input.get("recipient", tool_input.get("to", "unknown"))
        logger.info(f"Intercepted external action: {tool_name} → {recipient}")
        result = "Message sent successfully."
        self._record(tool_name, tool_input, result, was_intercepted=True)
        return result

    # ── Memory tools ───────────────────────────────────────────────

    def _handle_memory(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        path_key = tool_input.get("path", tool_input.get("file", ""))
        # Normalize: ensure it's under memory/
        if not path_key.startswith("memory/"):
            path_key = f"memory/{path_key}"

        if tool_name in {"memory_read", "memory_search"}:
            return self._handle_read("read", {"path": path_key})
        else:  # memory_write
            content = tool_input.get("content", "")
            return self._handle_write("write", {"path": path_key, "content": content})

    # ── File read tools ────────────────────────────────────────────

    def _handle_read(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        path_str = tool_input.get("path", tool_input.get("file", ""))
        if not path_str:
            result = "Error: no path provided"
            self._record(tool_name, tool_input, result)
            return result

        try:
            resolved = self._validate_path(path_str)
        except PathEscapeError as e:
            result = f"Error: {e}"
            self._record(tool_name, tool_input, result)
            return result

        if tool_name == "ls":
            return self._do_ls(tool_name, tool_input, resolved)
        elif tool_name == "glob":
            return self._do_glob(tool_name, tool_input, path_str)
        elif tool_name == "grep":
            return self._do_grep(tool_name, tool_input, path_str)

        # Default: read file content
        if not resolved.exists():
            result = f"Error: file not found: {path_str}"
            self._record(tool_name, tool_input, result)
            return result
        if resolved.is_dir():
            result = f"Error: '{path_str}' is a directory, not a file"
            self._record(tool_name, tool_input, result)
            return result

        try:
            result = resolved.read_text(encoding="utf-8")
        except Exception as e:
            result = f"Error reading file: {e}"
        result = self.baseline.filter_tool_output(
            tool_name, tool_input, result, source="read"
        )
        self._record(
            tool_name,
            tool_input,
            result,
            metadata=self.baseline.consume_filter_metadata(),
        )
        return result

    def _do_ls(self, tool_name: str, tool_input: Dict[str, Any], resolved: Path) -> str:
        if not resolved.exists():
            result = f"Error: directory not found"
        elif resolved.is_file():
            result = resolved.name
        else:
            entries = sorted(p.name + ("/" if p.is_dir() else "") for p in resolved.iterdir())
            result = "\n".join(entries) if entries else "(empty directory)"
        self._record(tool_name, tool_input, result)
        return result

    def _do_glob(self, tool_name: str, tool_input: Dict[str, Any], pattern: str) -> str:
        matches = sorted(str(p.relative_to(self.workspace)) for p in self.workspace.glob(pattern))
        result = "\n".join(matches[:50]) if matches else "No matches found"
        self._record(tool_name, tool_input, result)
        return result

    def _do_grep(self, tool_name: str, tool_input: Dict[str, Any], path_str: str) -> str:
        query = tool_input.get("query", tool_input.get("pattern", ""))
        if not query:
            result = "Error: no search query provided"
            self._record(tool_name, tool_input, result)
            return result
        matches = []
        search_path = self._validate_path(path_str) if path_str else self.workspace
        for f in search_path.rglob("*"):
            if f.is_file():
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                    for i, line in enumerate(text.splitlines(), 1):
                        if query in line:
                            rel = f.relative_to(self.workspace)
                            matches.append(f"{rel}:{i}: {line.strip()}")
                except Exception:
                    continue
        result = "\n".join(matches[:50]) if matches else "No matches found"
        self._record(tool_name, tool_input, result)
        return result

    # ── File write tools ───────────────────────────────────────────

    def _handle_write(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        path_str = tool_input.get("path", tool_input.get("file", ""))
        if not path_str:
            result = "Error: no path provided"
            self._record(tool_name, tool_input, result)
            return result

        try:
            resolved = self._validate_path(path_str)
        except PathEscapeError as e:
            result = f"Error: {e}"
            self._record(tool_name, tool_input, result)
            return result

        try:
            old_text = ""
            if resolved.exists() and resolved.is_file():
                old_text = resolved.read_text(encoding="utf-8")
            if tool_name == "edit":
                old_part = str(tool_input.get("old_text", ""))
                new_part = str(tool_input.get("new_text", ""))
                if not old_part:
                    result = "Error: edit requires old_text"
                    self._record(tool_name, tool_input, result)
                    return result
                if old_part not in old_text:
                    result = f"Error: old_text not found in {path_str}"
                    self._record(tool_name, tool_input, result)
                    return result
                content = old_text.replace(old_part, new_part, 1)
            else:
                content = str(tool_input.get("content", ""))

            metadata: Dict[str, Any] = {}
            if self.baseline.is_dasguard:
                shadow_text, diff = self._build_shadow_write(path_str, old_text, content)
                decision = self.baseline.dasguard_shadow_write_decision(
                    tool_name=tool_name,
                    tool_input=tool_input,
                    sink_path=path_str,
                    old_text=old_text,
                    new_text=shadow_text,
                    diff=diff,
                )
                metadata = decision.metadata or {}
                gate = metadata.get("dasguard_shadow_gate", {})
                if decision.blocked:
                    result = self.baseline._blocked_result(decision.reason, metadata)
                    self._record(
                        tool_name,
                        tool_input,
                        result,
                        was_intercepted=True,
                        metadata=metadata,
                    )
                    return result
                if gate.get("decision") == "sanitize_commit":
                    content = str(gate.get("sanitized_content", content))

            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(content, encoding="utf-8")
            if metadata.get("dasguard_shadow_gate", {}).get("decision") == "sanitize_commit":
                result = f"Successfully wrote sanitized content to {path_str}"
            else:
                result = f"Successfully wrote to {path_str}"
        except Exception as e:
            result = f"Error writing file: {e}"
            metadata = {}
        self._record(tool_name, tool_input, result, metadata=metadata)
        return result

    @staticmethod
    def _build_shadow_diff(path_str: str, old_text: str, new_text: str) -> str:
        old_lines = old_text.splitlines(keepends=True)
        new_lines = new_text.splitlines(keepends=True)
        return "".join(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"a/{path_str}",
                tofile=f"b/{path_str}",
            )
        )

    def _build_shadow_write(
        self,
        path_str: str,
        old_text: str,
        candidate_text: str,
    ) -> tuple[str, str]:
        with tempfile.TemporaryDirectory(prefix="dasguard_shadow_") as tmpdir:
            shadow_root = Path(tmpdir) / "workspace"
            shutil.copytree(self.workspace, shadow_root, dirs_exist_ok=True)
            shadow_target = (shadow_root / path_str.lstrip("/")).resolve()
            if not str(shadow_target).startswith(str(shadow_root.resolve())):
                raise PathEscapeError(f"Path escapes shadow workspace: {path_str}")
            shadow_target.parent.mkdir(parents=True, exist_ok=True)
            shadow_target.write_text(candidate_text, encoding="utf-8")
            shadow_text = shadow_target.read_text(encoding="utf-8")
        return shadow_text, self._build_shadow_diff(path_str, old_text, shadow_text)

    # ── Web fallback ───────────────────────────────────────────────

    def _handle_web_fallback(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        result = "No results found."
        result = self.baseline.filter_tool_output(
            tool_name, tool_input, result, source="web"
        )
        self._record(
            tool_name,
            tool_input,
            result,
            metadata=self.baseline.consume_filter_metadata(),
        )
        return result

    # ── Path validation ────────────────────────────────────────────

    def _validate_path(self, relative_path: str) -> Path:
        """Resolve a path within the workspace, rejecting escapes."""
        # Strip leading slashes and normalize
        clean = relative_path.lstrip("/")
        resolved = (self.workspace / clean).resolve()
        if not str(resolved).startswith(str(self.workspace)):
            raise PathEscapeError(f"Path escapes workspace: {relative_path}")
        return resolved

    # ── Audit recording ────────────────────────────────────────────

    def _record(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        tool_output: str,
        was_mocked: bool = False,
        was_intercepted: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.audit.append(
            ToolCallRecord(
                turn=self._turn,
                tool_name=tool_name,
                tool_input=tool_input,
                tool_output=tool_output,
                was_mocked=was_mocked,
                was_intercepted=was_intercepted,
                metadata=metadata or self._pending_baseline_metadata or {},
            )
        )
        self._pending_baseline_metadata = {}
