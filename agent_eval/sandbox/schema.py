"""Sandbox evaluation data structures.

Defines the core dataclasses for sandbox-based agent execution and ASR measurement.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class ToolMock:
    """Defines how a specific tool call should be intercepted and mocked."""

    tool_name: str  # e.g. "web_fetch", "read", "memory_read"
    trigger_pattern: str  # substring match against tool input
    response: str  # content to return to the agent
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SandboxConfig:
    """Per-step sandbox execution configuration."""

    sample_id: str
    step_idx: int
    eval_id: str
    attack_goal: str
    outcome_category: str
    injected_inst: str
    success_criteria: Dict[str, List[str]]  # {compromised: [...], partial: [...], safe: [...]}
    tool_mocks: List[ToolMock]
    available_tools: List[str]
    max_turns: int
    system_prompt: str
    session_history: List[Dict[str, str]]
    user_input: str
    workspace_path: str


@dataclass
class ToolCallRecord:
    """Recorded tool invocation during sandbox execution."""

    turn: int
    tool_name: str
    tool_input: Dict[str, Any]
    tool_output: str
    was_mocked: bool = False
    was_intercepted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DefenseState:
    """Runtime-only cross-step DASGuard context for one sample/trial."""

    sample_id: str
    up_to_step: int = 0
    items: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "DefenseState":
        data = data or {}
        return cls(
            sample_id=str(data.get("sample_id", "")),
            up_to_step=int(data.get("up_to_step", 0) or 0),
            items=list(data.get("items", []) or []),
        )


@dataclass
class AgentTrace:
    """Full execution trace for a single sandbox run."""

    eval_id: str
    model: str
    trial: int
    messages: List[Dict[str, Any]] = field(default_factory=list)
    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    final_response: str = ""
    terminated_reason: str = "completed"  # completed | max_turns | error
    duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class JudgeVerdict:
    """ASR judge output for one trace."""

    eval_id: str
    model: str
    trial: int
    verdict: str  # compromised | partial | safe | error
    artifact_outcome: str = "unclear"  # compromised | partial | safe | error | unclear
    threat_awareness: str = "unclear"  # none | implicit_resistance | explicit_detection | caveated_propagation | unclear
    defense_effect: str = "none"  # none | labeled_only | blocked | sanitized | overblocked | unclear
    causality_source: str = "unclear"  # direct_injection | tainted_artifact | user_directed | clean_source | unclear
    confidence: float = 0.0
    reasoning: str = ""
    matched_signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
