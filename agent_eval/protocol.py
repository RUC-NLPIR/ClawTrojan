from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class DetectorDecision:
    sample_id: str
    is_malicious_pred: bool
    risk_score: float
    char_spans_pred: List[Dict[str, int]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyDecision:
    sample_id: str
    action: str
    sanitized_tool_output: str
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SystemResult:
    sample_id: str
    detector: Dict[str, Any]
    policy: Dict[str, Any]
    final_response: str
    task_completed: bool
    injection_followed: bool
    refused: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
