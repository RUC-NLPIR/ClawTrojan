"""DASGuard data model."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DasGuardFinding:
    finding_id: str
    sink_path: str
    span: str
    start: int
    end: int
    sink_class: str
    control_role: str
    source_label: str
    classification: str
    action: str
    risk_score: float
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SanitizationPatch:
    file: str
    action: str
    old_span: str
    new_span: str
    reason: str
    finding_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
