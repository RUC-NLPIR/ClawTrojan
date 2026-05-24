"""DASGuard Detect-Attribute-Sanitize defense."""

from .detector import DasGuardDetector
from .embedder import (
    BaseDasGuardEmbedder,
    HashingDasGuardEmbedder,
    SiliconFlowDasGuardEmbedder,
    create_dasguard_embedder,
)
from .scanner import scan_text, scan_workspace
from .schema import DasGuardFinding, SanitizationPatch
from .sanitizer import apply_patch_to_text, build_patch
from .assessment import (
    ACTION_TIER_WEIGHTS,
    DasGuardAssessment,
    DasGuardContext,
    assess_text,
    build_context,
    classify_action_tier,
    review_assessment,
)
from .provenance import (
    ProvenanceGraph,
    ProvenanceNode,
    ProvenanceEdge,
    SpanAttribution,
    UNTRUSTED_LABELS,
)

__all__ = [
    "DasGuardDetector",
    "DasGuardFinding",
    "BaseDasGuardEmbedder",
    "HashingDasGuardEmbedder",
    "SiliconFlowDasGuardEmbedder",
    "SanitizationPatch",
    "DasGuardAssessment",
    "DasGuardContext",
    "ProvenanceGraph",
    "ProvenanceNode",
    "ProvenanceEdge",
    "SpanAttribution",
    "UNTRUSTED_LABELS",
    "ACTION_TIER_WEIGHTS",
    "apply_patch_to_text",
    "assess_text",
    "build_patch",
    "build_context",
    "classify_action_tier",
    "create_dasguard_embedder",
    "review_assessment",
    "scan_text",
    "scan_workspace",
]
