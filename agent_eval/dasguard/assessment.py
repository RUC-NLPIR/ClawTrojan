"""Unified DASGuard assessment policy.

This module keeps provenance context, action-tier measurement, risk scoring,
and sanitization decisions in one auditable contract. It deliberately consumes
only runtime-observable fields, not benchmark labels.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .embedder import BaseDasGuardEmbedder
from .policy import classify_finding_policy
from .provenance import UNTRUSTED_LABELS
from .reviewer import review_findings
from .sanitizer import build_patch
from .scanner import classify_sink, scan_text
from .schema import DasGuardFinding, SanitizationPatch


ACTION_TIER_WEIGHTS = {
    "L0": 0.00,
    "L1": 0.05,
    "L2": 0.10,
    "L3": 0.25,
    "L4": 0.35,
}


CONTROL_SINK_CLASSES = {
    "memory",
    "agent_instruction",
    "skill",
    "policy",
    "template",
    "external_action",
}

CONTROL_ROLES = {
    "directive",
    "fragment_join",
    "memory_policy",
    "policy_shift",
    "privilege_rule",
    "recipient_rule",
    "template_rule",
}

ACTION_SEVERITY = {
    "preserve": 0,
    "downgrade": 1,
    "require_confirmation": 2,
    "quarantine": 3,
    "delete": 4,
    "block_action": 5,
}

SECRET_PAYLOAD_RE = re.compile(
    r"\b(secret|credential|token|api[_ -]?key|password|private[_ -]?key)\b",
    re.IGNORECASE,
)

SECRET_VALUE_RE = re.compile(
    r"\b(?:secret|credential|token|api[_ -]?key|password|private[_ -]?key)\b"
    r"\s*(?:=|:|is|value)\s*['\"]?[A-Za-z0-9_./+=-]{8,}",
    re.IGNORECASE,
)

SECRET_ACTION_RE = re.compile(
    r"\b(?:reveal|disclose|print|copy|include|send|share|upload|export|leak|exfiltrat)\b"
    r".{0,80}\b(?:secret|credential|token|api[_ -]?key|password|private[_ -]?key)\b",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class DasGuardContext:
    mode: str
    tool_name: str = ""
    sink_path: str = ""
    sink_class: str = ""
    action_tier: str = "L2"
    source_label: str = "workspace_clean"
    authorization: Dict[str, Any] = field(default_factory=dict)
    provenance_matches_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DasGuardAssessment:
    context: DasGuardContext
    findings: List[DasGuardFinding]
    risk_score: float
    decision: str
    patches: List[SanitizationPatch] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "context": self.context.to_dict(),
            "risk_score": self.risk_score,
            "decision": self.decision,
            "findings": [finding.to_dict() for finding in self.findings],
            "patches": [patch.to_dict() for patch in self.patches],
        }


def classify_action_tier(
    *,
    tool_name: str = "",
    sink_path: str = "",
    sink_class: Optional[str] = None,
    source_label: str = "workspace_clean",
    payload: str = "",
) -> str:
    """Classify runtime action risk without benchmark annotations."""
    tool = (tool_name or "").lower()
    active_sink = sink_class or classify_sink(sink_path)
    if tool in {"message", "email", "send_message", "send_email", "feishu_send", "exec"}:
        return "L4"
    if tool in {"delete", "remove", "share"}:
        return "L4"
    if _contains_secret_handling_payload(payload or ""):
        return "L4"
    if active_sink in {"memory", "agent_instruction", "skill", "policy", "template", "final_artifact"}:
        return "L3"
    if tool in {"write", "edit", "memory_write"}:
        return "L2"
    if source_label in UNTRUSTED_LABELS and payload:
        return "L1"
    return "L0"


def build_context(
    *,
    mode: str,
    tool_name: str = "",
    sink_path: str = "",
    source_label: str = "workspace_clean",
    authorization: Optional[Dict[str, Any]] = None,
    provenance_matches_count: int = 0,
    payload: str = "",
) -> DasGuardContext:
    sink_class = classify_sink(sink_path)
    action_tier = classify_action_tier(
        tool_name=tool_name,
        sink_path=sink_path,
        sink_class=sink_class,
        source_label=source_label,
        payload=payload,
    )
    return DasGuardContext(
        mode=mode,
        tool_name=tool_name,
        sink_path=sink_path,
        sink_class=sink_class,
        action_tier=action_tier,
        source_label=source_label,
        authorization=authorization or {"status": "not_required"},
        provenance_matches_count=provenance_matches_count,
    )


def assess_text(
    text: str,
    *,
    context: DasGuardContext,
    finding_prefix: str = "das",
    memory_context: Optional[List[Dict[str, Any]]] = None,
    embedder: Optional[BaseDasGuardEmbedder] = None,
    use_embedding: bool = True,
) -> DasGuardAssessment:
    findings = scan_text(
        text,
        sink_path=context.sink_path,
        source_label=context.source_label,
        finding_prefix=finding_prefix,
        use_embedding=use_embedding,
        memory_context=memory_context,
        embedder=embedder,
    )
    adjusted = [
        _adjust_finding_for_context(finding, context)
        for finding in findings
    ]
    actionable = [finding for finding in adjusted if finding.action != "preserve"]
    risk = max((finding.risk_score for finding in adjusted), default=0.0)
    patches = [build_patch(finding) for finding in actionable]
    decision = _decision_for_context(context, actionable)
    return DasGuardAssessment(
        context=context,
        findings=adjusted,
        risk_score=risk,
        decision=decision,
        patches=patches,
    )


def review_assessment(
    assessment: DasGuardAssessment,
    *,
    llm_client: Any,
) -> DasGuardAssessment:
    """Apply optional LLM review and recompute derived assessment fields."""
    review_findings(assessment.findings, llm_client=llm_client)
    _apply_review_recommendations(assessment)
    actionable = [finding for finding in assessment.findings if finding.action != "preserve"]
    assessment.risk_score = max((finding.risk_score for finding in assessment.findings), default=0.0)
    assessment.patches = [build_patch(finding) for finding in actionable]
    assessment.decision = _decision_for_context(assessment.context, actionable)
    return assessment


def _apply_review_recommendations(assessment: DasGuardAssessment) -> None:
    for finding in assessment.findings:
        recommendation = finding.metadata.get("llm_review_recommendation")
        if not isinstance(recommendation, dict):
            continue
        original = {
            "classification": finding.classification,
            "action": finding.action,
            "risk_score": finding.risk_score,
        }
        applied: Dict[str, Any] = {}
        rejected: Dict[str, str] = {}

        proposed_risk = recommendation.get("risk_score")
        if isinstance(proposed_risk, (int, float)):
            proposed_risk = max(0.0, min(float(proposed_risk), 1.0))
            if _review_risk_allowed(
                context=assessment.context,
                finding=finding,
                original_risk=finding.risk_score,
                proposed_risk=proposed_risk,
            ):
                finding.risk_score = proposed_risk
                applied["risk_score"] = proposed_risk
            else:
                rejected["risk_score"] = "policy_engine_rejected_review_downgrade"

        if "risk_score" in applied:
            finding.classification, finding.action = _classify_adjusted(
                finding.risk_score,
                assessment.context,
                finding.sink_class,
                finding.control_role,
                finding.metadata.get("regex_roles", []),
            )

        proposed_classification = recommendation.get("classification")
        if isinstance(proposed_classification, str):
            if _review_classification_allowed(
                context=assessment.context,
                finding=finding,
                proposed_classification=proposed_classification,
            ):
                finding.classification = proposed_classification
                applied["classification"] = proposed_classification
            else:
                rejected["classification"] = "policy_engine_rejected_review_classification"

        proposed_action = recommendation.get("action")
        if isinstance(proposed_action, str):
            if _review_action_allowed(
                context=assessment.context,
                finding=finding,
                original_action=original["action"],
                proposed_action=proposed_action,
            ):
                finding.action = proposed_action
                applied["action"] = proposed_action
            else:
                rejected["action"] = "policy_engine_rejected_review_action"

        finding.metadata["llm_review_original_policy"] = original
        finding.metadata["llm_review_applied_fields"] = applied
        finding.metadata["llm_review_rejected_fields"] = rejected
        finding.metadata["policy_after_review"] = {
            "classification": finding.classification,
            "action": finding.action,
            "risk_score": finding.risk_score,
        }


def _review_classification_allowed(
    *,
    context: DasGuardContext,
    finding: DasGuardFinding,
    proposed_classification: str,
) -> bool:
    if _review_downgrade_protected(context, finding):
        protected = {"persistent_backdoor", "contaminated_control"}
        if finding.classification in protected and proposed_classification not in protected:
            return False
    return True


def _review_action_allowed(
    *,
    context: DasGuardContext,
    finding: DasGuardFinding,
    original_action: str,
    proposed_action: str,
) -> bool:
    if proposed_action not in ACTION_SEVERITY:
        return False
    if not _review_downgrade_protected(context, finding):
        return True
    return ACTION_SEVERITY[proposed_action] >= ACTION_SEVERITY.get(original_action, 0)


def _review_risk_allowed(
    *,
    context: DasGuardContext,
    finding: DasGuardFinding,
    original_risk: float,
    proposed_risk: float,
) -> bool:
    if not _review_downgrade_protected(context, finding):
        return True
    return proposed_risk >= original_risk


def _review_downgrade_protected(context: DasGuardContext, finding: DasGuardFinding) -> bool:
    """Return true for runtime gates where LLM review cannot weaken enforcement."""
    if context.mode != "runtime":
        return False
    if context.action_tier == "L4":
        return True
    if finding.sink_class == "external_action":
        return True
    if finding.control_role in {"recipient_rule", "privilege_rule"}:
        return finding.sink_class in CONTROL_SINK_CLASSES
    if finding.action == "block_action":
        return True
    return False


def _adjust_finding_for_context(
    finding: DasGuardFinding,
    context: DasGuardContext,
) -> DasGuardFinding:
    finding.metadata.setdefault("dasguard_context", context.to_dict())
    finding.metadata["action_tier"] = context.action_tier
    finding.metadata["authorization"] = context.authorization
    finding.metadata["provenance_matches_count"] = context.provenance_matches_count
    if context.authorization.get("status") in {"ambiguous", "needs_semantic_review"}:
        reasons = list(finding.metadata.get("llm_review_reasons", []))
        if "authorization" not in reasons:
            reasons.append("authorization")
        finding.metadata["llm_review_reasons"] = reasons
        finding.metadata["llm_review_recommended"] = True

    if _is_authorized_or_trusted(context, finding):
        finding.classification = "authorized_control"
        finding.action = "preserve"
        return finding

    if _is_local_review_artifact_context(context):
        finding.classification = "local_artifact_reference"
        finding.action = "preserve"
        finding.metadata["local_artifact_preserve_reason"] = (
            "ordinary workspace review/draft artifact; not a control sink"
        )
        return finding

    if _is_harmless_preference_artifact_context(context):
        finding.classification = "local_preference_reference"
        finding.action = "preserve"
        finding.metadata["local_artifact_preserve_reason"] = (
            "harmless formatting preference artifact; no affirmative external/action sink"
        )
        return finding

    increment = 0.0
    if context.source_label in UNTRUSTED_LABELS:
        increment += ACTION_TIER_WEIGHTS.get(context.action_tier, 0.0)
    if context.authorization.get("status") == "not_user_authorized":
        increment += 0.15
    if context.provenance_matches_count:
        increment += 0.05

    if increment:
        finding.risk_score = min(1.0, finding.risk_score + increment)
    finding.classification, finding.action = _classify_adjusted(
        finding.risk_score,
        context,
        finding.sink_class,
        finding.control_role,
        finding.metadata.get("regex_roles", []),
    )
    return finding


def _is_authorized_or_trusted(context: DasGuardContext, finding: DasGuardFinding) -> bool:
    if context.authorization.get("status") == "authorized":
        return True
    if context.source_label in {"trusted_user", "trusted_system"}:
        return True
    if finding.source_label in {"trusted_user", "trusted_system"}:
        return True
    return False


def _contains_secret_handling_payload(payload: str) -> bool:
    """Treat secret references as L4 only when the payload handles or exposes them."""
    return bool(SECRET_VALUE_RE.search(payload or "") or SECRET_ACTION_RE.search(payload or ""))


def _is_local_review_artifact_context(context: DasGuardContext) -> bool:
    """Allow local review documents to quote control language without rewriting them."""
    if context.mode != "runtime":
        return False
    if context.tool_name not in {"write", "edit"}:
        return False
    if context.source_label in {"tool_untrusted", "external_source", "skill_metadata", "memory_persistent"}:
        return False
    if context.action_tier == "L4":
        return False
    if context.sink_class not in {"ordinary_file", "final_artifact", "policy"}:
        return False
    path = context.sink_path.replace("\\", "/").lower()
    if not path.endswith((".md", ".txt", ".json", ".yaml", ".yml")):
        return False
    if path.startswith("external_action/") or "/external_action/" in path:
        return False
    local_runbook_draft = (
        "/runbooks/" in f"/{path}"
        and path.endswith((".md", ".txt"))
        and any(marker in path for marker in ("draft", "review", "packet", "pending"))
    )
    local_policy_review_packet = (
        any(part in f"/{path}" for part in ("/outbox/", "/review/", "/reports/"))
        and path.endswith((".md", ".txt"))
        and any(marker in path for marker in ("draft", "review", "packet", "pending", "report"))
    )
    if context.sink_class == "policy" and not (local_runbook_draft or local_policy_review_packet):
        return False
    local_artifact_dirs = (
        "/drafts/",
        "/review/",
        "/outbox/",
        "/reports/",
    )
    local_artifact = any(part in f"/{path}" for part in local_artifact_dirs)
    if not local_artifact:
        local_artifact = (
            "/state/" in f"/{path}"
            and path.endswith(".json")
            and any(marker in path for marker in ("review", "draft", "pending"))
        )
    if not local_artifact:
        local_artifact = local_runbook_draft
    if not local_artifact:
        return False

    authorization = context.authorization or {}
    proposed = authorization.get("proposed_action_facts") or {}
    if proposed.get("recipients"):
        return False
    actions = set(proposed.get("actions", []) or [])
    negatives = set(proposed.get("negative_constraints", []) or [])
    trusted_negative_conflicts = set(authorization.get("negative_conflicts", []) or [])
    affirmative_actions = actions - negatives - trusted_negative_conflicts
    dangerous_actions = {
        "external.message",
        "external.share",
        "shell.exec",
        "filesystem.delete",
        "memory.write",
    }
    if affirmative_actions.intersection(dangerous_actions):
        return False
    if "secret.handling" in affirmative_actions and context.sink_class in CONTROL_SINK_CLASSES:
        return False
    return True


def _is_harmless_preference_artifact_context(context: DasGuardContext) -> bool:
    """Preserve explicit local formatting preferences without weakening control sinks."""
    if context.mode != "runtime":
        return False
    if context.tool_name not in {"write", "edit"}:
        return False
    if context.action_tier == "L4":
        return False
    if context.sink_class not in {"memory", "final_artifact", "ordinary_file"}:
        return False
    path = context.sink_path.replace("\\", "/").lower()
    if not path.endswith((".md", ".txt")):
        return False
    if "preference" not in path and path not in {"memory/user_prefs.md", "user_prefs.md"}:
        return False

    authorization = context.authorization or {}
    proposed = authorization.get("proposed_action_facts") or {}
    if proposed.get("recipients"):
        return False
    actions = set(proposed.get("actions", []) or [])
    negatives = set(proposed.get("negative_constraints", []) or [])
    affirmative_actions = actions - negatives
    dangerous_actions = {
        "external.message",
        "external.share",
        "shell.exec",
        "filesystem.delete",
        "secret.handling",
    }
    if affirmative_actions.intersection(dangerous_actions):
        return False

    topics = set(proposed.get("topics", []) or [])
    preference_topics = {"formatting", "preference", "preferences", "status", "notes", "compact", "table"}
    return bool(topics.intersection(preference_topics))


def _classify_adjusted(
    risk_score: float,
    context: DasGuardContext,
    sink_class: str,
    control_role: str,
    regex_roles: List[str],
) -> tuple[str, str]:
    skill_guard = context.authorization.get("skill_supply_chain_guard") or {}
    return classify_finding_policy(
        risk_score=risk_score,
        source_label=context.source_label,
        sink_class=sink_class,
        control_role=control_role,
        mode=context.mode,
        action_tier=context.action_tier,
        authorization_status=str(context.authorization.get("status", "not_required")),
        regex_roles=regex_roles,
        missing_capabilities=skill_guard.get("missing_capabilities") or [],
    )


def _decision_for_context(
    context: DasGuardContext,
    actionable: List[DasGuardFinding],
) -> str:
    if not actionable:
        return "commit" if context.mode == "runtime" else "preserve"
    if any(finding.action == "block_action" for finding in actionable):
        return "block"
    if context.mode == "runtime":
        if context.action_tier == "L4":
            return "block"
        return "sanitize_commit"
    return "patch"
