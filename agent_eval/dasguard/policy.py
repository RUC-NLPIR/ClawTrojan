"""Shared DASGuard classification policy."""

from __future__ import annotations

from typing import Iterable


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

TRUSTED_LABELS = {"trusted_user", "trusted_system"}
WORKSPACE_LABELS = {"workspace_clean"}
UNTRUSTED_CONTROL_LABELS = {
    "tool_untrusted",
    "external_source",
    "skill_metadata",
    "memory_persistent",
    "derived_untrusted",
    "compromised_artifact",
}


def classify_finding_policy(
    *,
    risk_score: float,
    source_label: str,
    sink_class: str,
    control_role: str,
    mode: str = "static",
    action_tier: str = "",
    authorization_status: str = "not_required",
    regex_roles: Iterable[str] = (),
    missing_capabilities: Iterable[str] = (),
) -> tuple[str, str]:
    """Return the canonical classification/action pair for a finding.

    This function is intentionally deterministic and shared by static scan,
    cleanup, and runtime gates so threshold behavior cannot drift across paths.
    """
    if authorization_status == "authorized" or source_label in TRUSTED_LABELS:
        return "authorized_control", "preserve"

    if source_label in WORKSPACE_LABELS:
        if risk_score >= 0.85 and sink_class in {
            "memory",
            "agent_instruction",
            "skill",
            "policy",
        }:
            return "candidate_control", "require_confirmation"
        return "authorized_control", "preserve"

    high_risk = risk_score >= 0.80
    if high_risk:
        if _runtime_should_block(
            mode=mode,
            action_tier=action_tier,
            sink_class=sink_class,
            control_role=control_role,
            high_risk=True,
        ):
            return "persistent_backdoor", "block_action"
        if mode in {"cleanup", "static", "static_detect"}:
            return "persistent_backdoor", "delete"
        return "persistent_backdoor", "quarantine"

    if _unauthorized_control_sink(
        sink_class=sink_class,
        control_role=control_role,
        source_label=source_label,
    ):
        if _runtime_should_block(
            mode=mode,
            action_tier=action_tier,
            sink_class=sink_class,
            control_role=control_role,
            high_risk=False,
        ):
            return "persistent_backdoor", "block_action"
        if (
            mode == "cleanup"
            and sink_class == "skill"
            and set(missing_capabilities)
            and control_role in {"recipient_rule", "privilege_rule"}
        ):
            return "persistent_backdoor", "delete"
        return "contaminated_control", "quarantine"

    if sink_class == "memory" and source_label not in TRUSTED_LABELS:
        if control_role in {"recipient_rule", "privilege_rule"} and control_role in set(regex_roles):
            action = "block_action" if mode == "runtime" else "delete"
            return "persistent_backdoor", action
        if control_role in {
            "directive",
            "fragment_join",
            "memory_policy",
            "policy_shift",
            "template_rule",
        }:
            return "contaminated_control", "quarantine"

    if risk_score >= 0.60:
        return "contaminated_control", "quarantine"
    if risk_score >= 0.30:
        return "unsupported_claim", "downgrade"
    if sink_class == "final_artifact" and source_label not in TRUSTED_LABELS:
        return "unsupported_claim", "downgrade"
    return "benign_data", "preserve"


def _unauthorized_control_sink(
    *,
    sink_class: str,
    control_role: str,
    source_label: str,
) -> bool:
    return (
        sink_class in CONTROL_SINK_CLASSES
        and control_role in CONTROL_ROLES
        and source_label not in TRUSTED_LABELS
    )


def _runtime_should_block(
    *,
    mode: str,
    action_tier: str,
    sink_class: str,
    control_role: str,
    high_risk: bool = False,
) -> bool:
    if mode != "runtime":
        return False
    if action_tier == "L4":
        return True
    if sink_class == "external_action":
        return True
    if control_role in {"recipient_rule", "privilege_rule"}:
        return sink_class in CONTROL_SINK_CLASSES or (
            high_risk and sink_class not in {"ordinary_file", "final_artifact"}
        )
    if high_risk and sink_class == "agent_instruction" and control_role in CONTROL_ROLES:
        return True
    return sink_class in {"agent_instruction", "policy"} and control_role in {
        "policy_shift",
        "recipient_rule",
        "privilege_rule",
    }
