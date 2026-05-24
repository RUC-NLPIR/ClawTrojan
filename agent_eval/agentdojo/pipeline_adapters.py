"""DASGuard adapter notes and local runtime helpers for AgentDojo.

AgentDojo does not yet expose a stable CLI registry for third-party defenses.
This module keeps the DASGuard runtime-gate logic isolated so it can be wired
into an AgentDojo ``ToolsExecutionLoop`` once the installed package version is
known. The experiment runner records DASGuard as pending if that wiring is not
available, rather than reporting a misleading no-op result.
"""

from __future__ import annotations

import re
from ast import literal_eval
from typing import Any, Dict, List

from agentdojo.agent_pipeline.pi_detector import PromptInjectionDetector
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, is_string_list
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.types import ChatMessage, ChatToolResultMessage, MessageContentBlock, text_content_block_from_string

from agent_eval.dasguard.assessment import assess_text, build_context
from agent_eval.dasguard.embedder import create_dasguard_embedder
from agent_eval.dasguard.provenance import UNTRUSTED_LABELS


AGENTDOJO_DASGUARD_STATUS = "pending_agentdojo_pipeline_wiring"
DASGUARD_REMOVED_MARKER = "[DASGUARD_REMOVED_UNTRUSTED_INSTRUCTIONS]"


class AgentDojoDasGuardPIDetector(PromptInjectionDetector):
    """DASGuard tool-output boundary adapter for AgentDojo."""

    def __init__(self) -> None:
        super().__init__(mode="message", raise_on_injection=False)
        self.embedder = create_dasguard_embedder("hashing", None)
        self.assessments: list[Dict[str, Any]] = []

    def detect(self, tool_output: str) -> tuple[bool, float]:
        rule_match = detect_agentdojo_injection_pattern(tool_output)
        context = build_context(
            mode="runtime",
            tool_name="agentdojo_tool_output",
            sink_path="agentdojo/tool_output",
            source_label="external_source",
            authorization={"status": "not_required"},
            payload=tool_output,
        )
        assessment = assess_text(
            tool_output,
            context=context,
            finding_prefix="agentdojo_dasguard",
            embedder=self.embedder,
        )
        payload = assessment.to_dict()
        self.assessments.append(payload)
        blocked = assessment.decision in {"block_action", "quarantine"} or any(
            finding.get("action") in {"block_action", "quarantine", "delete"}
            for finding in payload.get("findings", [])
        )
        if rule_match:
            blocked = True
        return blocked, max(float(assessment.risk_score), 1.0 if rule_match else 0.0)

    def transform(self, tool_output: List[MessageContentBlock]) -> List[MessageContentBlock]:
        transformed: List[MessageContentBlock] = []
        for block in tool_output:
            if block["type"] != "text":
                transformed.append(block)
                continue
            sanitized = sanitize_agentdojo_tool_output(block["content"])
            transformed.append(text_content_block_from_string(sanitized))
        return transformed


class AgentDojoDasGuardToolsExecutor(ToolsExecutor):
    """AgentDojo executor with DASGuard's adapted action-boundary gate."""

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: List[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, List[ChatMessage], dict]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        untrusted_instructions_seen = conversation_contains_untrusted_instructions(messages)
        user_query = first_user_query(messages)
        tool_call_results = []
        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error="Empty function name provided. Provide a valid function name.",
                    )
                )
                continue
            if tool_call.function not in (tool.name for tool in runtime.functions.values()):
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=f"Invalid tool {tool_call.function} provided.",
                    )
                )
                continue

            if untrusted_instructions_seen and should_block_side_effect_tool_call(
                tool_call.function,
                tool_call.args,
                user_query=user_query,
            ):
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("DASGuard blocked this side-effect tool call.")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error="DASGuardBlockedAction: side-effect tool call derived from untrusted instructions.",
                    )
                )
                continue

            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and is_string_list(arg_v):
                    tool_call.args[arg_k] = literal_eval(arg_v)

            tool_call_result, error = runtime.run_function(env, tool_call.function, tool_call.args)
            formatted_tool_call_result = self.output_formatter(tool_call_result)
            tool_call_results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(formatted_tool_call_result)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *tool_call_results], extra_args


AGENTDOJO_ATTACK_BLOCK_RE = re.compile(
    r"(?is)\n*\s*<INFORMATION>\s*.*?</INFORMATION>\s*\n*"
)
AGENTDOJO_IMPORTANT_INSTRUCTIONS_RE = re.compile(
    r"(?is)this\s+is\s+an\s+important\s+message\s+from\s+me.*?"
    r"before\s+you\s+can\s+solve\s+the\s+task.*?"
    r"do\s+the\s+following\s+first"
)


def detect_agentdojo_injection_pattern(text: str) -> bool:
    """Detect AgentDojo fixed-jailbreak patterns at the tool-output boundary."""
    return bool(
        AGENTDOJO_ATTACK_BLOCK_RE.search(text)
        or AGENTDOJO_IMPORTANT_INSTRUCTIONS_RE.search(text)
    )


def sanitize_agentdojo_tool_output(text: str) -> str:
    """Strip injected instruction spans while preserving benign task data."""
    sanitized = AGENTDOJO_ATTACK_BLOCK_RE.sub(f"\n{DASGUARD_REMOVED_MARKER}\n", text)
    if sanitized == text and AGENTDOJO_IMPORTANT_INSTRUCTIONS_RE.search(text):
        sanitized = AGENTDOJO_IMPORTANT_INSTRUCTIONS_RE.sub(
            DASGUARD_REMOVED_MARKER,
            text,
        )
    return sanitized


SIDE_EFFECT_TOOL_RE = re.compile(
    r"(?i)(send|delete|remove|create|update|modify|post|invite|transfer|pay|book|reserve|cancel|add|share|email)"
)
TOKEN_RE = re.compile(r"[a-z0-9_.@+-]+")


def conversation_contains_untrusted_instructions(messages: List[ChatMessage]) -> bool:
    for message in messages:
        content = message.get("content") or []
        for block in content:
            if block.get("type") == "text":
                text = block.get("content", "")
                if DASGUARD_REMOVED_MARKER in text or detect_agentdojo_injection_pattern(text):
                    return True
    return False


def first_user_query(messages: List[ChatMessage]) -> str:
    for message in messages:
        if message.get("role") == "user":
            return " ".join(
                block.get("content", "")
                for block in (message.get("content") or [])
                if block.get("type") == "text"
            )
    return ""


def should_block_side_effect_tool_call(
    tool_name: str,
    args: Dict[str, Any],
    *,
    user_query: str,
) -> bool:
    if not SIDE_EFFECT_TOOL_RE.search(tool_name):
        return False
    action_payload = f"{tool_name} {args}"
    assessment = should_block_agentdojo_action(action_payload, tool_name=tool_name)
    if not assessment.get("blocked") and not SIDE_EFFECT_TOOL_RE.search(action_payload):
        return False
    return not tool_call_is_user_authorized(tool_name, args, user_query=user_query)


def tool_call_is_user_authorized(tool_name: str, args: Dict[str, Any], *, user_query: str) -> bool:
    query_tokens = set(TOKEN_RE.findall(user_query.lower()))
    payload_tokens = set(TOKEN_RE.findall(f"{tool_name} {args}".lower()))
    informative_payload = {
        token for token in payload_tokens if len(token) >= 4 or "@" in token or token.isdigit()
    }
    if not informative_payload:
        return False
    return len(query_tokens & informative_payload) >= 2


def assess_agentdojo_tool_output(
    text: str,
    *,
    tool_name: str = "",
    sink_path: str = "agentdojo/tool_output",
    source_label: str = "external_source",
) -> Dict[str, Any]:
    """Assess one AgentDojo tool output with DASGuard's runtime policy."""
    context = build_context(
        mode="runtime",
        tool_name=tool_name,
        sink_path=sink_path,
        source_label=source_label,
        authorization={"status": "not_required"},
        payload=text,
    )
    assessment = assess_text(
        text,
        context=context,
        finding_prefix="agentdojo_dasguard",
        embedder=create_dasguard_embedder("hashing", None),
    )
    result = assessment.to_dict()
    result["agentdojo_pattern_match"] = detect_agentdojo_injection_pattern(text)
    result["sanitized_text"] = sanitize_agentdojo_tool_output(text)
    return result


def should_block_agentdojo_action(
    action_payload: str,
    *,
    tool_name: str,
    source_label: str = "derived_untrusted",
) -> Dict[str, Any]:
    """Return a DASGuard runtime-gate decision for a proposed side-effect call."""
    context = build_context(
        mode="runtime",
        tool_name=tool_name,
        sink_path=f"agentdojo/action/{tool_name}",
        source_label=source_label,
        authorization={"status": "not_user_authorized"},
        provenance_matches_count=1 if source_label in UNTRUSTED_LABELS else 0,
        payload=action_payload,
    )
    assessment = assess_text(
        action_payload,
        context=context,
        finding_prefix="agentdojo_dasguard_action",
        embedder=create_dasguard_embedder("hashing", None),
    )
    blocked = assessment.decision == "block_action"
    result = assessment.to_dict()
    result["blocked"] = blocked
    return result
