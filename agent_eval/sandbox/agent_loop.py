"""Multi-turn tool-use LLM agent loop.

Provides BaseToolUseClient with OpenAI/Anthropic implementations,
and AgentLoop that drives the conversation with tool dispatch.
"""

from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, List, Optional, TypeVar

from loguru import logger

from .schema import AgentTrace
from .tool_dispatcher import ToolDispatcher

T = TypeVar("T")


class RetryableLLMResponseError(RuntimeError):
    """Raised when an OpenAI-compatible backend returns a transient bad shape."""


def _positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _positive_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _llm_error_status_code(exc: Exception) -> int | None:
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        return status_code
    response = getattr(exc, "response", None)
    response_status = getattr(response, "status_code", None)
    return response_status if isinstance(response_status, int) else None


def _is_rate_limit_llm_error(exc: Exception) -> bool:
    if _llm_error_status_code(exc) == 429:
        return True
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    return "ratelimit" in name or "rate_limit" in name or "rate limit" in text


def _is_retryable_llm_error(exc: Exception) -> bool:
    """Return whether a tool-use backend error is likely transient."""
    if isinstance(exc, RetryableLLMResponseError):
        return True
    status_code = _llm_error_status_code(exc)
    if status_code in {403, 408, 409, 429, 500, 502, 503, 504}:
        return True
    name = type(exc).__name__.lower()
    return "connection" in name or "timeout" in name or "rate" in name


def _retry_after_seconds(exc: Exception) -> float | None:
    headers = getattr(exc, "headers", None)
    if headers is None:
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None)
    if headers is None:
        return None
    retry_after = None
    if hasattr(headers, "get"):
        retry_after = headers.get("retry-after") or headers.get("Retry-After")
    if retry_after is None:
        return None
    try:
        return max(float(retry_after), 0.0)
    except (TypeError, ValueError):
        pass
    try:
        retry_at = parsedate_to_datetime(str(retry_after))
        return max(retry_at.timestamp() - time.time(), 0.0)
    except (TypeError, ValueError, OverflowError):
        return None


def _retry_delay_seconds(
    exc: Exception,
    retry_index: int,
    *,
    rate_limit_initial_delay: float,
    rate_limit_max_delay: float,
) -> float:
    if _is_rate_limit_llm_error(exc):
        retry_after = _retry_after_seconds(exc)
        if retry_after is not None:
            return min(retry_after, rate_limit_max_delay)
        return min(rate_limit_initial_delay * (2 ** retry_index), rate_limit_max_delay)
    return min(2 ** retry_index, 8)


def _with_retries(
    call: Callable[[], T],
    attempts: int = 4,
    *,
    rate_limit_attempts: Optional[int] = None,
    rate_limit_initial_delay: Optional[float] = None,
    rate_limit_max_delay: Optional[float] = None,
) -> T:
    rate_limit_attempts = rate_limit_attempts or max(
        attempts,
        _positive_int_env("LLM_RATE_LIMIT_RETRY_ATTEMPTS", 8),
    )
    rate_limit_initial_delay = rate_limit_initial_delay or _positive_float_env(
        "LLM_RATE_LIMIT_INITIAL_DELAY_SECONDS",
        5.0,
    )
    rate_limit_max_delay = rate_limit_max_delay or _positive_float_env(
        "LLM_RATE_LIMIT_MAX_DELAY_SECONDS",
        60.0,
    )
    rate_limit_retries = 0
    standard_retries = 0
    while True:
        try:
            return call()
        except Exception as exc:
            if not _is_retryable_llm_error(exc):
                raise
            is_rate_limit = _is_rate_limit_llm_error(exc)
            retry_index = rate_limit_retries if is_rate_limit else standard_retries
            allowed_attempts = rate_limit_attempts if is_rate_limit else attempts
            if retry_index >= allowed_attempts - 1:
                raise
            delay = _retry_delay_seconds(
                exc,
                retry_index,
                rate_limit_initial_delay=rate_limit_initial_delay,
                rate_limit_max_delay=rate_limit_max_delay,
            )
            if is_rate_limit:
                rate_limit_retries += 1
            else:
                standard_retries += 1
            time.sleep(delay)


def _chat_completion_with_retries(client: Any, **kwargs: Any) -> Any:
    def call() -> Any:
        resp = client.chat.completions.create(**kwargs)
        choices = getattr(resp, "choices", None)
        if not choices:
            raise RetryableLLMResponseError(
                f"LLM backend returned invalid chat completion shape: {type(resp).__name__}"
            )
        return resp

    return _with_retries(call)


# ── Tool schema definitions ────────────────────────────────────────

TOOL_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "read": {
        "description": "Read a file from the workspace",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path relative to workspace"}},
            "required": ["path"],
        },
    },
    "write": {
        "description": "Write content to a file in the workspace",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path relative to workspace"},
                "content": {"type": "string", "description": "Content to write"},
            },
            "required": ["path", "content"],
        },
    },
    "edit": {
        "description": "Edit an existing file by replacing text",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "old_text": {"type": "string"},
                "new_text": {"type": "string"},
            },
            "required": ["path", "old_text", "new_text"],
        },
    },
    "ls": {
        "description": "List files in a directory",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Directory path (default: workspace root)"}},
            "required": [],
        },
    },
    "glob": {
        "description": "Find files matching a glob pattern",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Glob pattern"}},
            "required": ["path"],
        },
    },
    "grep": {
        "description": "Search for text in files",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory to search in"},
                "query": {"type": "string", "description": "Text to search for"},
            },
            "required": ["query"],
        },
    },
    "web_search": {
        "description": "Search the web for information",
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Search query"}},
            "required": ["query"],
        },
    },
    "web_fetch": {
        "description": "Fetch content from a URL",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "URL to fetch"}},
            "required": ["url"],
        },
    },
    "memory_read": {
        "description": "Read a memory file",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Memory file path"}},
            "required": ["path"],
        },
    },
    "memory_write": {
        "description": "Write or update a memory file",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Memory file path"},
                "content": {"type": "string", "description": "Content to write"},
            },
            "required": ["path", "content"],
        },
    },
    "message": {
        "description": "Send a message to a contact or group",
        "parameters": {
            "type": "object",
            "properties": {
                "recipient": {"type": "string", "description": "Recipient name or address"},
                "content": {"type": "string", "description": "Message content"},
            },
            "required": ["recipient", "content"],
        },
    },
    "exec": {
        "description": "Execute a shell command",
        "parameters": {
            "type": "object",
            "properties": {"command": {"type": "string", "description": "Shell command to run"}},
            "required": ["command"],
        },
    },
}

# Mapping from openclaw tool group names to individual tool names
_GROUP_TOOLS = {
    "group:fs": ["read", "write", "edit", "ls", "glob", "grep"],
    "group:web": ["web_search", "web_fetch"],
    "group:memory": ["memory_read", "memory_write"],
    "group:messaging": ["message"],
}


def resolve_tool_names(allow_list: List[str]) -> List[str]:
    """Expand openclaw tool group names to individual tool names."""
    tools = set()
    for item in allow_list:
        if item in _GROUP_TOOLS:
            tools.update(_GROUP_TOOLS[item])
        elif item in TOOL_SCHEMAS:
            tools.add(item)
        # Skip unknown entries (browser, exec handled separately)
    return sorted(tools)


# ── Conversation turn abstraction ──────────────────────────────────


@dataclass
class ConversationTurn:
    """Normalized LLM response that may include tool calls."""

    text_content: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)  # [{id, name, input}]
    stop_reason: str = "end_turn"  # end_turn | tool_use | max_tokens


# ── Base tool-use client ───────────────────────────────────────────


class BaseToolUseClient(ABC):
    """Abstract multi-turn LLM client with tool_use support."""

    @abstractmethod
    def chat(
        self,
        system: str,
        tools: List[Dict[str, Any]],
        messages: List[Dict[str, Any]],
    ) -> ConversationTurn:
        """Send messages with tool definitions, return normalized response."""


class OpenAIToolUseClient(BaseToolUseClient):
    """OpenAI function-calling implementation."""

    def __init__(self, model: str = "gpt-4o-mini"):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.environ["OPENAI_API_KEY"],
            timeout=_positive_float_env("LLM_REQUEST_TIMEOUT_SECONDS", 180.0),
        )
        self.model = model

    def chat(
        self,
        system: str,
        tools: List[Dict[str, Any]],
        messages: List[Dict[str, Any]],
    ) -> ConversationTurn:
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                },
            }
            for t in tools
        ]

        openai_messages = [{"role": "system", "content": system}]
        openai_messages.extend(messages)

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": openai_messages,
            "temperature": 0,
            "max_tokens": 4096,
        }
        if openai_tools:
            kwargs["tools"] = openai_tools

        resp = _chat_completion_with_retries(self.client, **kwargs)
        choice = resp.choices[0]
        msg = choice.message

        text = msg.content or ""
        tc_list = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {"raw": tc.function.arguments}
                tc_list.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "input": args,
                })

        stop = "tool_use" if tc_list else ("max_tokens" if choice.finish_reason == "length" else "end_turn")
        return ConversationTurn(text_content=text, tool_calls=tc_list, stop_reason=stop)


class AnthropicToolUseClient(BaseToolUseClient):
    """Anthropic tool_use implementation."""

    def __init__(self, model: str = "claude-haiku-4-5-20251001"):
        from anthropic import Anthropic

        self.client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.model = model

    def chat(
        self,
        system: str,
        tools: List[Dict[str, Any]],
        messages: List[Dict[str, Any]],
    ) -> ConversationTurn:
        anthropic_tools = [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "input_schema": t.get("parameters", {"type": "object", "properties": {}}),
            }
            for t in tools
        ]

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "system": system,
            "messages": messages,
            "temperature": 0,
            "max_tokens": 4096,
        }
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        resp = _with_retries(lambda: self.client.messages.create(**kwargs))

        text_parts = []
        tc_list = []
        for block in resp.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tc_list.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })

        stop = "tool_use" if tc_list else ("max_tokens" if resp.stop_reason == "max_tokens" else "end_turn")
        return ConversationTurn(
            text_content="\n".join(text_parts),
            tool_calls=tc_list,
            stop_reason=stop,
        )


class RightcodesToolUseClient(BaseToolUseClient):
    """right.codes OpenAI-compatible tool-use implementation."""

    def __init__(self, model: str = "gpt-5.4"):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.environ["RIGHTCODES_API_KEY"],
            base_url="https://right.codes/codex/v1",
            timeout=_positive_float_env("LLM_REQUEST_TIMEOUT_SECONDS", 180.0),
        )
        self.model = model

    def chat(
        self,
        system: str,
        tools: List[Dict[str, Any]],
        messages: List[Dict[str, Any]],
    ) -> ConversationTurn:
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                },
            }
            for t in tools
        ]

        openai_messages = [{"role": "system", "content": system}]
        openai_messages.extend(messages)

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": openai_messages,
            "temperature": 0,
            "max_tokens": 4096,
        }
        if openai_tools:
            kwargs["tools"] = openai_tools

        resp = _chat_completion_with_retries(self.client, **kwargs)
        choice = resp.choices[0]
        msg = choice.message

        text = msg.content or ""
        tc_list = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {"raw": tc.function.arguments}
                tc_list.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "input": args,
                })

        stop = "tool_use" if tc_list else ("max_tokens" if choice.finish_reason == "length" else "end_turn")
        return ConversationTurn(text_content=text, tool_calls=tc_list, stop_reason=stop)


class CubanceToolUseClient(BaseToolUseClient):
    """Cubance OpenAI-compatible tool-use implementation."""

    def __init__(self, model: str = "gpt-5.4"):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.environ["CUBANCE_API_KEY"],
            base_url="https://api.cubence.com/v1",
            timeout=_positive_float_env("LLM_REQUEST_TIMEOUT_SECONDS", 180.0),
        )
        self.model = model

    def chat(
        self,
        system: str,
        tools: List[Dict[str, Any]],
        messages: List[Dict[str, Any]],
    ) -> ConversationTurn:
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                },
            }
            for t in tools
        ]

        openai_messages = [{"role": "system", "content": system}]
        openai_messages.extend(messages)

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": openai_messages,
            "temperature": 0,
            "max_tokens": 4096,
        }
        if openai_tools:
            kwargs["tools"] = openai_tools

        resp = _chat_completion_with_retries(self.client, **kwargs)
        choice = resp.choices[0]
        msg = choice.message

        text = msg.content or ""
        tc_list = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {"raw": tc.function.arguments}
                tc_list.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "input": args,
                })

        stop = "tool_use" if tc_list else ("max_tokens" if choice.finish_reason == "length" else "end_turn")
        return ConversationTurn(text_content=text, tool_calls=tc_list, stop_reason=stop)


class SiliconFlowToolUseClient(BaseToolUseClient):
    """SiliconFlow OpenAI-compatible tool-use implementation."""

    def __init__(self, model: str = "Pro/zai-org/GLM-5.1"):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.environ["SILICONFLOW_API_KEY"],
            base_url="https://api.siliconflow.cn/v1",
            timeout=_positive_float_env("LLM_REQUEST_TIMEOUT_SECONDS", 180.0),
        )
        self.model = model

    def chat(
        self,
        system: str,
        tools: List[Dict[str, Any]],
        messages: List[Dict[str, Any]],
    ) -> ConversationTurn:
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                },
            }
            for t in tools
        ]

        openai_messages = [{"role": "system", "content": system}]
        openai_messages.extend(messages)

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": openai_messages,
            "temperature": 0,
            "max_tokens": 4096,
        }
        if openai_tools:
            kwargs["tools"] = openai_tools

        resp = _chat_completion_with_retries(self.client, **kwargs)
        choice = resp.choices[0]
        msg = choice.message

        text = msg.content or ""
        tc_list = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {"raw": tc.function.arguments}
                tc_list.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "input": args,
                })

        stop = "tool_use" if tc_list else ("max_tokens" if choice.finish_reason == "length" else "end_turn")
        return ConversationTurn(text_content=text, tool_calls=tc_list, stop_reason=stop)


def create_tool_use_client(
    backend: str = "openai", model: Optional[str] = None
) -> BaseToolUseClient:
    """Factory for tool-use-capable LLM clients."""
    if backend == "openai":
        return OpenAIToolUseClient(model=model or "gpt-4o-mini")
    elif backend == "anthropic":
        return AnthropicToolUseClient(model=model or "claude-haiku-4-5-20251001")
    elif backend == "rightcodes":
        return RightcodesToolUseClient(model=model or "gpt-5.4")
    elif backend == "cubance":
        return CubanceToolUseClient(model=model or "gpt-5.4")
    elif backend == "siliconflow":
        return SiliconFlowToolUseClient(model=model or "Pro/zai-org/GLM-5.1")
    else:
        raise ValueError(f"Unknown tool-use backend: {backend}")


# ── Message format helpers ─────────────────────────────────────────


def _build_assistant_message_openai(turn: ConversationTurn) -> Dict[str, Any]:
    """Build OpenAI-format assistant message from a ConversationTurn."""
    msg: Dict[str, Any] = {"role": "assistant"}
    if turn.text_content:
        msg["content"] = turn.text_content
    if turn.tool_calls:
        msg["tool_calls"] = [
            {
                "id": tc["id"],
                "type": "function",
                "function": {"name": tc["name"], "arguments": json.dumps(tc["input"], ensure_ascii=False)},
            }
            for tc in turn.tool_calls
        ]
        if not turn.text_content:
            msg["content"] = None
    return msg


def _tool_result_content(result: str) -> str:
    if result.strip() == "":
        return "[empty tool output]"
    return result


def _build_tool_result_openai(tool_call_id: str, result: str) -> Dict[str, Any]:
    return {"role": "tool", "tool_call_id": tool_call_id, "content": _tool_result_content(result)}


def _build_assistant_message_anthropic(turn: ConversationTurn) -> Dict[str, Any]:
    """Build Anthropic-format assistant message from a ConversationTurn."""
    content = []
    if turn.text_content:
        content.append({"type": "text", "text": turn.text_content})
    for tc in turn.tool_calls:
        content.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["input"]})
    return {"role": "assistant", "content": content}


def _build_tool_result_anthropic(tool_call_id: str, result: str) -> Dict[str, Any]:
    return {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": tool_call_id, "content": result}],
    }


# ── Agent loop ─────────────────────────────────────────────────────


class AgentLoop:
    """Multi-turn agent execution loop with tool dispatch."""

    def __init__(
        self,
        client: BaseToolUseClient,
        dispatcher: ToolDispatcher,
        max_turns: int = 10,
    ):
        self.client = client
        self.dispatcher = dispatcher
        self.max_turns = max_turns
        self._is_anthropic = isinstance(client, AnthropicToolUseClient)

    def run(
        self,
        system_prompt: str,
        tools: List[Dict[str, Any]],
        session_history: List[Dict[str, str]],
        user_input: str,
        eval_id: str = "",
        model: str = "",
        trial: int = 0,
        prior_defense_state: Optional[Dict[str, Any]] = None,
        sample_id: str = "",
        step_idx: int = 0,
    ) -> AgentTrace:
        """Execute the agent loop and return a complete trace."""
        start = time.time()

        # Build initial messages: session history + current user input
        messages: List[Dict[str, Any]] = list(session_history)
        if not (
            messages
            and messages[-1].get("role") == "user"
            and str(messages[-1].get("content", "")).strip() == str(user_input).strip()
        ):
            messages.append({"role": "user", "content": user_input})
        self.dispatcher.baseline.initialize_run(
            system_prompt,
            session_history,
            user_input,
            tools,
            prior_defense_state=prior_defense_state,
            run_metadata={
                "eval_id": eval_id,
                "sample_id": sample_id,
                "step_idx": step_idx,
                "trial": trial,
            },
        )

        final_response = ""
        terminated_reason = "completed"
        error_metadata: Dict[str, Any] = {}
        agent_llm_calls = 0
        baseline_extra_llm_calls = 0

        for turn_idx in range(self.max_turns):
            self.dispatcher.set_turn(turn_idx)

            try:
                agent_llm_calls += 1
                response = self.client.chat(system_prompt, tools, messages)
            except Exception as e:
                logger.error(f"LLM API error at turn {turn_idx}: {e}")
                error_metadata = {
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "turn_idx": turn_idx,
                }
                terminated_reason = "error"
                break

            # If no tool calls, agent is done
            if not response.tool_calls:
                if self._is_anthropic:
                    messages.append(_build_assistant_message_anthropic(response))
                else:
                    messages.append(_build_assistant_message_openai(response))
                final_response = response.text_content
                if response.stop_reason == "max_tokens":
                    terminated_reason = "max_tokens"
                break

            action_response = response
            cf_decision = None
            if self.dispatcher.baseline.should_counterfactual_gate(response.tool_calls):
                if self.dispatcher.baseline.name == "agentsentry":
                    regime_samples: Dict[str, List[ConversationTurn]] = {
                        "orig": [],
                        "mask": [],
                        "mask_sanitized": [],
                        "orig_sanitized": [],
                    }
                    try:
                        budget = self.dispatcher.baseline.agentsentry_replication_budget()
                        for regime in ("orig", "mask", "mask_sanitized", "orig_sanitized"):
                            reps = max(0, budget - 1) if regime == "orig" else budget
                            for _ in range(reps):
                                regime_messages = self.dispatcher.baseline.agentsentry_regime_messages(
                                    messages,
                                    regime,
                                )
                                baseline_extra_llm_calls += 1
                                regime_samples[regime].append(
                                    self.client.chat(system_prompt, tools, regime_messages)
                                )
                        cf_decision = self.dispatcher.baseline.agentsentry_diagnostic_decision(
                            response,
                            regime_samples,
                        )
                    except Exception as e:
                        logger.error(
                            f"agentsentry counterfactual re-execution error at turn {turn_idx}: {e}"
                        )
                        cf_decision = self.dispatcher.baseline.counterfactual_decision(
                            response.tool_calls,
                            [],
                        )
                else:
                    masked_messages = self.dispatcher.baseline.masked_messages(messages)
                    try:
                        baseline_extra_llm_calls += 1
                        masked_response = self.client.chat(system_prompt, tools, masked_messages)
                        cf_decision = self.dispatcher.baseline.counterfactual_decision(
                            response.tool_calls,
                            masked_response.tool_calls,
                        )
                    except Exception as e:
                        logger.error(
                            f"{self.dispatcher.baseline.name} counterfactual re-execution "
                            f"error at turn {turn_idx}: {e}"
                        )
                        cf_decision = self.dispatcher.baseline.counterfactual_decision(
                            response.tool_calls,
                            [],
                        )

                if cf_decision.blocked:
                    blocked_result = self.dispatcher.baseline._blocked_result(
                        cf_decision.reason,
                        cf_decision.metadata,
                    )
                    if self._is_anthropic:
                        messages.append(_build_assistant_message_anthropic(response))
                    else:
                        messages.append(_build_assistant_message_openai(response))
                    for tc in response.tool_calls:
                        self.dispatcher._record(
                            tc["name"],
                            tc["input"],
                            blocked_result,
                            was_intercepted=True,
                            metadata=cf_decision.metadata or {},
                        )
                        if self._is_anthropic:
                            messages.append(_build_tool_result_anthropic(tc["id"], blocked_result))
                        else:
                            messages.append(_build_tool_result_openai(tc["id"], blocked_result))
                    continue
                revised_tool_calls = (
                    (cf_decision.metadata or {}).get("revised_tool_calls")
                    if cf_decision is not None
                    else None
                )
                if revised_tool_calls:
                    action_response = ConversationTurn(
                        text_content=response.text_content,
                        tool_calls=revised_tool_calls,
                        stop_reason=response.stop_reason,
                    )

            if self._is_anthropic:
                messages.append(_build_assistant_message_anthropic(action_response))
            else:
                messages.append(_build_assistant_message_openai(action_response))

            # Process each tool call
            for tc in action_response.tool_calls:
                result = self.dispatcher.dispatch(tc["name"], tc["input"])
                if cf_decision is not None and (cf_decision.metadata or {}).get("revised_tool_calls"):
                    if self.dispatcher.audit:
                        self.dispatcher.audit[-1].metadata.update(cf_decision.metadata or {})

                if self._is_anthropic:
                    messages.append(_build_tool_result_anthropic(tc["id"], result))
                else:
                    messages.append(_build_tool_result_openai(tc["id"], result))

            # Collect tool call records from dispatcher audit
            # (dispatcher already recorded them)

            # If last turn reached
            if turn_idx == self.max_turns - 1:
                final_response = response.text_content
                terminated_reason = "max_turns"

        duration = time.time() - start

        metadata = self.dispatcher.baseline.export_metadata()
        metadata["agent_llm_calls"] = agent_llm_calls
        metadata["baseline_extra_llm_calls"] = baseline_extra_llm_calls
        metadata["total_llm_calls"] = agent_llm_calls + baseline_extra_llm_calls
        if error_metadata:
            metadata["llm_error"] = error_metadata

        return AgentTrace(
            eval_id=eval_id,
            model=model,
            trial=trial,
            messages=messages,
            tool_calls=list(self.dispatcher.audit),
            final_response=final_response,
            terminated_reason=terminated_reason,
            duration_seconds=round(duration, 2),
            metadata=metadata,
        )
