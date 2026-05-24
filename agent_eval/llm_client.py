"""Shared LLM client abstraction for evaluation and defense components."""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from email.utils import parsedate_to_datetime
from typing import Any, Callable, TypeVar
from typing import Optional

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
    """Return whether an LLM backend error is likely transient."""
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


class BaseLLMClient(ABC):
    """Abstract LLM completion interface."""

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Single-turn completion. Returns the assistant's text response."""


class OpenAIClient(BaseLLMClient):
    """OpenAI Chat Completions backend."""

    def __init__(self, model: str = "gpt-4o-mini"):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.environ["OPENAI_API_KEY"],
            timeout=_positive_float_env("LLM_REQUEST_TIMEOUT_SECONDS", 180.0),
        )
        self.model = model

    def complete(self, system: str, user: str) -> str:
        resp = _chat_completion_with_retries(
            self.client,
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0,
            max_tokens=1024,
        )
        return resp.choices[0].message.content or ""


class AnthropicClient(BaseLLMClient):
    """Anthropic Messages API backend."""

    def __init__(self, model: str = "claude-haiku-4-5-20251001"):
        from anthropic import Anthropic

        self.client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.model = model

    def complete(self, system: str, user: str) -> str:
        resp = _with_retries(
            lambda: self.client.messages.create(
                model=self.model,
                system=system,
                messages=[{"role": "user", "content": user}],
                temperature=0,
                max_tokens=1024,
            )
        )
        for block in resp.content:
            if block.type == "text":
                return block.text  # type: ignore[union-attr]
        return ""


class RightcodesClient(BaseLLMClient):
    """right.codes OpenAI-compatible backend."""

    def __init__(self, model: str = "gpt-5.4"):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.environ["RIGHTCODES_API_KEY"],
            base_url="https://right.codes/codex/v1",
            timeout=_positive_float_env("LLM_REQUEST_TIMEOUT_SECONDS", 180.0),
        )
        self.model = model

    def complete(self, system: str, user: str) -> str:
        resp = _chat_completion_with_retries(
            self.client,
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0,
            max_tokens=1024,
        )
        return resp.choices[0].message.content or ""


class CubanceClient(BaseLLMClient):
    """Cubance OpenAI-compatible backend."""

    def __init__(self, model: str = "gpt-5.4"):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.environ["CUBANCE_API_KEY"],
            base_url="https://api.cubence.com/v1",
            timeout=_positive_float_env("LLM_REQUEST_TIMEOUT_SECONDS", 180.0),
        )
        self.model = model

    def complete(self, system: str, user: str) -> str:
        resp = _chat_completion_with_retries(
            self.client,
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0,
            max_tokens=1024,
        )
        return resp.choices[0].message.content or ""


class SiliconFlowClient(BaseLLMClient):
    """SiliconFlow OpenAI-compatible backend."""

    def __init__(self, model: str = "Pro/zai-org/GLM-5.1"):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.environ["SILICONFLOW_API_KEY"],
            base_url="https://api.siliconflow.cn/v1",
            timeout=_positive_float_env("LLM_REQUEST_TIMEOUT_SECONDS", 180.0),
        )
        self.model = model

    def complete(self, system: str, user: str) -> str:
        resp = _chat_completion_with_retries(
            self.client,
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0,
            max_tokens=1024,
        )
        return resp.choices[0].message.content or ""


def create_llm_client(
    backend: str = "openai", model: Optional[str] = None
) -> BaseLLMClient:
    """Create an LLM client by backend name."""

    if backend == "openai":
        return OpenAIClient(model=model or "gpt-4o-mini")
    if backend == "anthropic":
        return AnthropicClient(model=model or "claude-haiku-4-5-20251001")
    if backend == "rightcodes":
        return RightcodesClient(model=model or "gpt-5.4")
    if backend == "cubance":
        return CubanceClient(model=model or "gpt-5.4")
    if backend == "siliconflow":
        return SiliconFlowClient(model=model or "Pro/zai-org/GLM-5.1")
    raise ValueError(f"Unknown LLM backend: {backend}")
