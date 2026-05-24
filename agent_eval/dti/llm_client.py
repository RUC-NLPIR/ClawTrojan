"""Deprecated compatibility wrapper for legacy DtI imports."""

from agent_eval.llm_client import (  # noqa: F401
    AnthropicClient,
    BaseLLMClient,
    CubanceClient,
    OpenAIClient,
    RightcodesClient,
    SiliconFlowClient,
    create_llm_client,
)
