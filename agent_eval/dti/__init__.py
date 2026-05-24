"""Legacy DtI prototype.

DtI is retained for reproducibility of old experiments. New paper-method code
lives in :mod:`agent_eval.dasguard`.
"""

from .detector import DtiDetector
from .drift_monitor import DriftMonitor, DriftResult
from .counterfactual_gate import CounterfactualGate, GateResult
from .embedder import BaseEmbedder, create_embedder
from .llm_client import BaseLLMClient, create_llm_client

__all__ = [
    "DtiDetector",
    "DriftMonitor",
    "DriftResult",
    "CounterfactualGate",
    "GateResult",
    "BaseEmbedder",
    "create_embedder",
    "BaseLLMClient",
    "create_llm_client",
]
