"""Embedding abstraction layer for DtI defense.

Supports OpenAI API and local sentence-transformers backends.
All embedders return L2-normalized vectors so cosine similarity = dot product.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import List, Optional

import numpy as np


class BaseEmbedder(ABC):
    """Abstract embedding interface."""

    @abstractmethod
    def embed(self, text: str) -> np.ndarray:
        """Embed a single text, return L2-normalized vector."""

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> np.ndarray:
        """Embed multiple texts, return (N, dim) L2-normalized matrix."""

    def cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Cosine similarity between two L2-normalized vectors."""
        return float(np.dot(a, b))


class OpenAIEmbedder(BaseEmbedder):
    """OpenAI Embedding API backend."""

    def __init__(self, model: str = "text-embedding-3-small"):
        from openai import OpenAI

        self.client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        self.model = model

    def embed(self, text: str) -> np.ndarray:
        resp = self.client.embeddings.create(input=[text], model=self.model)
        vec = np.array(resp.data[0].embedding, dtype=np.float32)
        vec /= np.linalg.norm(vec)
        return vec

    def embed_batch(self, texts: List[str]) -> np.ndarray:
        resp = self.client.embeddings.create(input=texts, model=self.model)
        vecs = np.array(
            [d.embedding for d in sorted(resp.data, key=lambda x: x.index)],
            dtype=np.float32,
        )
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1, norms)
        return vecs / norms


class SiliconFlowEmbedder(BaseEmbedder):
    """SiliconFlow Embedding API backend (OpenAI-compatible)."""

    def __init__(self, model: str = "BAAI/bge-m3"):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.environ["SILICONFLOW_API_KEY"],
            base_url="https://api.siliconflow.cn/v1",
        )
        self.model = model

    def embed(self, text: str) -> np.ndarray:
        resp = self.client.embeddings.create(input=[text], model=self.model)
        vec = np.array(resp.data[0].embedding, dtype=np.float32)
        vec /= np.linalg.norm(vec)
        return vec

    def embed_batch(self, texts: List[str]) -> np.ndarray:
        resp = self.client.embeddings.create(input=texts, model=self.model)
        vecs = np.array(
            [d.embedding for d in sorted(resp.data, key=lambda x: x.index)],
            dtype=np.float32,
        )
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1, norms)
        return vecs / norms


class LocalEmbedder(BaseEmbedder):
    """Local sentence-transformers backend (lazy model loading)."""

    def __init__(self, model: str = "BAAI/bge-m3"):
        self.model_name = model
        self._model = None

    @property
    def model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.model_name)
        return self._model

    def embed(self, text: str) -> np.ndarray:
        vec = self.model.encode(text, normalize_embeddings=True)
        return np.array(vec, dtype=np.float32)

    def embed_batch(self, texts: List[str]) -> np.ndarray:
        vecs = self.model.encode(texts, normalize_embeddings=True)
        return np.array(vecs, dtype=np.float32)


def create_embedder(
    backend: str = "openai", model: Optional[str] = None
) -> BaseEmbedder:
    """Factory: create an embedder by backend name.

    Args:
        backend: "openai" or "local"
        model: Override default model name. Defaults vary by backend:
            - openai: "text-embedding-3-small"
            - local: "BAAI/bge-m3"
    """
    if backend == "openai":
        return OpenAIEmbedder(model=model or "text-embedding-3-small")
    elif backend == "siliconflow":
        return SiliconFlowEmbedder(model=model or "BAAI/bge-m3")
    elif backend == "local":
        return LocalEmbedder(model=model or "BAAI/bge-m3")
    else:
        raise ValueError(f"Unknown embedding backend: {backend}")
