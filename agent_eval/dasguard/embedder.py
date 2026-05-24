"""DASGuard embedding backends."""

from __future__ import annotations

import hashlib
import math
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv


EMBEDDING_DIM = 256
_ENV_LOADED = False

TOKEN_ALIASES = {
    "mandatory": "must",
    "required": "must",
    "silently": "hidden",
    "quietly": "hidden",
    "conceal": "hidden",
    "hide": "hidden",
    "store": "remember",
    "persist": "remember",
    "preference": "memory",
    "default": "memory",
    "later": "future",
    "ongoing": "future",
    "approved": "approve",
    "approval": "approve",
    "authorized": "authorize",
    "authorization": "authorize",
    "waiver": "waive",
    "exception": "policy",
    "credential": "secret",
    "credentials": "secret",
    "token": "secret",
    "recipient": "send",
    "route": "send",
    "routing": "send",
    "share": "send",
    "forward": "send",
    "dispatch": "send",
    "dispatching": "send",
    "deliver": "send",
    "delivery": "send",
    "distribution": "send",
    "contact": "recipient",
    "summaries": "report",
    "summary": "report",
    "notes": "report",
    "artifacts": "artifact",
    "sync": "upload",
    "syncing": "upload",
    "configured": "secret",
    "partner": "external",
    "alias": "recipient",
    "procedure": "workflow",
    "checklist": "workflow",
    "runbook": "workflow",
    "template": "workflow",
}

TOKEN_STOPWORDS = {
    "a",
    "an",
    "as",
    "is",
    "it",
    "of",
    "the",
    "them",
    "this",
    "to",
    "through",
}


class BaseDasGuardEmbedder(ABC):
    backend_name = "base"

    @abstractmethod
    def embed(self, text: str) -> List[float]:
        """Return an L2-normalized embedding vector."""

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self.embed(text) for text in texts]

    @staticmethod
    def cosine(a: List[float], b: List[float]) -> float:
        return sum(x * y for x, y in zip(a, b))


class HashingDasGuardEmbedder(BaseDasGuardEmbedder):
    """Deterministic offline fallback used when external embeddings are unavailable."""

    backend_name = "hashing"

    def __init__(self, dim: int = EMBEDDING_DIM):
        self.dim = dim

    def embed(self, text: str) -> List[float]:
        vec = [0.0] * self.dim
        for token in self._tokenize(text):
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            value = int.from_bytes(digest, "big")
            idx = value % self.dim
            sign = 1.0 if (value >> 8) & 1 else -1.0
            vec[idx] += sign
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0:
            return vec
        return [v / norm for v in vec]

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        import re

        tokens = re.findall(r"[a-z0-9_@./-]+", text.lower())
        normalized: List[str] = []
        for token in tokens:
            token = token.strip(".")
            token = TOKEN_ALIASES.get(token, token)
            if token in TOKEN_STOPWORDS:
                continue
            if len(token) > 4 and token.endswith("ing"):
                token = token[:-3]
            elif len(token) > 3 and token.endswith("ed"):
                token = token[:-2]
            elif len(token) > 3 and token.endswith("s"):
                token = token[:-1]
            normalized.append(token)
        return normalized


class SiliconFlowDasGuardEmbedder(BaseDasGuardEmbedder):
    """SiliconFlow embeddings API backend."""

    backend_name = "siliconflow"

    def __init__(self, model: str = "BAAI/bge-m3"):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.environ["SILICONFLOW_API_KEY"],
            base_url="https://api.siliconflow.cn/v1",
        )
        self.model = model

    def embed(self, text: str) -> List[float]:
        return self.embed_batch([text])[0]

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        resp = self.client.embeddings.create(input=texts, model=self.model)
        rows = sorted(resp.data, key=lambda item: item.index)
        return [_normalize([float(x) for x in row.embedding]) for row in rows]


def _normalize(vec: List[float]) -> List[float]:
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0:
        return vec
    return [v / norm for v in vec]


def create_dasguard_embedder(
    backend: Optional[str] = None,
    model: Optional[str] = None,
    *,
    allow_fallback: bool = True,
) -> BaseDasGuardEmbedder:
    _load_embedding_env()
    requested = (backend or os.getenv("DASGUARD_EMBEDDING_BACKEND") or "siliconflow").lower()
    if requested == "hashing":
        return HashingDasGuardEmbedder()
    if requested == "siliconflow":
        if os.getenv("SILICONFLOW_API_KEY"):
            try:
                return SiliconFlowDasGuardEmbedder(
                    model=model or os.getenv("DASGUARD_EMBEDDING_MODEL") or "BAAI/bge-m3"
                )
            except Exception:
                if not allow_fallback:
                    raise
        elif not allow_fallback:
            raise RuntimeError("SILICONFLOW_API_KEY is required for DASGuard SiliconFlow embeddings")
        return HashingDasGuardEmbedder()
    raise ValueError(f"Unknown DASGuard embedding backend: {requested}")


def _load_embedding_env() -> None:
    """Load repo-local .env before checking embedding credentials."""
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    repo_root = Path(__file__).resolve().parents[2]
    load_dotenv(repo_root / ".env")
    load_dotenv()
    _ENV_LOADED = True
