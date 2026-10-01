"""Embedding providers.

* ``bedrock``  - Amazon Titan Text Embeddings v2 through LangChain (production).
* ``hash``     - deterministic feature-hashing embedder. It needs no network or model download, so
  it powers local development, CI and the evaluation harness. It captures lexical overlap
  (unigrams, bigrams and character trigrams) but *not* deep semantics; production should use a
  real embedding model.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from itertools import pairwise

from langchain_core.embeddings import Embeddings

from tirag.config import Settings
from tirag.text import tokenize


class HashEmbeddings(Embeddings):
    """Signed feature-hashing embeddings (deterministic across processes and platforms)."""

    def __init__(self, dim: int = 384) -> None:
        if dim < 16:
            raise ValueError("dim must be >= 16")
        self.dim = dim

    def _bucket(self, feature: str) -> tuple[int, float]:
        digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        return value % self.dim, 1.0 if (value >> 63) & 1 else -1.0

    def _features(self, text: str) -> Counter[str]:
        feats: Counter[str] = Counter()
        tokens = tokenize(text)
        for tok in tokens:
            feats[f"u:{tok}"] += 1.0
            padded = f"^{tok}$"
            if len(padded) > 4:
                for i in range(len(padded) - 2):
                    feats[f"c:{padded[i : i + 3]}"] += 0.25
        for left, right in pairwise(tokens):
            feats[f"b:{left}_{right}"] += 0.5
        return feats

    def _embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for feature, count in self._features(text).items():
            idx, sign = self._bucket(feature)
            vec[idx] += sign * (1.0 + math.log(count))
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            return vec
        return [v / norm for v in vec]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)


def build_embeddings(settings: Settings) -> Embeddings:
    provider = settings.embedding_provider
    if provider == "hash":
        return HashEmbeddings(settings.embedding_dim)
    if provider == "bedrock":
        from langchain_aws import BedrockEmbeddings

        return BedrockEmbeddings(
            model_id=settings.embedding_model_id,
            region_name=settings.aws_region,
            model_kwargs={"dimensions": settings.embedding_dim, "normalize": True},
        )
    raise ValueError(f"unsupported embedding provider: {provider}")
