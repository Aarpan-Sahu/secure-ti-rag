"""Hybrid retriever: dense vectors + lexical + exact-IOC match, fused with Reciprocal Rank Fusion.

Why hybrid? Embeddings capture topical similarity ("ransomware affecting hospitals") but are weak
on opaque tokens (a SHA-256, an IP, a CVE id). Exact IOC lookup and lexical search cover those, and
RRF combines the rankings without needing comparable score scales.

Relevance gating: a chunk is only returned if it has an exact IOC hit, a minimum cosine
similarity, or sufficient overlap with the question's content terms. If nothing passes, the chain
answers "insufficient evidence" without calling the LLM (cheaper, and no room to hallucinate).
"""

from __future__ import annotations

from collections import defaultdict

from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.retrievers import BaseRetriever
from pydantic import ConfigDict

from tirag.security.iocs import extract_iocs
from tirag.store.base import ChunkStore, ScoredChunk, SearchFilter
import math

from tirag.text import content_terms, query_concepts, tokenize

_RRF_K = 60
_CHANNEL_WEIGHT = {"ioc": 3.0, "lexical": 1.0, "vector": 1.0}


class HybridRetriever(BaseRetriever):
    """Per-request retriever: the TLP ceiling of the caller is baked into ``search_filter``."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    store: ChunkStore
    embeddings: Embeddings
    search_filter: SearchFilter
    k: int = 8
    fetch_k: int = 30
    max_chunks_per_doc: int = 3
    min_vector_score: float = 0.30
    min_term_overlap: float = 0.34

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun | None = None
    ) -> list[Document]:
        concepts = query_concepts(content_terms(query))
        terms = sorted({tok for concept in concepts for tok in concept})
        ioc_values = [i.value for i in extract_iocs(query)]

        channels: dict[str, list[ScoredChunk]] = {
            "ioc": self.store.search_iocs(ioc_values, self.fetch_k, self.search_filter)
            if ioc_values
            else [],
            "lexical": self.store.search_lexical(terms, self.fetch_k, self.search_filter),
            "vector": self.store.search_vector(
                self.embeddings.embed_query(query), self.fetch_k, self.search_filter
            ),
        }

        fused: dict[str, float] = defaultdict(float)
        docs: dict[str, Document] = {}
        seen_channels: dict[str, set[str]] = defaultdict(set)
        vector_scores: dict[str, float] = {}
        for channel, results in channels.items():
            for rank, hit in enumerate(results):
                cid = hit.document.metadata["chunk_id"]
                fused[cid] += _CHANNEL_WEIGHT[channel] / (_RRF_K + rank + 1)
                docs[cid] = hit.document
                seen_channels[cid].add(channel)
                if channel == "vector":
                    vector_scores[cid] = hit.score

        pool_tokens = {cid: set(tokenize(doc.page_content)) for cid, doc in docs.items()}
        weights = self._concept_weights(concepts, pool_tokens)

        selected: list[Document] = []
        per_doc: dict[str, int] = defaultdict(int)
        for cid, score in sorted(fused.items(), key=lambda kv: -kv[1]):
            doc = docs[cid]
            if not self._relevant(cid, weights, pool_tokens[cid], seen_channels[cid], vector_scores):
                continue
            doc_id = doc.metadata["doc_id"]
            if per_doc[doc_id] >= self.max_chunks_per_doc:
                continue  # diversity: do not let one document crowd out the rest
            per_doc[doc_id] += 1
            selected.append(
                Document(
                    page_content=doc.page_content,
                    metadata={
                        **doc.metadata,
                        "score": round(score, 6),
                        "channels": sorted(seen_channels[cid]),
                        "vector_score": round(vector_scores[cid], 4) if cid in vector_scores else None,
                    },
                )
            )
            if len(selected) >= self.k:
                break
        return selected

    @staticmethod
    def _concept_weights(
        concepts: list[frozenset[str]], pool_tokens: dict[str, set[str]]
    ) -> list[tuple[frozenset[str], float]]:
        """IDF per concept over the candidate pool. A concept that no candidate contains carries
        no weight, so an off-topic question (nothing in the corpus matches it) cannot pass."""
        n = max(len(pool_tokens), 1)
        weighted: list[tuple[frozenset[str], float]] = []
        for concept in concepts:
            df = sum(1 for tokens in pool_tokens.values() if tokens & concept)
            if df:
                weighted.append((concept, math.log(1 + n / df)))
        return weighted

    def _relevant(
        self,
        cid: str,
        weights: list[tuple[frozenset[str], float]],
        chunk_tokens: set[str],
        channels: set[str],
        vector_scores: dict[str, float],
    ) -> bool:
        if "ioc" in channels:
            return True
        if vector_scores.get(cid, 0.0) >= self.min_vector_score:
            return True
        total = sum(w for _, w in weights)
        if total == 0.0:
            return False
        matched = sum(w for concept, w in weights if chunk_tokens & concept)
        return matched / total >= self.min_term_overlap
