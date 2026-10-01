"""Vector-store abstraction.

Stores hold *chunks* (LangChain ``Document`` + embedding) and answer three kinds of query:
dense vector similarity, lexical (BM25 / full-text) and exact IOC match. Every query carries a
``SearchFilter`` whose TLP ceiling is enforced **inside the store**, so evidence above the
caller's clearance never leaves the database.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from langchain_core.documents import Document

from tirag.models import QuarantineRecord


@dataclass(frozen=True)
class SearchFilter:
    max_tlp_rank: int
    doc_types: frozenset[str] | None = None
    sources: frozenset[str] | None = None

    def allows(self, metadata: dict) -> bool:
        if int(metadata.get("tlp_rank", 99)) > self.max_tlp_rank:
            return False
        if self.doc_types is not None and metadata.get("doc_type") not in self.doc_types:
            return False
        return not (self.sources is not None and metadata.get("source") not in self.sources)


@dataclass
class ScoredChunk:
    document: Document
    score: float
    channel: str  # "vector" | "lexical" | "ioc"


@dataclass
class StoreStats:
    chunks: int = 0
    documents: int = 0
    by_source: dict[str, int] = field(default_factory=dict)
    by_doc_type: dict[str, int] = field(default_factory=dict)
    quarantined: int = 0


class ChunkStore(ABC):
    """Persistence + retrieval interface implemented by the memory and pgvector backends."""

    @abstractmethod
    def init_schema(self) -> None: ...

    @abstractmethod
    def upsert_document(
        self, doc_id: str, chunks: list[Document], embeddings: list[list[float]]
    ) -> None:
        """Atomically replace every chunk belonging to ``doc_id``."""

    @abstractmethod
    def delete_document(self, doc_id: str) -> int: ...

    @abstractmethod
    def search_vector(
        self, embedding: list[float], k: int, flt: SearchFilter
    ) -> list[ScoredChunk]: ...

    @abstractmethod
    def search_lexical(self, terms: list[str], k: int, flt: SearchFilter) -> list[ScoredChunk]: ...

    @abstractmethod
    def search_iocs(self, values: list[str], k: int, flt: SearchFilter) -> list[ScoredChunk]: ...

    @abstractmethod
    def record_quarantine(self, records: list[QuarantineRecord]) -> None: ...

    @abstractmethod
    def get_state(self, key: str) -> str | None: ...

    @abstractmethod
    def set_state(self, key: str, value: str) -> None: ...

    @abstractmethod
    def stats(self) -> StoreStats: ...

    @abstractmethod
    def ping(self) -> bool: ...

    def flush(self) -> None:  # pragma: no cover - optional hook
        return None

    def close(self) -> None:  # pragma: no cover - optional hook
        return None
